//! `kron_wallet_relay_service` — low-power Mesh Relay for the phone wallet.
//!
//! Passive sleep/wake only: poll inbound DAG vertices, intercept+sign a
//! **carrier proof**, stash in a tiny mempool, flush when the conceptual
//! global link is up. This thread must never run PoUCW, Dilithium mining,
//! or educational LWE matrix work.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::kron::KronKeypair;
use crate::types::Address;

use super::tx::{relay_proof_message, DagTransaction, RelayProof};

/// Documented OS-style background duty cycle (5–15 s). Default mid-window.
pub const RELAY_DUTY_SLEEP_SECS_MIN: u64 = 5;
pub const RELAY_DUTY_SLEEP_SECS_MAX: u64 = 15;
pub const RELAY_DUTY_SLEEP_SECS_DEFAULT: u64 = 10;

/// Tiny in-process relay store. Evicts the oldest vertex when full.
pub const RELAY_MEMPOOL_CAP: usize = 32;

/// Conceptual BLE / Wi-Fi Direct (in-process, like [`super::OfflineLink`]).
/// No host Bluetooth stack.
#[derive(Clone)]
pub struct MeshInterface {
    inbound: VecDeque<DagTransaction>,
    global_link_up: bool,
    stop: bool,
    /// Tests set this to `Duration::ZERO` so the duty loop does not park.
    pub park_timeout: Duration,
    wake: Arc<(Mutex<bool>, Condvar)>,
    /// Vertices ready for `merge_offline_graphs` / attach after the link came up.
    pub flush_ready: Vec<DagTransaction>,
}

impl Default for MeshInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshInterface {
    pub fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            global_link_up: false,
            stop: false,
            park_timeout: Duration::from_secs(RELAY_DUTY_SLEEP_SECS_DEFAULT),
            wake: Arc::new((Mutex::new(false), Condvar::new())),
            flush_ready: Vec::new(),
        }
    }

    /// Instant-return interface for unit tests (no 5–15 s park).
    pub fn for_tests() -> Self {
        let mut m = Self::new();
        m.park_timeout = Duration::ZERO;
        m
    }

    pub fn push_inbound(&mut self, tx: DagTransaction) {
        self.inbound.push_back(tx);
        self.wake_now();
    }

    pub fn poll_inbound(&mut self) -> Option<DagTransaction> {
        self.inbound.pop_front()
    }

    pub fn global_link_up(&self) -> bool {
        self.global_link_up
    }

    pub fn set_global_link_up(&mut self, up: bool) {
        self.global_link_up = up;
        if up {
            self.wake_now();
        }
    }

    pub fn request_stop(&mut self) {
        self.stop = true;
        self.wake_now();
    }

    pub fn is_stopped(&self) -> bool {
        self.stop
    }

    pub fn take_flush(&mut self) -> Vec<DagTransaction> {
        std::mem::take(&mut self.flush_ready)
    }

    pub fn stage_for_global_dag(&mut self, txs: Vec<DagTransaction>) {
        self.flush_ready.extend(txs);
    }

    /// Park 5–15 s (or `park_timeout`) until `wake` or timeout. CPU near zero.
    pub fn park_duty_cycle(&self) {
        if self.park_timeout.is_zero() {
            return;
        }
        let (lock, cv) = &*self.wake;
        let Ok(guard) = lock.lock() else {
            return;
        };
        let _ = cv.wait_timeout(guard, self.park_timeout);
    }

    fn wake_now(&self) {
        let (lock, cv) = &*self.wake;
        if let Ok(mut flag) = lock.lock() {
            *flag = true;
        }
        cv.notify_all();
    }
}

/// Bounded FIFO of intercepted vertices in the wallet process.
#[derive(Clone, Debug, Default)]
pub struct RelayMempool {
    txs: VecDeque<DagTransaction>,
}

impl RelayMempool {
    pub fn new() -> Self {
        Self {
            txs: VecDeque::with_capacity(RELAY_MEMPOOL_CAP),
        }
    }

    pub fn push(&mut self, tx: DagTransaction) {
        if self.txs.len() >= RELAY_MEMPOOL_CAP {
            self.txs.pop_front();
        }
        self.txs.push_back(tx);
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &DagTransaction> {
        self.txs.iter()
    }

    pub fn drain(&mut self) -> Vec<DagTransaction> {
        self.txs.drain(..).collect()
    }
}

/// Outcome of [`start_wallet_relay_mode`].
#[derive(Clone, Debug)]
pub struct WalletRelaySession {
    pub mempool: RelayMempool,
    /// Always false: this service never calls the miner / PoUCW path.
    pub mining_ran: bool,
}

/// Append this wallet’s public id to `tx.relay_nodes` and sign a **relay packet**
/// (carrier proof). The original sender [`DagTransaction::signature`] is kept.
pub fn relay_intercept_and_sign(
    mut tx: DagTransaction,
    relay_keys: &KronKeypair,
) -> DagTransaction {
    let node = relay_keys.public_key().address();
    if !tx.relay_nodes.contains(&node) {
        tx.relay_nodes.push(node);
    }
    let msg = relay_proof_message(&tx.id, relay_keys.public_key());
    let sig = relay_keys
        .lattice()
        .secret
        .sign(&msg)
        .expect("ML-DSA-44 relay carrier proof");
    tx.relay_proofs.push(RelayProof {
        node,
        public_key: relay_keys.public_key().clone(),
        sig,
    });
    tx
}

/// One sleep/wake duty cycle: poll → intercept+sign → mempool → flush if online.
/// Never runs mining.
pub fn wallet_relay_step(
    wallet_keys: &KronKeypair,
    mesh_interface: &mut MeshInterface,
    session: &mut WalletRelaySession,
) {
    session.mining_ran = false;
    while let Some(tx) = mesh_interface.poll_inbound() {
        let signed = relay_intercept_and_sign(tx, wallet_keys);
        session.mempool.push(signed);
    }
    if mesh_interface.global_link_up() && !session.mempool.is_empty() {
        mesh_interface.stage_for_global_dag(session.mempool.drain());
    }
}

/// Passive wallet relay mode. Blocks the caller thread (the wallet’s background
/// task) in a 5–15 s park / condvar wake loop until `mesh_interface` stops.
///
/// MUST NOT run PoUCW / Dilithium mining / heavy matrix work.
pub fn start_wallet_relay_mode(
    wallet_keys: &KronKeypair,
    mesh_interface: &mut MeshInterface,
) -> WalletRelaySession {
    let mut session = WalletRelaySession {
        mempool: RelayMempool::new(),
        mining_ran: false,
    };
    loop {
        wallet_relay_step(wallet_keys, mesh_interface, &mut session);
        if mesh_interface.is_stopped() {
            break;
        }
        mesh_interface.park_duty_cycle();
        if mesh_interface.is_stopped() {
            break;
        }
    }
    session
}

/// Address of the relay wallet (mesh [`Address`] / kron1 hash).
pub fn relay_wallet_id(wallet_keys: &KronKeypair) -> Address {
    wallet_keys.public_key().address()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::{KronDAG, NodeId};
    use crate::economics::{dag_relay_total_of, FIXED_TRANSACTION_FEE, INITIAL_TX_SUBSIDY};
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    const PHONE_CREDIT: u64 = 1_000_000;
    const SEND_AMOUNT: u64 = 10_000;

    #[test]
    fn relay_intercept_keeps_sender_sig_and_never_mines() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x8E1A);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        let mut island = KronDAG::with_genesis();
        island.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);

        let tx = island
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        let sender_sig = tx.signature.clone();
        let tx_id = tx.id;
        assert!(tx.relay_nodes.is_empty());
        assert!(tx.verify_signature());

        let mut mesh = MeshInterface::for_tests();
        mesh.push_inbound(tx);
        mesh.set_global_link_up(true);
        mesh.request_stop();
        let session = start_wallet_relay_mode(&bob, &mut mesh);

        assert!(!session.mining_ran, "relay thread must not run mining");
        assert_eq!(session.mempool.len(), 0, "flushed when global link is up");
        assert_eq!(mesh.flush_ready.len(), 1);
        let carried = &mesh.flush_ready[0];
        let bob_id: NodeId = *bob.address().as_bytes();
        assert_eq!(carried.id, tx_id);
        assert_eq!(carried.signature, sender_sig);
        assert!(carried.verify_signature(), "original sender sig still verifies");
        assert!(carried.relay_nodes.contains(&bob_id));
        assert_eq!(carried.relay_proofs.len(), 1);
        assert!(carried.verify_relay_proofs());
        assert_eq!(carried.relay_proofs[0].node, bob_id);

        let mut global = KronDAG::with_genesis();
        global.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let n = global
            .merge_offline_graphs(mesh.take_flush(), bob_id)
            .unwrap();
        assert_eq!(n, 1);
        assert!(global.contains(&tx_id));
        assert_eq!(global.relay_node(&tx_id), Some(bob_id));
        let relay_cut = dag_relay_total_of(INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE);
        assert_eq!(global.relay_credit(&bob_id), relay_cut);
    }

    #[test]
    fn relay_mempool_evicts_oldest() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x8E32);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), 50_000_000);

        let mut pool = RelayMempool::new();
        let mut first_id = None;
        for i in 0..(RELAY_MEMPOOL_CAP + 1) {
            let tx = dag
                .compose_and_sign(&alice, *bob.address().as_bytes(), 1)
                .unwrap();
            if i == 0 {
                first_id = Some(tx.id);
            }
            dag.attach_and_verify_tx(tx.clone()).unwrap();
            pool.push(relay_intercept_and_sign(tx, &bob));
        }
        assert_eq!(pool.len(), RELAY_MEMPOOL_CAP);
        assert!(pool.iter().all(|t| t.id != first_id.unwrap()));
        assert!(pool.iter().all(|t| t.verify_signature() && t.verify_relay_proofs()));
    }
}
