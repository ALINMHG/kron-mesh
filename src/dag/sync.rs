//! KRON offline mesh sync (`kron_offline_mesh_sync`).
//!
//! Conceptual BLE / Wi-Fi Direct: in-process structs that simulate a short-range
//! hop. There is no host Bluetooth stack. Two phones exchange ML-DSA-44 ids,
//! run the lattice anti-bot handshake (same attestation path as
//! [`crate::p2p::handshake`]), then reconcile DAG islands with Have/Need.
//!
//! # Relay economics
//! The phone that **physically carried** the other's vertices is marked
//! `Mesh_Relay_Node` and is credited **20%** of `(tx subsidy + fee)`
//! ([`RELAY_SHARE_PERCENT`]). The remaining 80% goes to the miner phone
//! (sender / attaching device). This is **not** a 70/30 validator split.
//!
//! Relay identity is stored in a **local sidecar** ([`KronDAG::relay_of`])
//! and, when the wallet intercepts, on `tx.relay_nodes` + `relay_proofs`.
//! Those sidecar fields are **not** part of the sender-signed body, so
//! mutating them cannot break [`TxHash`] / ML-DSA verify.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::anti_bot::attestation::is_datacenter_ipv4;
use crate::anti_bot::{
    verify_hardware_authenticity, DeviceAttestation, DeviceScore, SecurityError,
};
use crate::crypto::hash::sha256_parts;
use crate::crypto::lattice::LatticeKeyPair;
use crate::economics::relay_share_of;
use crate::kron::KronKeypair;
use crate::anti_bot::profile::DeviceClass;
use crate::p2p::handshake::HandshakeConfig;
use crate::p2p::peer::PeerRole;
use crate::types::Address;

use super::engine::KronDAG;
use super::error::DagError;
use super::reconciliation::{compute_dag_diff, SyncInventory};
use super::tx::{DagTransaction, TxHash, NULL_PARENT};

/// Mesh phone identity: 32-byte ML-DSA-44 address ([`Address`]).
/// Distinct from aBFT committee [`crate::types::NodeId`] (`u32`).
pub type NodeId = Address;

/// Handshake attempts on a flaky short-range link (signal instability).
pub const HANDSHAKE_RETRIES: u32 = 3;

pub use crate::economics::mesh_relay_split;

/// Re-export so callers can write `dag::relay_share_of(fee)`.
pub fn relay_share(total: u64) -> u64 {
    relay_share_of(total)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SyncError {
    #[error("mesh handshake rejected: {0}")]
    Handshake(&'static str),
    #[error("anti-bot / attestation failed")]
    AntiBot,
    #[error("missing parent {0:?} not in local DAG or incoming batch")]
    MissingParent(TxHash),
    #[error("incoming batch has a cycle")]
    CyclicBatch,
    #[error("attach failed: {0}")]
    Attach(#[from] DagError),
    #[error("short-range link dropped after retries")]
    UnstableLink,
    #[error("lattice identity signature failed")]
    BadIdentity,
    #[error("phone-only shield: {0}")]
    Shield(#[from] crate::crypto::mobile_only::ShieldError),
}

/// Simulated BLE / Wi-Fi Direct hop. No real radio.
#[derive(Clone, Debug)]
pub struct OfflineLink {
    pub retries: u32,
}

impl Default for OfflineLink {
    fn default() -> Self {
        Self {
            retries: HANDSHAKE_RETRIES,
        }
    }
}

impl OfflineLink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Anti-bot + Dilithium identity exchange with retries on failure.
    pub fn mesh_handshake(
        &self,
        phone_a: &MeshPhone,
        phone_b: &MeshPhone,
    ) -> Result<MeshSession, SyncError> {
        let mut last = SyncError::UnstableLink;
        for _ in 0..self.retries.max(1) {
            match mesh_handshake(phone_a, phone_b) {
                Ok(session) => return Ok(session),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// In-process phone identity for the conceptual short-range link.
#[derive(Clone)]
pub struct MeshPhone {
    pub handshake: HandshakeConfig,
}

impl MeshPhone {
    pub fn id(&self) -> NodeId {
        self.handshake.peer_id()
    }

    /// Honest `LegacyMobile` quote (residential prefix, noisy probes).
    pub fn honest_mobile(keys: LatticeKeyPair) -> Self {
        Self {
            handshake: HandshakeConfig::honest(
                keys,
                PeerRole::EdgeMiner,
                DeviceClass::LegacyMobile,
                true,
            ),
        }
    }

    pub fn from_wallet(wallet: &KronKeypair) -> Self {
        Self::honest_mobile(wallet.lattice().clone())
    }

    /// Datacenter / emulator quote — must be rejected like the P2P path.
    pub fn datacenter_emulator(keys: LatticeKeyPair) -> Self {
        let id = keys.public.address();
        let mut handshake = HandshakeConfig::honest(
            keys,
            PeerRole::EdgeMiner,
            DeviceClass::LegacyMobile,
            true,
        );
        handshake.attestation = DeviceAttestation::datacenter_bot(
            id,
            DeviceClass::LegacyMobile,
            crate::anti_bot::attestation::datacenter_ipv4(&id),
        );
        Self { handshake }
    }
}

/// Result of a successful mutual mesh handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshSession {
    pub phone_a: NodeId,
    pub phone_b: NodeId,
    pub score_a: DeviceScore,
    pub score_b: DeviceScore,
}

/// Thin wrapper: local DAG + this phone's mesh identity.
#[derive(Clone)]
pub struct MeshSyncEngine {
    pub dag: KronDAG,
    pub phone: MeshPhone,
}

impl MeshSyncEngine {
    pub fn new(dag: KronDAG, phone: MeshPhone) -> Self {
        Self { dag, phone }
    }

    pub fn inventory(&self) -> SyncInventory {
        SyncInventory::from_dag(&self.dag, self.phone.id())
    }

    pub fn merge_offline_graphs(
        &mut self,
        incoming_txs: Vec<DagTransaction>,
        relay_node_id: NodeId,
    ) -> Result<u32, SyncError> {
        self.dag.merge_offline_graphs(incoming_txs, relay_node_id)
    }
}

/// Accrued 20% `Mesh_Relay_Node` credits (also mirrored on [`KronDAG`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayLedger {
    pub relay_of: HashMap<TxHash, NodeId>,
    pub credits: HashMap<NodeId, u64>,
}

impl RelayLedger {
    pub fn record(&mut self, tx_id: TxHash, relay: NodeId, fee: u64) {
        self.relay_of.insert(tx_id, relay);
        let share = relay_share_of(fee);
        *self.credits.entry(relay).or_insert(0) = self
            .credits
            .get(&relay)
            .copied()
            .unwrap_or(0)
            .saturating_add(share);
    }
}

/// Mutual lattice / Dilithium handshake + anti-bot attestation.
///
/// Rejects datacenter IPv4 and emulator / VM fingerprints the same way
/// [`crate::p2p::handshake::perform_secure_handshake`] does.
pub fn mesh_handshake(phone_a: &MeshPhone, phone_b: &MeshPhone) -> Result<MeshSession, SyncError> {
    let score_a = verify_mesh_peer(phone_a)?;
    let score_b = verify_mesh_peer(phone_b)?;
    mutual_dilithium(phone_a, phone_b)?;
    Ok(MeshSession {
        phone_a: phone_a.id(),
        phone_b: phone_b.id(),
        score_a,
        score_b,
    })
}

fn verify_mesh_peer(phone: &MeshPhone) -> Result<DeviceScore, SyncError> {
    let att = &phone.handshake.attestation;
    let pk = &phone.handshake.keys.public;
    if att.miner != pk.address() {
        return Err(SyncError::Handshake("attestation/key mismatch"));
    }
    if is_datacenter_ipv4(att.ipv4) {
        return Err(SyncError::Handshake("datacenter ip"));
    }
    let score = verify_hardware_authenticity(att).map_err(map_security)?;
    if score.authenticity < phone.handshake.min_authenticity {
        return Err(SyncError::Handshake("weak hardware score"));
    }
    Ok(score)
}

fn map_security(err: SecurityError) -> SyncError {
    match err {
        SecurityError::DatacenterCluster => SyncError::Handshake("datacenter ip"),
        SecurityError::VirtualMachineFingerprint | SecurityError::EmulatorTiming => {
            SyncError::AntiBot
        }
        _ => SyncError::AntiBot,
    }
}

fn mutual_dilithium(a: &MeshPhone, b: &MeshPhone) -> Result<(), SyncError> {
    let transcript = sha256_parts(&[
        b"kron-offline-mesh-hs-v1",
        &a.id(),
        &b.id(),
        &a.handshake.attestation.quote,
        &b.handshake.attestation.quote,
    ]);
    let sig_a = a
        .handshake
        .keys
        .sign(&transcript)
        .map_err(|_| SyncError::BadIdentity)?;
    let sig_b = b
        .handshake
        .keys
        .sign(&transcript)
        .map_err(|_| SyncError::BadIdentity)?;
    if !a.handshake.keys.public.verify(&transcript, &sig_a) {
        return Err(SyncError::BadIdentity);
    }
    if !b.handshake.keys.public.verify(&transcript, &sig_b) {
        return Err(SyncError::BadIdentity);
    }
    Ok(())
}

impl KronDAG {
    /// §46 `mesh_graph_merger` — insert a topo-ordered batch, stamp relay sidecar.
    ///
    /// Duplicates are ignored (idempotent). Missing parents that are neither
    /// local nor in the batch abort the remaining inserts.
    /// Same as [`Self::merge_offline_graphs`] but this host is the relay device.
    /// x86/emulator processes are isolated (no insert).
    pub fn merge_offline_graphs_as_relay(
        &mut self,
        incoming_txs: Vec<DagTransaction>,
        relay_node_id: NodeId,
    ) -> Result<u32, SyncError> {
        crate::crypto::mobile_only::enforce_real_mobile()?;
        self.merge_offline_graphs(incoming_txs, relay_node_id)
    }

    pub fn merge_offline_graphs(
        &mut self,
        incoming_txs: Vec<DagTransaction>,
        relay_node_id: NodeId,
    ) -> Result<u32, SyncError> {
        let ordered = topo_order_incoming(self, incoming_txs)?;
        let mut inserted = 0u32;
        for tx in ordered {
            if self.contains(&tx.id) {
                continue;
            }
            for p in [tx.parent_1, tx.parent_2] {
                if tx.is_genesis() {
                    continue;
                }
                if p == NULL_PARENT || !self.contains(&p) {
                    return Err(SyncError::MissingParent(p));
                }
            }
            let id = tx.id;
            let is_genesis = tx.is_genesis();
            // Unsigned sidecar names do not get the 20% split. Only proven
            // relay_nodes already on the vertex are paid.
            match self.insert_graph_only(tx) {
                Ok(()) => {
                    if !is_genesis {
                        self.stamp_relay(id, relay_node_id);
                    }
                    inserted = inserted.saturating_add(1);
                }
                Err(DagError::DuplicateTx(_)) => continue,
                Err(e) => return Err(SyncError::Attach(e)),
            }
        }
        if inserted > 0 {
            self.resolve_conflicts_and_rebuild_ledger()
                .map_err(SyncError::Attach)?;
        }
        Ok(inserted)
    }

    fn stamp_relay(&mut self, tx_id: TxHash, relay: NodeId) {
        self.relay_of.insert(tx_id, relay);
        // Ledger + `relay_credits` are written by DAG minting (20% of subsidy+fee).
    }

    /// Native minting already credits relay phones on the ledger. This helper
    /// remains for callers that only stamped the sidecar without minting.
    pub fn apply_relay_credits_from_fee_pool(&mut self) {
        let credits: Vec<(Address, u64)> = self
            .relay_credits
            .iter()
            .map(|(a, c)| (*a, *c))
            .collect();
        for (addr, amount) in credits {
            self.credit_account(addr, amount);
        }
    }
}

fn topo_order_incoming(
    local: &KronDAG,
    txs: Vec<DagTransaction>,
) -> Result<Vec<DagTransaction>, SyncError> {
    let mut unique: HashMap<TxHash, DagTransaction> = HashMap::new();
    for tx in txs {
        unique.entry(tx.id).or_insert(tx);
    }
    let batch_ids: HashSet<TxHash> = unique.keys().copied().collect();

    let mut dependents: HashMap<TxHash, Vec<TxHash>> = HashMap::new();
    let mut indeg: HashMap<TxHash, usize> = HashMap::new();
    for id in &batch_ids {
        indeg.insert(*id, 0);
    }

    for tx in unique.values() {
        let mut parents = Vec::with_capacity(2);
        if tx.parent_1 != NULL_PARENT {
            parents.push(tx.parent_1);
        }
        if tx.parent_2 != NULL_PARENT && tx.parent_2 != tx.parent_1 {
            parents.push(tx.parent_2);
        }
        for p in parents {
            let in_local = local.contains(&p);
            let in_batch = batch_ids.contains(&p);
            if !in_local && !in_batch {
                return Err(SyncError::MissingParent(p));
            }
            if in_batch && !in_local {
                *indeg.get_mut(&tx.id).expect("indegree key") += 1;
                dependents.entry(p).or_default().push(tx.id);
            }
        }
    }

    let mut ready: Vec<TxHash> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| *id)
        .collect();
    ready.sort();
    let mut queue: VecDeque<TxHash> = ready.into();
    let mut ordered = Vec::with_capacity(unique.len());
    while let Some(id) = queue.pop_front() {
        let tx = unique.remove(&id).expect("topo node");
        if let Some(kids) = dependents.get(&id) {
            let mut newly = Vec::new();
            for kid in kids {
                let d = indeg.get_mut(kid).expect("indegree key");
                *d = d.saturating_sub(1);
                if *d == 0 {
                    newly.push(*kid);
                }
            }
            newly.sort();
            queue.extend(newly);
        }
        ordered.push(tx);
    }
    if !unique.is_empty() {
        return Err(SyncError::CyclicBatch);
    }
    Ok(ordered)
}

/// One-round Have/Need body exchange. `carrier` is the mule (`Mesh_Relay_Node`).
pub fn exchange_and_merge(
    local: &mut KronDAG,
    remote: &KronDAG,
    remote_inventory: &SyncInventory,
    carrier: NodeId,
) -> Result<u32, SyncError> {
    let (need, _have) = compute_dag_diff(local, remote_inventory);
    let bodies = remote.transactions_for(&need);
    local.merge_offline_graphs(bodies, carrier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::{remainder_after_relay, FIXED_TRANSACTION_FEE, RELAY_SHARE_PERCENT};
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    const PHONE_CREDIT: u64 = 1_000_000;
    const SEND_AMOUNT: u64 = 10_000;

    #[test]
    fn relay_share_is_20_percent_integer() {
        assert_eq!(RELAY_SHARE_PERCENT, 20);
        assert_eq!(relay_share_of(FIXED_TRANSACTION_FEE), 200);
        assert_eq!(relay_share_of(1_000), 200);
        let (relay, rest) = mesh_relay_split(1_000);
        assert_eq!(relay, 200);
        assert_eq!(rest, 800);
        assert_eq!(rest, remainder_after_relay(1_000));
        assert_eq!(relay + rest, 1_000);
    }

    #[test]
    fn handshake_rejects_datacenter_emulator() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xB07);
        let honest = MeshPhone::honest_mobile(LatticeKeyPair::generate(&mut rng));
        let bot = MeshPhone::datacenter_emulator(LatticeKeyPair::generate(&mut rng));
        let err = mesh_handshake(&honest, &bot).unwrap_err();
        assert!(matches!(
            err,
            SyncError::Handshake("datacenter ip") | SyncError::AntiBot
        ));
        let link = OfflineLink::new();
        assert!(link.mesh_handshake(&honest, &bot).is_err());
    }

    #[test]
    fn honest_phones_handshake_and_idempotent_merge() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x0FF);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        let a = MeshPhone::from_wallet(&alice);
        let b = MeshPhone::from_wallet(&bob);
        let session = OfflineLink::new()
            .mesh_handshake(&a, &b)
            .expect("honest BLE handshake");
        assert_eq!(session.phone_a, a.id());
        assert_eq!(session.phone_b, b.id());
        assert!(session.score_a.is_strong());
        assert!(session.score_b.is_strong());

        let mut shared = KronDAG::with_genesis();
        shared.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        shared.credit_account(*bob.address().as_bytes(), PHONE_CREDIT);
        let mut dag_a = shared.clone();
        let mut dag_b = shared;
        let tx = dag_a
            .compose_and_sign_with_rng(
                &alice,
                *bob.address().as_bytes(),
                SEND_AMOUNT,
                &mut rng,
            )
            .unwrap();
        dag_a.attach_and_verify_tx(tx.clone()).unwrap();
        let carried = crate::dag::relay_intercept_and_sign(tx.clone(), &alice);
        assert!(carried.verify_relay_proofs());
        let n = dag_b
            .merge_offline_graphs(vec![carried.clone()], a.id())
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            dag_b.merge_offline_graphs(vec![carried], a.id()).unwrap(),
            0,
            "duplicate insert must be ignored"
        );
        assert_eq!(
            dag_b.relay_credit(&a.id()),
            crate::economics::dag_relay_total_of(
                crate::economics::INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE
            )
        );
    }
}
