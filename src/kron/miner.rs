//! Active phone miner loop. Heavy lattice / PoUCW work + DAG attach.
//!
//! This path is **phone-only**. A PC host is rejected by
//! [`crate::crypto::mobile_only::enforce_real_mobile`] before any mint.

use crate::crypto::lattice::{expand_matrix, matrix_vec, N};
use crate::crypto::mobile_only::{enforce_real_mobile, ShieldError};
use crate::dag::{AttachingDevice, DagError, DagTransaction, KronDAG};
use crate::economics::FIXED_TRANSACTION_FEE;
use crate::kron::{KronKeypair, KronWallet};
use crate::types::Address;

/// Result of a bounded miner burst (tests call this with `steps`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerLoopOutcome {
    pub attached: u32,
    pub work_units: u32,
}

/// One in-process miner step. Never blocks on the network or on peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerTickOutcome {
    pub genesis_created: bool,
    pub faucet_credited: u64,
    pub attached: bool,
    pub work_units: u32,
    pub vertices: usize,
    pub tips: usize,
    pub supply: u64,
    pub balance: u64,
    pub tx: Option<DagTransaction>,
    pub status: MinerTickStatus,
    pub error: Option<String>,
}

/// Why this tick attached a share or stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinerTickStatus {
    Attached,
    WaitingForTips,
    WaitingForBalance,
    ComposeFailed,
    AttachFailed,
}

impl MinerTickStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "share attached",
            Self::WaitingForTips => "waiting for tips/genesis",
            Self::WaitingForBalance => "waiting for balance",
            Self::ComposeFailed => "compose failed",
            Self::AttachFailed => "attach failed",
        }
    }
}

/// Educational LWE mat-vec (PoUCW). Never used as a live signature.
fn poucw_work(step: u32) {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&step.to_le_bytes());
    seed[4..].fill(0x4B);
    let a = expand_matrix(&seed);
    let v: Vec<i64> = (0..N).map(|i| (i as i64) % 7 - 3).collect();
    let _ = matrix_vec(&a, &v);
}

/// Explicit miner mode only. Calls the host enforcer, then work + attach.
pub fn run_active_miner_loop(
    wallet: &KronWallet,
    dag: &mut KronDAG,
    dest: Address,
    steps: u32,
) -> Result<MinerLoopOutcome, ShieldError> {
    if !wallet.miner_mode() {
        return Err(ShieldError::MinerModeRequired);
    }
    enforce_real_mobile()?;
    let mut attached = 0u32;
    for step in 0..steps {
        poucw_work(step);
        let sender = *wallet.address().as_bytes();
        if dag.balance(&sender) < FIXED_TRANSACTION_FEE.saturating_add(1) {
            continue;
        }
        let tx = dag
            .compose_and_sign(wallet.keypair(), dest, 1)
            .map_err(|_| ShieldError::AttachFailed)?;
        match dag.attach_and_verify_for(tx, AttachingDevice::Miner) {
            Ok(()) => attached = attached.saturating_add(1),
            Err(DagError::Shield(e)) => return Err(e),
            Err(_) => return Err(ShieldError::AttachFailed),
        }
    }
    Ok(MinerLoopOutcome {
        attached,
        work_units: steps,
    })
}

/// One miner tick: genesis if empty, dust faucet on a genesis-only DAG, then
/// compose + attach. Returns immediately — callers must not treat this as a
/// blocking accept loop.
pub fn miner_tick(
    wallet: &KronKeypair,
    dag: &mut KronDAG,
    dest: Address,
    device: AttachingDevice,
) -> MinerTickOutcome {
    let genesis_created = dag.ensure_genesis();
    poucw_work(0);

    let sender = *wallet.address().as_bytes();
    let need = FIXED_TRANSACTION_FEE.saturating_add(1);
    let mut faucet_credited = 0u64;
    if dag.vertex_count() <= 1 && dag.balance(&sender) < need {
        faucet_credited = need.saturating_sub(dag.balance(&sender));
        if faucet_credited > 0 {
            dag.credit_account(sender, faucet_credited);
        }
    }

    let mut out = MinerTickOutcome {
        genesis_created,
        faucet_credited,
        attached: false,
        work_units: 1,
        vertices: dag.vertex_count(),
        tips: dag.tips().len(),
        supply: dag.current_supply,
        balance: dag.balance(&sender),
        tx: None,
        status: MinerTickStatus::WaitingForTips,
        error: None,
    };

    if dag.tips().is_empty() {
        return out;
    }
    if out.balance < need {
        out.status = MinerTickStatus::WaitingForBalance;
        return out;
    }

    match dag.compose_and_sign(wallet, dest, 1) {
        Ok(tx) => match dag.attach_and_verify_for(tx.clone(), device) {
            Ok(()) => {
                out.attached = true;
                out.tx = Some(tx);
                out.vertices = dag.vertex_count();
                out.tips = dag.tips().len();
                out.supply = dag.current_supply;
                out.balance = dag.balance(&sender);
                out.status = MinerTickStatus::Attached;
            }
            Err(e) => {
                out.status = MinerTickStatus::AttachFailed;
                out.error = Some(e.to_string());
            }
        },
        Err(e) => {
            out.status = MinerTickStatus::ComposeFailed;
            out.error = Some(e.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mobile_only::HostArch;
    use crate::kron::{generate_kron_wallet_from_rng, KronWallet};
    use rand::SeedableRng;

    #[test]
    fn miner_loop_requires_explicit_mode() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D49_4E45);
        let wallet = KronWallet::generate_from_rng(&mut rng);
        let mut dag = KronDAG::with_genesis();
        let dest = *wallet.address().as_bytes();
        assert_eq!(
            run_active_miner_loop(&wallet, &mut dag, dest, 1).unwrap_err(),
            ShieldError::MinerModeRequired
        );
    }

    #[test]
    fn miner_loop_refuses_x86_host() {
        if !HostArch::detect().is_pc_class() {
            return;
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D49_4E46);
        let mut wallet = KronWallet::generate_from_rng(&mut rng);
        wallet.enable_miner_mode();
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*wallet.address().as_bytes(), 1_000_000);
        let dest = *wallet.address().as_bytes();
        let err = run_active_miner_loop(&wallet, &mut dag, dest, 1).unwrap_err();
        assert!(err.is_critical());
        assert_eq!(err, ShieldError::PcArchitecture);
        assert_eq!(dag.dag_tx_count, 0);
    }

    #[test]
    fn miner_tick_starts_on_empty_dag_without_hanging() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let started = Instant::now();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut rng = rand::rngs::StdRng::seed_from_u64(0x5449_434B);
            let wallet = generate_kron_wallet_from_rng(&mut rng);
            let mut dag = KronDAG::new();
            let dest = *wallet.address().as_bytes();
            let out = miner_tick(&wallet, &mut dag, dest, AttachingDevice::LocalGraph);
            let _ = tx.send((out, dag.vertex_count()));
        });
        let (out, vertices) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("miner tick must return before the test timeout");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(out.genesis_created);
        assert!(out.faucet_credited > 0);
        assert!(out.attached);
        assert_eq!(out.status, MinerTickStatus::Attached);
        assert!(vertices >= 2);
    }
}
