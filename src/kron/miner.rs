//! Active phone miner loop. Heavy lattice / PoUCW work + DAG attach.
//!
//! This path is **phone-only**. A PC host is rejected by
//! [`crate::crypto::mobile_only::enforce_real_mobile`] before any mint.

use crate::crypto::lattice::{expand_matrix, matrix_vec, N};
use crate::crypto::mobile_only::{enforce_real_mobile, ShieldError};
use crate::dag::{AttachingDevice, DagError, KronDAG};
use crate::economics::FIXED_TRANSACTION_FEE;
use crate::kron::KronWallet;
use crate::types::Address;

/// Result of a bounded miner burst (tests call this with `steps`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerLoopOutcome {
    pub attached: u32,
    pub work_units: u32,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mobile_only::HostArch;
    use crate::kron::KronWallet;
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
}
