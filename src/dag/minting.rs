//! Transaction-driven / virtual-epoch DAG minting (no physical blocks).
//!
//! Emission uses integer `u64` minor units only. This path pays **80% miner
//! phone / 20% relay phones** of `(tx subsidy + fee)`. There is no block
//! subsidy and no validator coinbase.

use crate::crypto::mobile_only::enforce_real_mobile;
use crate::economics::{
    dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, EconomicError,
};
use crate::types::Address;

use super::engine::KronDAG;
use super::error::DagError;
use super::tx::DagTransaction;

/// Credit `(subsidy + fee)` after a confirmed DAG vertex.
///
/// * `tx_subsidy = get_current_tx_subsidy(dag.dag_tx_count, dag.current_supply)`
/// * `total_tx_pool = subsidy + fee` (`fee` already taken from the sender)
/// * miner phone gets `(pool * 80) / 100`
/// * relays share the remainder equally (dust to the first relay)
/// * no relays → miner (or first miner) keeps the leftover so units are not burned
/// * `current_supply` grows by **subsidy only**; confirmed tx count grows by 1
///
/// Does not charge the sender again. Genesis vertices must not call this.
pub fn apply_dag_minting_natively(
    dag: &mut KronDAG,
    tx: &DagTransaction,
    miner: Address,
    relay_nodes: &[Address],
) -> Result<(), EconomicError> {
    mint_confirmed_tx(dag, tx.fee, miner, relay_nodes)
}

/// Thin wrapper: miner = `tx.sender` (self-attached spend / confirming phone).
pub fn apply_dag_minting_from_sender(
    dag: &mut KronDAG,
    tx: &DagTransaction,
    relay_nodes: Vec<Address>,
) -> Result<(), EconomicError> {
    apply_dag_minting_natively(dag, tx, tx.sender, &relay_nodes)
}

/// Minting originated by this host acting as a miner phone. The PC is refused.
pub fn apply_dag_minting_as_miner(
    dag: &mut KronDAG,
    tx: &DagTransaction,
    miner: Address,
    relay_nodes: &[Address],
) -> Result<(), DagError> {
    enforce_real_mobile().map_err(DagError::Shield)?;
    apply_dag_minting_natively(dag, tx, miner, relay_nodes).map_err(|e| match e {
        EconomicError::Overflow => DagError::Overflow,
    })
}

/// Same split as [`apply_dag_minting_natively`] when only the fee is known
/// (avoids borrowing a vertex that already lives inside `dag`).
pub(crate) fn mint_confirmed_tx(
    dag: &mut KronDAG,
    fee: u64,
    miner: Address,
    relay_nodes: &[Address],
) -> Result<(), EconomicError> {
    let subsidy = get_current_tx_subsidy(dag.dag_tx_count, dag.current_supply);
    let total_tx_pool = subsidy.checked_add(fee).ok_or(EconomicError::Overflow)?;

    let miner_share = dag_miner_share_of(total_tx_pool);
    let relay_total = total_tx_pool.saturating_sub(miner_share);
    debug_assert_eq!(relay_total, dag_relay_total_of(total_tx_pool));

    let relays = unique_relays(relay_nodes);
    let (miner_paid, relay_payouts) = if relays.is_empty() {
        // Conserve remainder: no relay phones → miner keeps the 20% leftover.
        (miner_share.saturating_add(relay_total), Vec::new())
    } else {
        let n = relays.len() as u64;
        let each = relay_total / n;
        let dust = relay_total % n;
        let payouts: Vec<(Address, u64)> = relays
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let extra = if i == 0 { dust } else { 0 };
                (*addr, each.saturating_add(extra))
            })
            .collect();
        (miner_share, payouts)
    };

    dag.credit_checked(miner, miner_paid)?;
    for (addr, amount) in relay_payouts.iter() {
        dag.credit_checked(*addr, *amount)?;
        let entry = dag.relay_credits.entry(*addr).or_insert(0);
        *entry = entry
            .checked_add(*amount)
            .ok_or(EconomicError::Overflow)?;
    }

    dag.current_supply = dag
        .current_supply
        .checked_add(subsidy)
        .ok_or(EconomicError::Overflow)?;
    dag.dag_tx_count = dag
        .dag_tx_count
        .checked_add(1)
        .ok_or(EconomicError::Overflow)?;
    Ok(())
}

fn unique_relays(nodes: &[Address]) -> Vec<Address> {
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        if !out.contains(n) {
            out.push(*n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::{
        get_current_tx_subsidy, FIXED_TRANSACTION_FEE, HARD_CAP, INITIAL_TX_SUBSIDY,
        TX_HALVING_INTERVAL,
    };
    use crate::kron::generate_kron_wallet_from_rng;
    use crate::dag::KronDAG;
    use rand::SeedableRng;

    const PHONE_CREDIT: u64 = 1_000_000;
    const SEND_AMOUNT: u64 = 10_000;

    fn wallets(seed: u64) -> (crate::kron::KronKeypair, crate::kron::KronKeypair, crate::kron::KronKeypair) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        (
            generate_kron_wallet_from_rng(&mut rng),
            generate_kron_wallet_from_rng(&mut rng),
            generate_kron_wallet_from_rng(&mut rng),
        )
    }

    #[test]
    fn first_confirmed_tx_mints_initial_subsidy() {
        assert_eq!(get_current_tx_subsidy(0, 0), INITIAL_TX_SUBSIDY);
        let (alice, bob, _) = wallets(0xDA6_0001);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        dag.attach_and_verify_tx(tx).unwrap();

        let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
        assert_eq!(dag.dag_tx_count, 1);
        assert_eq!(dag.current_supply, INITIAL_TX_SUBSIDY);
        assert_eq!(
            dag.balance(alice.address().as_bytes()),
            PHONE_CREDIT - SEND_AMOUNT - FIXED_TRANSACTION_FEE + pool
        );
        assert_eq!(dag.balance(bob.address().as_bytes()), SEND_AMOUNT);
    }

    #[test]
    fn after_halving_interval_subsidy_shifts_right() {
        assert_eq!(
            get_current_tx_subsidy(TX_HALVING_INTERVAL, 0),
            INITIAL_TX_SUBSIDY >> 1
        );
        assert_eq!(get_current_tx_subsidy(TX_HALVING_INTERVAL, 0), 50_000);

        let (alice, bob, relay) = wallets(0xDA6_0002);
        let mut dag = KronDAG::with_genesis();
        dag.dag_tx_count = TX_HALVING_INTERVAL;
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let mut tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        tx = crate::dag::relay_intercept_and_sign(tx, &relay);
        dag.attach_and_verify_tx(tx).unwrap();

        let subsidy = 50_000u64;
        let pool = subsidy + FIXED_TRANSACTION_FEE;
        let miner_paid = dag_miner_share_of(pool);
        let relay_paid = dag_relay_total_of(pool);
        assert_eq!(miner_paid, 40_800);
        assert_eq!(relay_paid, 10_200);
        assert_eq!(dag.current_supply, subsidy);
        assert_eq!(dag.dag_tx_count, TX_HALVING_INTERVAL + 1);
        assert_eq!(
            dag.balance(alice.address().as_bytes()),
            PHONE_CREDIT - SEND_AMOUNT - FIXED_TRANSACTION_FEE + miner_paid
        );
        assert_eq!(dag.balance(relay.address().as_bytes()), relay_paid);
        assert_eq!(dag.relay_credit(relay.address().as_bytes()), relay_paid);
    }

    #[test]
    fn hard_cap_fees_only_still_split_80_20() {
        let (alice, bob, relay) = wallets(0xDA6_0CA9);
        let mut dag = KronDAG::with_genesis();
        dag.current_supply = HARD_CAP;
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let mut tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        tx = crate::dag::relay_intercept_and_sign(tx, &relay);
        dag.attach_and_verify_tx(tx).unwrap();

        assert_eq!(get_current_tx_subsidy(dag.dag_tx_count.saturating_sub(1), HARD_CAP), 0);
        assert_eq!(dag.current_supply, HARD_CAP);
        assert_eq!(dag.dag_tx_count, 1);
        assert_eq!(dag.balance(alice.address().as_bytes()), PHONE_CREDIT - SEND_AMOUNT - 200);
        assert_eq!(dag.balance(relay.address().as_bytes()), 200);
        assert_eq!(dag.relay_credit(relay.address().as_bytes()), 200);
        assert_eq!(dag.balance(bob.address().as_bytes()), SEND_AMOUNT);
    }

    #[test]
    fn unsigned_relay_list_does_not_get_twenty_percent() {
        let (alice, bob, relay) = wallets(0xDA6_0BAD_20);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let mut tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        tx.relay_nodes.push(*relay.address().as_bytes());
        assert!(!tx.verify_relay_proofs());
        assert!(dag.attach_and_verify_tx(tx).is_err());
        assert_eq!(dag.balance(relay.address().as_bytes()), 0);
        assert_eq!(dag.relay_credit(relay.address().as_bytes()), 0);
        assert_eq!(dag.current_supply, 0);
    }

    #[test]
    fn sidecar_cannot_change_payouts_after_first_ingest() {
        let (alice, bob, relay) = wallets(0xDA6_0F12);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        dag.accept_wire_vertex(tx.clone()).unwrap();
        let before = dag.balance(relay.address().as_bytes());
        let mut forged = tx.clone();
        forged.relay_nodes.push(*relay.address().as_bytes());
        assert_eq!(dag.accept_wire_vertex(forged).unwrap(), false);
        assert_eq!(dag.balance(relay.address().as_bytes()), before);
        assert_eq!(dag.relay_credit(relay.address().as_bytes()), 0);
    }

    #[test]
    fn empty_relays_miner_keeps_fee_and_subsidy() {
        let (alice, bob, _) = wallets(0xDA6_0E00);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        assert!(tx.relay_nodes.is_empty());
        dag.attach_and_verify_tx(tx).unwrap();
        let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
        assert_eq!(
            dag.balance(alice.address().as_bytes()),
            PHONE_CREDIT - SEND_AMOUNT - FIXED_TRANSACTION_FEE + pool
        );
        assert_eq!(dag.relay_credit(alice.address().as_bytes()), 0);
    }

    #[test]
    fn credit_checked_overflow_is_reported() {
        let (alice, _, _) = wallets(0xDA6_0F00);
        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), u64::MAX);
        assert_eq!(
            dag.credit_checked(*alice.address().as_bytes(), 1),
            Err(EconomicError::Overflow)
        );
    }

    #[test]
    fn apply_as_miner_refuses_pc_host() {
        if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            return;
        }
        let (alice, bob, _) = wallets(0xDA6_0BAD);
        let mut dag = KronDAG::with_genesis();
        let tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        let err = apply_dag_minting_as_miner(&mut dag, &tx, tx.sender, &[]).unwrap_err();
        assert!(matches!(err, crate::dag::DagError::Shield(e) if e.is_critical()));
        assert_eq!(dag.current_supply, 0);
    }

    #[test]
    fn apply_wrapper_uses_tx_sender_as_miner() {
        let (alice, bob, _) = wallets(0xDA6_02A9);
        let mut dag = KronDAG::with_genesis();
        let tx = dag
            .compose_and_sign(&alice, *bob.address().as_bytes(), SEND_AMOUNT)
            .unwrap();
        apply_dag_minting_from_sender(&mut dag, &tx, Vec::new()).unwrap();
        assert_eq!(dag.current_supply, INITIAL_TX_SUBSIDY);
        assert_eq!(
            dag.balance(alice.address().as_bytes()),
            INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE
        );
        assert_eq!(dag.dag_tx_count, 1);
    }
}
