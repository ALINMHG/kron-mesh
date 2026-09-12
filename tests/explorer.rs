//! End-to-end KRON Mesh explorer: index DAG vertices and query them.

use new_blockchain::dag::KronDAG;
use new_blockchain::economics::{
    dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, txs_remaining_until_halving,
    FIXED_TRANSACTION_FEE, HARD_CAP, INITIAL_TX_SUBSIDY, TX_HALVING_INTERVAL,
};
use new_blockchain::explorer::{get_kron_asset_metadata, ExplorerApi};
use new_blockchain::kron::{derive_kron_address, generate_kron_wallet_from_rng};
use rand::SeedableRng;

#[test]
fn test_kron_explorer_flow() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xE2_91_03E7);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let alice_kron1 = derive_kron_address(alice.public_key());
    let bob_kron1 = derive_kron_address(bob.public_key());

    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let amount = 50_000u64;
    let tx = dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), amount, &mut rng)
        .expect("compose");
    dag.attach_and_verify_tx(tx.clone()).expect("attach");

    let mut api = ExplorerApi::new();
    api.sync_from_dag(&dag);
    let by_hash = api
        .get_transaction_by_hash(tx.id)
        .expect("tx indexed by hash");
    assert_eq!(by_hash.from, alice_kron1);
    assert_eq!(by_hash.to, bob_kron1);
    assert_eq!(by_hash.amount, amount);
    assert_eq!(by_hash.fee, FIXED_TRANSACTION_FEE);
    let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
    assert_eq!(by_hash.fee_split.miner_amount, dag_miner_share_of(pool));
    assert_eq!(by_hash.fee_split.relay_amount, dag_relay_total_of(pool));

    let stats = api.get_network_stats();
    assert_eq!(stats.dag_tx_count, 1);
    assert!(stats.vertex_count >= 2);
    assert_eq!(stats.circulating_supply, get_current_tx_subsidy(0, 0));
    assert_eq!(stats.hard_cap, HARD_CAP);
    assert_eq!(
        stats.txs_remaining_until_halving,
        txs_remaining_until_halving(1)
    );
    assert_eq!(TX_HALVING_INTERVAL, 126_144_000);
    assert_eq!(get_kron_asset_metadata().ticker, "KRON");
}

#[test]
fn explorer_indexes_live_dag_not_blocks() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(99);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 25_000, &mut rng)
        .unwrap();
    let hash = tx.id;
    dag.attach_and_verify_tx(tx).unwrap();

    let mut api = ExplorerApi::new();
    api.sync_from_dag(&dag);
    let fetched = api.get_transaction_by_hash(hash).expect("vertex");
    assert_eq!(fetched.fee, FIXED_TRANSACTION_FEE);
    assert!(fetched.is_tip || api.tips().contains(&hash));
    let stats = api.get_network_stats();
    assert!(stats.dag_tx_count >= 1);
    assert_eq!(stats.hard_cap, HARD_CAP);
    assert!(api.get_wallet_balance(alice.address().as_str()) > 0);
}
