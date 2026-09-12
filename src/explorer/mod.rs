//! Native KRON Mesh explorer: in-memory indexer plus a sync query API.
//!
//! Indexes DAG vertices, tips, and supply. There are no traditional blocks.

pub mod api;
pub mod http;
pub mod indexer;
pub mod seed;

pub use api::{get_kron_asset_metadata, ExplorerApi};
pub use http::start_explorer_http;
pub use seed::seed_demo_if_empty;
pub use indexer::{
    index_vertex, parse_explorer_address, ExplorerEngine, FeeSplit, IndexedTransaction,
    IndexedVertex, MeshState, NetworkStats, WalletSnapshot,
};
pub use crate::dag::TxHash;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::KronDAG;
    use crate::economics::{
        dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, txs_remaining_until_halving,
        FIXED_TRANSACTION_FEE, HARD_CAP, INITIAL_TX_SUBSIDY, TX_HALVING_INTERVAL,
    };
    use crate::kron::{derive_kron_address, generate_kron_wallet_from_rng};
    use rand::SeedableRng;

    #[test]
    fn test_kron_explorer_flow() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xE2_91_03E7);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        let alice_kron1 = derive_kron_address(alice.public_key());
        let bob_kron1 = derive_kron_address(bob.public_key());
        assert!(alice_kron1.starts_with("kron1"));

        let mut dag = KronDAG::with_genesis();
        dag.credit_account(*alice.address().as_bytes(), 1_000_000);
        let amount = 50_000u64;
        let tx = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), amount, &mut rng)
            .expect("compose");
        dag.attach_and_verify_tx(tx.clone()).expect("attach");

        let mut api = ExplorerApi::new();
        assert!(api.seed_demo_if_empty());
        assert!(!api.seed_demo_if_empty());

        let mut api = ExplorerApi::new();
        api.sync_from_dag(&dag);
        let by_hash = api
            .get_transaction_by_hash(tx.id)
            .expect("tx indexed by hash");
        assert_eq!(by_hash.from, alice_kron1);
        assert_eq!(by_hash.to, bob_kron1);
        assert_eq!(by_hash.amount, amount);
        assert_eq!(by_hash.fee, FIXED_TRANSACTION_FEE);
        assert_eq!(by_hash.parent_1, tx.parent_1);
        let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
        assert_eq!(by_hash.fee_split.miner_amount, dag_miner_share_of(pool));
        assert_eq!(by_hash.fee_split.relay_amount, dag_relay_total_of(pool));

        let alice_hist = api.get_wallet_history(alice_kron1.clone());
        assert_eq!(alice_hist, vec![by_hash.clone()]);
        assert_eq!(
            api.get_wallet_history(hex::encode(alice.public_key().address())),
            alice_hist
        );

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

        let meta = api.get_kron_asset_metadata();
        assert_eq!(meta.ticker, "KRON");
        assert_eq!(meta.name, "KRON Network");
        assert_eq!(get_kron_asset_metadata().ticker, "KRON");
    }
}
