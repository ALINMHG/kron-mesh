//! Sync in-process explorer query API (HTTP is optional and not required).

use crate::dag::{DagTransaction, KronDAG, TxHash};
use crate::explorer::indexer::{
    ExplorerEngine, IndexedTransaction, IndexedVertex, NetworkStats, WalletSnapshot,
};
use crate::kron::{get_kron_metadata, AssetMetadata};

/// Required explorer surface: hash lookup, wallet history, and network stats.
#[derive(Clone, Debug, Default)]
pub struct ExplorerApi {
    engine: ExplorerEngine,
}

impl ExplorerApi {
    pub fn new() -> Self {
        Self {
            engine: ExplorerEngine::new(),
        }
    }

    pub fn engine(&self) -> &ExplorerEngine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut ExplorerEngine {
        &mut self.engine
    }

    pub fn sync_from_dag(&mut self, dag: &KronDAG) {
        self.engine.sync_from_dag(dag);
    }

    pub fn index_new_vertex(&mut self, dag: &KronDAG, tx: &DagTransaction) -> IndexedTransaction {
        self.engine.index_new_vertex(dag, tx)
    }

    pub fn get_transaction_by_hash(&self, hash: TxHash) -> Option<IndexedTransaction> {
        self.engine.get_transaction_by_hash(hash)
    }

    pub fn get_wallet_history(&self, address: String) -> Vec<IndexedTransaction> {
        self.engine.get_wallet_history(address)
    }

    pub fn get_wallet_balance(&self, address: impl AsRef<str>) -> u64 {
        self.engine.get_wallet_balance(address)
    }

    pub fn get_wallet_snapshot(&self, address: impl AsRef<str>) -> WalletSnapshot {
        self.engine.get_wallet_snapshot(address)
    }

    pub fn compose_hint(&self, address: impl AsRef<str>) -> (u64, TxHash, TxHash, u64) {
        self.engine.compose_hint(address)
    }

    pub fn genesis(&self) -> TxHash {
        self.engine.tips().first().copied().unwrap_or([0u8; 32])
    }

    pub fn get_network_stats(&self) -> NetworkStats {
        self.engine.get_network_stats()
    }

    pub fn get_kron_asset_metadata(&self) -> AssetMetadata {
        get_kron_asset_metadata()
    }

    pub fn tips(&self) -> Vec<TxHash> {
        self.engine.tips()
    }

    pub fn recent_vertices(&self, limit: usize) -> Vec<IndexedVertex> {
        self.engine.recent_vertices(limit)
    }

    pub fn recent_transactions(&self, limit: usize) -> Vec<IndexedTransaction> {
        self.engine.recent_transactions(limit)
    }

    /// Index a signed demo transfer so the first page load is not empty.
    pub fn seed_demo_if_empty(&mut self) -> bool {
        crate::explorer::seed::seed_demo_if_empty(self)
    }
}

/// Brand record for the web UI (geometric / matte black / electric blue).
pub fn get_kron_asset_metadata() -> AssetMetadata {
    get_kron_metadata()
}
