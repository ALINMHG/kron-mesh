//! In-memory KRON Mesh explorer: vertices, tips, supply, DAG balances.

use std::collections::{BTreeMap, HashMap};

use crate::dag::{DagTransaction, KronDAG, TxHash};
use crate::economics::{
    dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, txs_remaining_until_halving,
    HARD_CAP,
};
use crate::kron::wallet::KronAddress;
use crate::types::Address;

/// Ledger view the indexer reads while recording vertices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshState {
    pub accounts: BTreeMap<Address, u64>,
    pub nonces: BTreeMap<Address, u64>,
    pub dag_tx_count: u64,
    pub circulating_supply: u64,
    pub tips: Vec<TxHash>,
    pub genesis: TxHash,
}

impl MeshState {
    pub fn from_dag(dag: &KronDAG) -> Self {
        Self {
            accounts: dag.account_snapshot(),
            nonces: dag.nonce_snapshot(),
            dag_tx_count: dag.dag_tx_count,
            circulating_supply: dag.current_supply,
            tips: dag.tip_list(),
            genesis: dag.genesis_id(),
        }
    }
}

/// Per-tx fee transparency: 80% miner phone / 20% relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    pub miner_amount: u64,
    pub relay_amount: u64,
    pub miner_address: String,
    pub relay_addresses: Vec<String>,
}

/// Indexed DAG vertex for the query API and web UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedTransaction {
    pub hash: TxHash,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub parent_1: TxHash,
    pub parent_2: TxHash,
    pub weight: u64,
    pub is_tip: bool,
    pub dag_tx_index: u64,
    pub fee_split: FeeSplit,
    /// True when this vertex lost a merge conflict and does not affect balances.
    pub conflicted: bool,
}

/// Tip / recent-vertex row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedVertex {
    pub hash: TxHash,
    pub tx_count: u64,
    pub subsidy: u64,
    pub total_fees: u64,
    pub miner_share: u64,
    pub relay_share: u64,
    pub miner: String,
    pub txs: Vec<IndexedTransaction>,
}

/// Wallet query: ledger balance plus indexed history for a `kron1` address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSnapshot {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub txs: Vec<IndexedTransaction>,
}

/// Circulating supply vs [`HARD_CAP`] plus the next tx-count halving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkStats {
    pub vertex_count: u64,
    pub tip_count: u64,
    pub dag_tx_count: u64,
    pub circulating_supply: u64,
    pub hard_cap: u64,
    pub txs_remaining_until_halving: u64,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            vertex_count: 0,
            tip_count: 0,
            dag_tx_count: 0,
            circulating_supply: 0,
            hard_cap: HARD_CAP,
            txs_remaining_until_halving: txs_remaining_until_halving(0),
        }
    }
}

fn encode_kron1(addr: Address) -> String {
    KronAddress::from_hash(addr).into_string()
}

/// Accept a `kron1…` Bech32 string or a 32-byte hex address (`0x` optional).
pub fn parse_explorer_address(input: &str) -> Option<Address> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = KronAddress::parse(trimmed) {
        return Some(*parsed.as_bytes());
    }
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Some(addr)
}

fn canonical_kron1(input: &str) -> Option<String> {
    parse_explorer_address(input).map(encode_kron1)
}

pub fn index_vertex(dag: &KronDAG, tx: &DagTransaction, dag_tx_index: u64) -> IndexedTransaction {
    let pool = if tx.is_genesis() {
        0
    } else {
        get_current_tx_subsidy(dag_tx_index.saturating_sub(1), 0).saturating_add(tx.fee)
    };
    let miner_amount = dag_miner_share_of(pool);
    let relay_amount = dag_relay_total_of(pool);
    IndexedTransaction {
        hash: tx.id,
        from: tx.sender_kron1.clone(),
        to: tx.recipient_kron1.clone(),
        amount: tx.amount,
        fee: tx.fee,
        parent_1: tx.parent_1,
        parent_2: tx.parent_2,
        weight: dag.cumulative_weight(&tx.id),
        is_tip: dag.tips().contains(&tx.id),
        dag_tx_index,
        conflicted: dag.is_conflict(&tx.id),
        fee_split: FeeSplit {
            miner_amount,
            relay_amount,
            miner_address: tx.sender_kron1.clone(),
            relay_addresses: tx
                .relay_nodes
                .iter()
                .copied()
                .map(encode_kron1)
                .collect(),
        },
    }
}

/// In-memory explorer database. No SQLite — `HashMap` / `BTreeMap` only.
#[derive(Clone, Debug, Default)]
pub struct ExplorerEngine {
    txs_by_hash: HashMap<TxHash, IndexedTransaction>,
    history_by_kron1: HashMap<String, Vec<TxHash>>,
    balances_by_kron1: HashMap<String, u64>,
    nonces_by_kron1: HashMap<String, u64>,
    genesis: TxHash,
    order: Vec<TxHash>,
    tips: Vec<TxHash>,
    circulating_supply: u64,
    dag_tx_count: u64,
    vertex_count: u64,
}

impl ExplorerEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sync_from_dag(&mut self, dag: &KronDAG) {
        *self = Self::default();
        let state = MeshState::from_dag(dag);
        let mut user_index = 0u64;
        for tx in dag.transactions_in_order() {
            if !tx.is_genesis() {
                user_index = user_index.saturating_add(1);
            }
            let row = index_vertex(dag, &tx, user_index);
            self.txs_by_hash.insert(row.hash, row.clone());
            self.order.push(row.hash);
            if canonical_kron1(&row.from).is_some() {
                self.push_history(&row.from, row.hash);
            }
            if row.to != row.from {
                self.push_history(&row.to, row.hash);
            }
        }
        self.sync_balances(&state);
        self.sync_nonces(&state);
        self.genesis = state.genesis;
        self.circulating_supply = state.circulating_supply;
        self.dag_tx_count = state.dag_tx_count;
        self.vertex_count = dag.vertex_count() as u64;
        self.tips = state.tips;
    }

    pub fn index_new_vertex(&mut self, dag: &KronDAG, tx: &DagTransaction) -> IndexedTransaction {
        self.sync_from_dag(dag);
        self.txs_by_hash
            .get(&tx.id)
            .cloned()
            .unwrap_or_else(|| index_vertex(dag, tx, dag.dag_tx_count))
    }

    fn sync_balances(&mut self, state: &MeshState) {
        for (addr, bal) in &state.accounts {
            self.balances_by_kron1.insert(encode_kron1(*addr), *bal);
        }
    }

    fn sync_nonces(&mut self, state: &MeshState) {
        for (addr, nonce) in &state.nonces {
            self.nonces_by_kron1.insert(encode_kron1(*addr), *nonce);
        }
    }

    pub fn get_wallet_balance(&self, address: impl AsRef<str>) -> u64 {
        let Some(kron1) = canonical_kron1(address.as_ref()) else {
            return 0;
        };
        self.balances_by_kron1.get(&kron1).copied().unwrap_or(0)
    }

    pub fn get_wallet_snapshot(&self, address: impl AsRef<str>) -> WalletSnapshot {
        let kron1 = canonical_kron1(address.as_ref())
            .unwrap_or_else(|| address.as_ref().trim().to_string());
        WalletSnapshot {
            address: kron1.clone(),
            balance: self.balances_by_kron1.get(&kron1).copied().unwrap_or(0),
            nonce: self.nonces_by_kron1.get(&kron1).copied().unwrap_or(0),
            txs: self.get_wallet_history(&kron1),
        }
    }

    /// Parents + nonce a wallet needs to compose a spend against this DAG.
    pub fn compose_hint(&self, address: impl AsRef<str>) -> (u64, TxHash, TxHash, u64) {
        let snap = self.get_wallet_snapshot(address);
        let genesis = self.genesis;
        let (p1, p2) = match self.tips.as_slice() {
            [] => (genesis, genesis),
            [t] => (*t, genesis),
            [a, b, ..] => (*a, *b),
        };
        (snap.nonce, p1, p2, snap.balance)
    }

    pub fn get_transaction_by_hash(&self, hash: TxHash) -> Option<IndexedTransaction> {
        self.txs_by_hash.get(&hash).cloned()
    }

    pub fn get_wallet_history(&self, address: impl AsRef<str>) -> Vec<IndexedTransaction> {
        let Some(kron1) = canonical_kron1(address.as_ref()) else {
            return Vec::new();
        };
        let Some(hashes) = self.history_by_kron1.get(&kron1) else {
            return Vec::new();
        };
        let mut txs: Vec<IndexedTransaction> = hashes
            .iter()
            .filter_map(|h| self.txs_by_hash.get(h).cloned())
            .collect();
        txs.sort_by_key(|tx| tx.dag_tx_index);
        txs
    }

    pub fn get_network_stats(&self) -> NetworkStats {
        NetworkStats {
            vertex_count: self.vertex_count,
            tip_count: self.tips.len() as u64,
            dag_tx_count: self.dag_tx_count,
            circulating_supply: self.circulating_supply,
            hard_cap: HARD_CAP,
            txs_remaining_until_halving: txs_remaining_until_halving(self.dag_tx_count),
        }
    }

    pub fn tips(&self) -> Vec<TxHash> {
        self.tips.clone()
    }

    pub fn recent_vertices(&self, limit: usize) -> Vec<IndexedVertex> {
        self.recent_transactions(limit)
            .into_iter()
            .map(|tx| {
                let pool = tx.fee_split.miner_amount.saturating_add(tx.fee_split.relay_amount);
                IndexedVertex {
                    hash: tx.hash,
                    tx_count: 1,
                    subsidy: pool.saturating_sub(tx.fee),
                    total_fees: tx.fee,
                    miner_share: tx.fee_split.miner_amount,
                    relay_share: tx.fee_split.relay_amount,
                    miner: tx.from.clone(),
                    txs: vec![tx],
                }
            })
            .collect()
    }

    pub fn recent_transactions(&self, limit: usize) -> Vec<IndexedTransaction> {
        let mut txs: Vec<IndexedTransaction> = self
            .order
            .iter()
            .rev()
            .filter_map(|h| self.txs_by_hash.get(h).cloned())
            .collect();
        txs.truncate(limit);
        txs
    }

    fn push_history(&mut self, kron1: &str, hash: TxHash) {
        let entry = self.history_by_kron1.entry(kron1.to_string()).or_default();
        if !entry.contains(&hash) {
            entry.push(hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::FIXED_TRANSACTION_FEE;

    #[test]
    fn fee_helpers_are_80_20() {
        assert_eq!(dag_miner_share_of(FIXED_TRANSACTION_FEE), 800);
        assert_eq!(dag_relay_total_of(FIXED_TRANSACTION_FEE), 200);
    }
}
