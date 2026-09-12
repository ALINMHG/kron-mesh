//! §45 `dag_reconciliation` — Have/Need over a short tip inventory.
//!
//! Phones do not dump the entire history. Each side advertises current tips
//! plus a bounded recent ancestor set. The peer then:
//! * **Need** — remote tips / recent hashes we do not store (never genesis
//!   when we already have it), plus missing ancestors of remote tips we *do*
//!   already store.
//! * **Have** — the local tip subgraph the remote did not advertise, stopping
//!   at a hash the remote listed (common prefix) or at shared genesis.

use std::collections::HashSet;

use crate::types::Address;

use super::engine::KronDAG;
use super::tx::{TxHash, NULL_PARENT};

/// Hard cap on advertised tip + recent hashes (DoS bound).
pub const MAX_INVENTORY_HASHES: usize = 4_096;

/// Compact advertisement of a phone's DAG frontier.
/// Faucet / bootstrap credits are never advertised: they are local-only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncInventory {
    pub tips: Vec<TxHash>,
    /// Optional recent hashes (tip parent-closures, genesis omitted).
    pub recent: Vec<TxHash>,
    pub peer_id: Option<Address>,
}

impl SyncInventory {
    pub fn new(tips: Vec<TxHash>) -> Self {
        Self {
            tips,
            recent: Vec::new(),
            peer_id: None,
        }
    }

    /// Build an inventory from local tips and their parent closures.
    /// Genesis is assumed shared and is not listed in `recent`.
    pub fn from_dag(dag: &KronDAG, peer_id: Address) -> Self {
        let mut tips: Vec<TxHash> = dag.tips().iter().copied().collect();
        tips.sort();
        let genesis = dag.genesis_id();
        let mut seen = HashSet::new();
        let mut recent = Vec::new();
        for tip in &tips {
            for h in dag.parent_closure(*tip) {
                if h == genesis || h == NULL_PARENT {
                    continue;
                }
                if seen.insert(h) {
                    recent.push(h);
                }
            }
        }
        recent.sort();
        Self {
            tips,
            recent,
            peer_id: Some(peer_id),
        }
    }

    /// Tips ∪ recent (deduped).
    pub fn advertised(&self) -> HashSet<TxHash> {
        let mut set = HashSet::with_capacity(self.tips.len() + self.recent.len());
        set.extend(self.tips.iter().copied());
        set.extend(self.recent.iter().copied());
        set
    }
}

/// First tuple: **Need** (download). Second: **Have** (send).
pub fn compute_dag_diff(
    local_dag: &KronDAG,
    remote_inventory: &SyncInventory,
) -> (Vec<TxHash>, Vec<TxHash>) {
    let need = collect_need(local_dag, remote_inventory);
    let have = collect_have(local_dag, &remote_inventory.advertised());
    (need, have)
}

fn collect_need(local: &KronDAG, remote: &SyncInventory) -> Vec<TxHash> {
    let genesis = local.genesis_id();
    let mut need = HashSet::new();

    for tip in &remote.tips {
        if *tip == NULL_PARENT {
            continue;
        }
        if local.contains(tip) {
            // Walk ancestors we already store; request any hole (should be rare
            // on a consistent DAG, but keeps partial sync honest).
            if let Some(tx) = local.get(tip) {
                for p in [tx.parent_1, tx.parent_2] {
                    if p != NULL_PARENT && !local.contains(&p) {
                        need.insert(p);
                    }
                }
            }
            continue;
        }
        if *tip == genesis && local.contains(&genesis) {
            continue;
        }
        need.insert(*tip);
    }

    for h in &remote.recent {
        if *h == NULL_PARENT {
            continue;
        }
        if local.contains(h) {
            continue;
        }
        if *h == genesis && local.contains(&genesis) {
            continue;
        }
        need.insert(*h);
    }

    let mut out: Vec<TxHash> = need.into_iter().collect();
    out.sort();
    out
}

fn collect_have(local: &KronDAG, advertised: &HashSet<TxHash>) -> Vec<TxHash> {
    let genesis = local.genesis_id();
    let mut have = Vec::new();
    let mut seen = HashSet::new();
    for tip in local.tips() {
        let mut stack = vec![*tip];
        while let Some(h) = stack.pop() {
            if !seen.insert(h) {
                continue;
            }
            if h == NULL_PARENT || h == genesis {
                continue;
            }
            // Remote already advertised this hash: they have it (and its
            // ancestors). Do not dump that prefix.
            if advertised.contains(&h) {
                continue;
            }
            if !local.contains(&h) {
                continue;
            }
            have.push(h);
            if let Some(tx) = local.get(&h) {
                if tx.parent_1 != NULL_PARENT {
                    stack.push(tx.parent_1);
                }
                if tx.parent_2 != NULL_PARENT && tx.parent_2 != tx.parent_1 {
                    stack.push(tx.parent_2);
                }
            }
        }
    }
    have.sort();
    have
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::FIXED_TRANSACTION_FEE;

    #[test]
    fn shared_genesis_is_not_needed() {
        let local = KronDAG::with_genesis();
        let remote = KronDAG::with_genesis();
        assert_eq!(local.genesis_id(), remote.genesis_id());
        let inv = SyncInventory::from_dag(&remote, [1u8; 32]);
        let (need, have) = compute_dag_diff(&local, &inv);
        assert!(need.is_empty(), "shared genesis must not be Need");
        assert!(have.is_empty(), "nothing unique to send");
        assert_eq!(local.vertex_count(), 1);
        assert_eq!(FIXED_TRANSACTION_FEE, 1_000);
    }
}
