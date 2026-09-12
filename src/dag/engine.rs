//! In-memory KRON mesh DAG: tips, cumulative weights, and a local account ledger.

use std::collections::{HashMap, HashSet};

use rand::seq::IteratorRandom;
use rand::Rng;

use crate::crypto::lattice::LatticeKeyPair;
use crate::crypto::mobile_only::enforce_real_mobile;
use crate::economics::{EconomicError, FIXED_TRANSACTION_FEE};
use crate::kron::KronKeypair;
use crate::types::Address;

use super::error::DagError;
use super::minting::mint_confirmed_tx;
use super::tx::{DagTransaction, GENESIS_SEED, NULL_PARENT, TxHash};

/// Who is attaching a vertex. Miner/relay admission calls the phone-only
/// enforcer; [`Self::LocalGraph`] is ledger replay (tests, explorer, WAL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachingDevice {
    /// In-process graph / economics. Does not admit this host as a miner.
    LocalGraph,
    /// This host is the attaching miner phone.
    Miner,
    /// This host is the attaching mesh relay.
    Relay,
}

impl AttachingDevice {
    /// Runtime gate for the attaching miner/relay device. No-op for replay.
    pub fn admit_host(self) -> Result<(), DagError> {
        match self {
            Self::LocalGraph => Ok(()),
            Self::Miner | Self::Relay => enforce_real_mobile().map_err(DagError::Shield),
        }
    }
}

/// Cap ancestor walks when updating weights or checking parent closure.
/// Tests stay well below this; phones must not walk unbounded history.
const ANCESTOR_WALK_BOUND: usize = 1_024;
/// Cap the MCMC walk toward a tip (depth, not |V|).
const TIP_WALK_BOUND: usize = 256;

/// Local mesh DAG. No server-produced blocks — phones attach signed vertices.
#[derive(Clone, Debug)]
pub struct KronDAG {
    vertices: HashMap<TxHash, DagTransaction>,
    children: HashMap<TxHash, HashSet<TxHash>>,
    tips: HashSet<TxHash>,
    /// Own weight 1 plus one per future approver (IOTA-style cumulative weight).
    weights: HashMap<TxHash, u64>,
    balances: HashMap<Address, u64>,
    next_nonce: HashMap<Address, u64>,
    genesis_id: Option<TxHash>,
    /// Local sidecar: `Mesh_Relay_Node` that physically carried each imported
    /// vertex. Never written into the signed payload (remote txs are already
    /// signed without a relay field).
    pub(crate) relay_of: HashMap<TxHash, Address>,
    /// Accrued 20% of `(subsidy + fee)` keyed by `Mesh_Relay_Node` identity.
    pub(crate) relay_credits: HashMap<Address, u64>,
    /// Official circulating DAG supply (subsidy only; faucet credits do not count).
    pub current_supply: u64,
    /// Confirmed user DAG vertices on this local graph (virtual-epoch counter).
    pub dag_tx_count: u64,
    /// Attach order (genesis first). Used to persist and restore the graph.
    attach_order: Vec<TxHash>,
    /// Bootstrap / faucet credits (not minted supply). Rebuild uses this as
    /// the ledger baseline so a peer can replay spends after mesh sync.
    faucet: HashMap<Address, u64>,
    /// Conflict losers: `loser_tx_id → winner_tx_id` (or `NULL_PARENT` if the
    /// overlapping spend lost on balance rather than a same-nonce pair).
    /// Losers stay in `vertices` for audit but do not affect balances.
    conflicts: HashMap<TxHash, TxHash>,
}

impl Default for KronDAG {
    fn default() -> Self {
        Self::with_genesis()
    }
}

impl KronDAG {
    pub fn new() -> Self {
        Self {
            vertices: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
            weights: HashMap::new(),
            balances: HashMap::new(),
            next_nonce: HashMap::new(),
            genesis_id: None,
            relay_of: HashMap::new(),
            relay_credits: HashMap::new(),
            current_supply: 0,
            dag_tx_count: 0,
            attach_order: Vec::new(),
            faucet: HashMap::new(),
            conflicts: HashMap::new(),
        }
    }

    /// Insert the IOTA-style genesis vertex (dummy [`NULL_PARENT`] pair, fee 0).
    pub fn with_genesis() -> Self {
        let mut dag = Self::new();
        dag.ensure_genesis();
        dag
    }

    /// Attach protocol genesis when the local graph has no vertices.
    ///
    /// Returns `true` when genesis was created. Safe to call on a loaded DAG.
    pub fn ensure_genesis(&mut self) -> bool {
        if !self.vertices.is_empty() {
            return false;
        }
        let genesis = signed_genesis_tx();
        self.attach_and_verify_tx(genesis)
            .expect("protocol genesis must attach");
        true
    }

    pub fn genesis_id(&self) -> TxHash {
        self.genesis_id.unwrap_or(NULL_PARENT)
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub fn tips(&self) -> &HashSet<TxHash> {
        &self.tips
    }

    pub fn get(&self, id: &TxHash) -> Option<&DagTransaction> {
        self.vertices.get(id)
    }

    pub fn contains(&self, id: &TxHash) -> bool {
        self.vertices.contains_key(id)
    }

    /// All vertex hashes currently in the DAG (including genesis).
    pub fn vertex_set(&self) -> HashSet<TxHash> {
        self.vertices.keys().copied().collect()
    }

    /// Bodies for `ids` that we already store (skips unknown hashes).
    pub fn transactions_for(&self, ids: &[TxHash]) -> Vec<DagTransaction> {
        ids.iter()
            .filter_map(|id| self.vertices.get(id).cloned())
            .collect()
    }

    /// Requested bodies in attach order (parents before children) for wire sync.
    pub fn transactions_for_in_order(&self, ids: &[TxHash]) -> Vec<DagTransaction> {
        let want: HashSet<TxHash> = ids.iter().copied().collect();
        self.attach_order
            .iter()
            .filter(|id| want.contains(*id))
            .filter_map(|id| self.vertices.get(id).cloned())
            .collect()
    }

    /// Phone marked `Mesh_Relay_Node` for an imported vertex, if any.
    pub fn relay_node(&self, id: &TxHash) -> Option<Address> {
        self.relay_of.get(id).copied()
    }

    /// Accrued 20% of `(subsidy + fee)` for a `Mesh_Relay_Node` on this local DAG.
    pub fn relay_credit(&self, relay: &Address) -> u64 {
        self.relay_credits.get(relay).copied().unwrap_or(0)
    }

    /// Alias of [`Self::dag_tx_count`] (confirmed global / local user txs).
    pub fn global_tx_count(&self) -> u64 {
        self.dag_tx_count
    }

    /// Checked credit used by DAG minting (not the test faucet).
    pub(crate) fn credit_checked(
        &mut self,
        address: Address,
        amount: u64,
    ) -> Result<(), EconomicError> {
        if amount == 0 {
            return Ok(());
        }
        let entry = self.balances.entry(address).or_insert(0);
        *entry = entry.checked_add(amount).ok_or(EconomicError::Overflow)?;
        Ok(())
    }

    pub fn cumulative_weight(&self, id: &TxHash) -> u64 {
        self.weights.get(id).copied().unwrap_or(0)
    }

    pub fn balance(&self, address: &Address) -> u64 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    pub fn next_nonce(&self, address: &Address) -> u64 {
        self.next_nonce.get(address).copied().unwrap_or(0)
    }

    pub fn children_of(&self, id: &TxHash) -> impl Iterator<Item = &TxHash> {
        self.children
            .get(id)
            .into_iter()
            .flat_map(|set| set.iter())
    }

    pub fn has_children(&self, id: &TxHash) -> bool {
        self.children.get(id).is_some_and(|c| !c.is_empty())
    }

    /// Credit the local ledger only (bootstrap / test faucet). Not a DAG vertex
    /// and does **not** increase [`Self::current_supply`].
    pub fn credit_account(&mut self, address: Address, amount: u64) {
        if amount == 0 {
            return;
        }
        let entry = self.balances.entry(address).or_insert(0);
        *entry = entry.saturating_add(amount);
        let faucet = self.faucet.entry(address).or_insert(0);
        *faucet = faucet.saturating_add(amount);
    }

    /// Faucet map for snapshots and `SyncInventory` (not minted supply).
    pub fn faucet_snapshot(&self) -> std::collections::BTreeMap<Address, u64> {
        self.faucet.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Union a peer's faucet advertisement. Only the missing delta is credited.
    pub fn apply_faucet_hint(&mut self, address: Address, amount: u64) {
        let have = self.faucet.get(&address).copied().unwrap_or(0);
        if amount > have {
            self.credit_account(address, amount - have);
        }
    }

    /// True when `id` is stored but excluded from the ledger (conflict loser).
    pub fn is_conflict(&self, id: &TxHash) -> bool {
        self.conflicts.contains_key(id)
    }

    /// Winner chosen for a stored loser, if this vertex lost a conflict.
    pub fn conflict_winner(&self, loser: &TxHash) -> Option<TxHash> {
        self.conflicts.get(loser).copied()
    }

    /// Phone-facing parent pick. Uses the thread RNG.
    pub fn select_parents(&self) -> (TxHash, TxHash) {
        self.select_parents_with_rng(&mut rand::thread_rng())
    }

    /// Simplified MCMC / weighted random walk toward current tips.
    ///
    /// Rule:
    /// * Walk from genesis along child edges. At each vertex pick a child
    ///   with probability proportional to that child's cumulative weight
    ///   (integer weights only — no `exp(-α·ΔW)` floats).
    /// * Only the current vertex's children are inspected (O(degree), not |V|).
    /// * One tip: return `(tip, genesis)` when they differ; `(tip, tip)` only
    ///   while the DAG is a single vertex.
    /// * Two or more tips: two independent walks; if they collide, replace the
    ///   second parent with a different tip from the tips set.
    pub fn select_parents_with_rng<R: Rng>(&self, rng: &mut R) -> (TxHash, TxHash) {
        let genesis = self.genesis_id();
        if self.tips.is_empty() {
            return (NULL_PARENT, NULL_PARENT);
        }
        if self.tips.len() == 1 {
            let tip = *self.tips.iter().next().expect("len == 1");
            if tip == genesis {
                return (tip, tip);
            }
            return (tip, genesis);
        }

        let p1 = self.walk_to_tip(rng);
        let mut p2 = self.walk_to_tip(rng);
        if p1 == p2 {
            for t in &self.tips {
                if *t != p1 {
                    p2 = *t;
                    break;
                }
            }
        }
        (p1, p2)
    }

    fn walk_to_tip<R: Rng>(&self, rng: &mut R) -> TxHash {
        let genesis = self.genesis_id();
        let mut current = if self.vertices.contains_key(&genesis) {
            genesis
        } else {
            return self
                .tips
                .iter()
                .choose(rng)
                .copied()
                .unwrap_or(NULL_PARENT);
        };

        for _ in 0..TIP_WALK_BOUND {
            match self.pick_weighted_child(current, rng) {
                Some(next) => current = next,
                None => return current,
            }
        }
        self.tips
            .iter()
            .choose(rng)
            .copied()
            .unwrap_or(current)
    }

    /// Weighted pick among *this vertex's* children only.
    fn pick_weighted_child<R: Rng>(&self, parent: TxHash, rng: &mut R) -> Option<TxHash> {
        let kids = self.children.get(&parent)?;
        if kids.is_empty() {
            return None;
        }
        let mut total = 0u64;
        for h in kids {
            total = total.saturating_add(self.weights.get(h).copied().unwrap_or(1).max(1));
        }
        if total == 0 {
            return kids.iter().next().copied();
        }
        let mut ticket = rng.gen_range(0..total);
        for h in kids {
            let w = self.weights.get(h).copied().unwrap_or(1).max(1);
            if ticket < w {
                return Some(*h);
            }
            ticket -= w;
        }
        kids.iter().next().copied()
    }

    /// Select parents, sign with the phone key, and return a ready vertex.
    pub fn compose_and_sign(
        &self,
        wallet: &KronKeypair,
        recipient: Address,
        amount: u64,
    ) -> Result<DagTransaction, DagError> {
        let (p1, p2) = self.select_parents();
        self.compose_and_sign_with_parents(wallet, recipient, amount, p1, p2)
    }

    pub fn compose_and_sign_with_rng<R: Rng>(
        &self,
        wallet: &KronKeypair,
        recipient: Address,
        amount: u64,
        rng: &mut R,
    ) -> Result<DagTransaction, DagError> {
        let (p1, p2) = self.select_parents_with_rng(rng);
        self.compose_and_sign_with_parents(wallet, recipient, amount, p1, p2)
    }

    pub fn compose_and_sign_with_parents(
        &self,
        wallet: &KronKeypair,
        recipient: Address,
        amount: u64,
        parent_1: TxHash,
        parent_2: TxHash,
    ) -> Result<DagTransaction, DagError> {
        let sender = wallet.public_key().address();
        let nonce = self.next_nonce(&sender);
        DagTransaction::user_transfer(parent_1, parent_2, wallet, recipient, amount, nonce)
    }

    /// Verify and attach a vertex (ledger replay / user-wallet tests).
    ///
    /// For the **attaching miner/relay device** use [`Self::attach_and_verify_for`]
    /// with [`AttachingDevice::Miner`] or [`AttachingDevice::Relay`] — those
    /// paths call [`enforce_real_mobile`]. This method does not ban reading
    /// tests or WAL/explorer replay on a PC.
    pub fn attach_and_verify_tx(&mut self, tx: DagTransaction) -> Result<(), DagError> {
        self.attach_and_verify_for(tx, AttachingDevice::LocalGraph)
    }

    /// Attach as the local miner phone. Isolated on x86/emulator hosts.
    pub fn attach_and_verify_tx_as_miner(&mut self, tx: DagTransaction) -> Result<(), DagError> {
        self.attach_and_verify_for(tx, AttachingDevice::Miner)
    }

    /// Attach as the local mesh relay phone. Isolated on x86/emulator hosts.
    pub fn attach_and_verify_tx_as_relay(&mut self, tx: DagTransaction) -> Result<(), DagError> {
        self.attach_and_verify_for(tx, AttachingDevice::Relay)
    }

    /// Verify + attach. Miner/relay device roles call the host enforcer first.
    pub fn attach_and_verify_for(
        &mut self,
        tx: DagTransaction,
        device: AttachingDevice,
    ) -> Result<(), DagError> {
        device.admit_host()?;
        let relays = tx.relay_nodes.clone();
        self.attach_vertex_and_maybe_mint(tx, true, &relays)
    }

    /// Attach without minting. Kept for callers that insert then mint once.
    #[allow(dead_code)]
    pub(crate) fn attach_vertex_unminted(&mut self, tx: DagTransaction) -> Result<(), DagError> {
        self.attach_vertex_and_maybe_mint(tx, false, &[])
    }

    fn attach_vertex_and_maybe_mint(
        &mut self,
        tx: DagTransaction,
        mint: bool,
        mint_relays: &[Address],
    ) -> Result<(), DagError> {
        if self.vertices.contains_key(&tx.id) {
            return Err(DagError::DuplicateTx(tx.id));
        }
        self.check_parents(&tx)?;
        if tx.is_genesis() {
            if tx.fee != 0 {
                return Err(DagError::InvalidFee);
            }
        } else if tx.fee != FIXED_TRANSACTION_FEE {
            return Err(DagError::InvalidFee);
        }
        if tx.public_key.address() != tx.sender {
            return Err(DagError::AddressMismatch);
        }
        if !tx.verify_signature() {
            return Err(DagError::InvalidSignature);
        }
        if !tx.verify_relay_proofs() {
            return Err(DagError::InvalidRelayProof);
        }

        let expected = self.next_nonce(&tx.sender);
        if tx.nonce != expected {
            return Err(DagError::DoubleSpend { nonce: tx.nonce });
        }

        let cost = tx
            .amount
            .checked_add(tx.fee)
            .ok_or(DagError::Overflow)?;
        let from_bal = self.balance(&tx.sender);
        if from_bal < cost {
            return Err(DagError::InsufficientBalance);
        }
        let (new_from, new_to) = if tx.sender == tx.recipient {
            let after_fee = from_bal.checked_sub(tx.fee).ok_or(DagError::Overflow)?;
            (after_fee, after_fee)
        } else {
            let new_from = from_bal.checked_sub(cost).ok_or(DagError::Overflow)?;
            let new_to = self
                .balance(&tx.recipient)
                .checked_add(tx.amount)
                .ok_or(DagError::Overflow)?;
            (new_from, new_to)
        };

        let id = tx.id;
        let p1 = tx.parent_1;
        let p2 = tx.parent_2;
        let sender = tx.sender;
        let recipient = tx.recipient;
        let fee = tx.fee;
        let is_genesis = tx.is_genesis();

        self.vertices.insert(id, tx);
        self.attach_order.push(id);
        self.weights.insert(id, 1);
        self.children.entry(id).or_default();
        self.tips.insert(id);
        self.note_child(p1, id);
        if p2 != p1 {
            self.note_child(p2, id);
        }
        if is_genesis {
            self.genesis_id = Some(id);
        } else {
            self.increment_ancestor_weights(p1, p2);
        }

        self.balances.insert(sender, new_from);
        if sender != recipient {
            self.balances.insert(recipient, new_to);
        }
        self.next_nonce.insert(sender, expected.saturating_add(1));

        if mint && !is_genesis {
            // Fee already deducted from the sender (sink). Minting redistributes
            // fee + new subsidy; it must not charge the sender again.
            mint_confirmed_tx(self, fee, sender, mint_relays).map_err(|e| match e {
                EconomicError::Overflow => DagError::Overflow,
            })?;
        }
        Ok(())
    }

    fn check_parents(&self, tx: &DagTransaction) -> Result<(), DagError> {
        if tx.is_genesis() {
            if !self.vertices.is_empty() {
                return Err(DagError::InvalidGenesis);
            }
            return Ok(());
        }
        for p in [tx.parent_1, tx.parent_2] {
            if p == NULL_PARENT || !self.vertices.contains_key(&p) {
                return Err(DagError::UnknownParent(p));
            }
        }
        Ok(())
    }

    fn note_child(&mut self, parent: TxHash, child: TxHash) {
        if parent == NULL_PARENT {
            return;
        }
        self.children.entry(parent).or_default().insert(child);
        self.tips.remove(&parent);
    }

    fn increment_ancestor_weights(&mut self, p1: TxHash, p2: TxHash) {
        let mut stack = Vec::with_capacity(8);
        if p1 != NULL_PARENT {
            stack.push(p1);
        }
        if p2 != NULL_PARENT && p2 != p1 {
            stack.push(p2);
        }
        let mut seen = HashSet::new();
        let mut steps = 0usize;
        while let Some(h) = stack.pop() {
            if h == NULL_PARENT || !seen.insert(h) {
                continue;
            }
            if steps >= ANCESTOR_WALK_BOUND {
                break;
            }
            steps += 1;
            if let Some(w) = self.weights.get_mut(&h) {
                *w = w.saturating_add(1);
            }
            if let Some(tx) = self.vertices.get(&h) {
                if tx.parent_1 != NULL_PARENT {
                    stack.push(tx.parent_1);
                }
                if tx.parent_2 != NULL_PARENT && tx.parent_2 != tx.parent_1 {
                    stack.push(tx.parent_2);
                }
            }
        }
    }

    /// All vertices reachable by walking parents from `id` (includes `id`).
    pub fn parent_closure(&self, id: TxHash) -> HashSet<TxHash> {
        let mut seen = HashSet::new();
        let mut stack = vec![id];
        let mut steps = 0usize;
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if steps >= ANCESTOR_WALK_BOUND {
                break;
            }
            steps += 1;
            if let Some(tx) = self.vertices.get(&cur) {
                if tx.parent_1 != NULL_PARENT {
                    stack.push(tx.parent_1);
                }
                if tx.parent_2 != NULL_PARENT {
                    stack.push(tx.parent_2);
                }
            }
        }
        seen
    }

    /// Vertices in attach order (genesis first). Gateway WAL uses this.
    pub fn transactions_in_order(&self) -> Vec<DagTransaction> {
        self.attach_order
            .iter()
            .filter_map(|id| self.vertices.get(id).cloned())
            .collect()
    }

    pub fn account_snapshot(&self) -> std::collections::BTreeMap<Address, u64> {
        self.balances.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn nonce_snapshot(&self) -> std::collections::BTreeMap<Address, u64> {
        self.next_nonce.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn tip_list(&self) -> Vec<TxHash> {
        let mut tips: Vec<TxHash> = self.tips.iter().copied().collect();
        tips.sort();
        tips
    }

    /// Tips set matches the child map: no tip has children.
    pub fn tips_are_consistent(&self) -> bool {
        for tip in &self.tips {
            if self.has_children(tip) {
                return false;
            }
        }
        for (id, kids) in &self.children {
            if !kids.is_empty() && self.tips.contains(id) {
                return false;
            }
        }
        for id in self.vertices.keys() {
            if !self.has_children(id) && !self.tips.contains(id) {
                return false;
            }
        }
        true
    }

    /// Hub / test ingest: LocalGraph attach, or store a conflicting spend and
    /// rebuild the ledger so exactly one of the spends affects balances.
    pub fn accept_wire_vertex(&mut self, tx: DagTransaction) -> Result<bool, DagError> {
        if self.contains(&tx.id) {
            return Ok(false);
        }
        match self.attach_and_verify_tx(tx.clone()) {
            Ok(()) => Ok(true),
            Err(DagError::DoubleSpend { .. }) | Err(DagError::InsufficientBalance) => {
                self.insert_graph_only(tx)?;
                self.resolve_conflicts_and_rebuild_ledger()?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Insert a signed vertex into the graph without touching the ledger.
    /// Used by meetup merge and conflict storage (audit / orphan).
    pub(crate) fn insert_graph_only(&mut self, tx: DagTransaction) -> Result<(), DagError> {
        if self.vertices.contains_key(&tx.id) {
            return Err(DagError::DuplicateTx(tx.id));
        }
        self.check_parents(&tx)?;
        if tx.is_genesis() {
            if tx.fee != 0 {
                return Err(DagError::InvalidFee);
            }
        } else if tx.fee != FIXED_TRANSACTION_FEE {
            return Err(DagError::InvalidFee);
        }
        if tx.public_key.address() != tx.sender {
            return Err(DagError::AddressMismatch);
        }
        if !tx.verify_signature() {
            return Err(DagError::InvalidSignature);
        }
        if !tx.verify_relay_proofs() {
            return Err(DagError::InvalidRelayProof);
        }

        let id = tx.id;
        let p1 = tx.parent_1;
        let p2 = tx.parent_2;
        let is_genesis = tx.is_genesis();

        self.vertices.insert(id, tx);
        self.attach_order.push(id);
        self.weights.insert(id, 1);
        self.children.entry(id).or_default();
        self.tips.insert(id);
        self.note_child(p1, id);
        if p2 != p1 {
            self.note_child(p2, id);
        }
        if is_genesis {
            self.genesis_id = Some(id);
        } else {
            self.increment_ancestor_weights(p1, p2);
        }
        Ok(())
    }

    /// Deterministic conflict rule: same-sender spends that cannot both be
    /// true (same nonce, or overlapping balance after nonce winners).
    /// Higher cumulative weight wins; ties break by greater tx-id bytes.
    pub fn resolve_conflicts_and_rebuild_ledger(&mut self) -> Result<(), DagError> {
        let genesis = self.genesis_id();
        let mut by_nonce: HashMap<(Address, u64), Vec<TxHash>> = HashMap::new();
        for (id, tx) in &self.vertices {
            if *id == genesis || tx.is_genesis() {
                continue;
            }
            by_nonce.entry((tx.sender, tx.nonce)).or_default().push(*id);
        }

        let mut losers = HashSet::new();
        let mut winner_of: HashMap<TxHash, TxHash> = HashMap::new();
        for ((_sender, _nonce), mut group) in by_nonce {
            if group.len() <= 1 {
                continue;
            }
            group.sort_by(|a, b| conflict_rank(self, a).cmp(&conflict_rank(self, b)));
            let winner = *group.last().expect("group len > 1");
            for id in &group {
                if *id != winner {
                    losers.insert(*id);
                    winner_of.insert(*id, winner);
                }
            }
        }

        let faucet = self.faucet.clone();
        self.balances.clear();
        for (addr, amount) in &faucet {
            self.balances.insert(*addr, *amount);
        }
        self.next_nonce.clear();
        self.current_supply = 0;
        self.dag_tx_count = 0;
        self.relay_credits.clear();

        let order = self.attach_order.clone();
        let mut extra_losers = Vec::new();
        for id in order {
            if losers.contains(&id) {
                continue;
            }
            let Some(tx) = self.vertices.get(&id).cloned() else {
                continue;
            };
            if tx.is_genesis() {
                continue;
            }
            match self.apply_ledger_effects(&tx) {
                Ok(()) => {}
                Err(DagError::DoubleSpend { .. }) | Err(DagError::InsufficientBalance) => {
                    extra_losers.push(id);
                }
                Err(e) => return Err(e),
            }
        }

        self.conflicts.clear();
        for (loser, winner) in winner_of {
            self.conflicts.insert(loser, winner);
        }
        for loser in extra_losers {
            self.conflicts.entry(loser).or_insert(NULL_PARENT);
        }
        Ok(())
    }

    fn apply_ledger_effects(&mut self, tx: &DagTransaction) -> Result<(), DagError> {
        let expected = self.next_nonce(&tx.sender);
        if tx.nonce != expected {
            return Err(DagError::DoubleSpend { nonce: tx.nonce });
        }
        let cost = tx.amount.checked_add(tx.fee).ok_or(DagError::Overflow)?;
        let from_bal = self.balance(&tx.sender);
        if from_bal < cost {
            return Err(DagError::InsufficientBalance);
        }
        let (new_from, new_to) = if tx.sender == tx.recipient {
            let after_fee = from_bal.checked_sub(tx.fee).ok_or(DagError::Overflow)?;
            (after_fee, after_fee)
        } else {
            let new_from = from_bal.checked_sub(cost).ok_or(DagError::Overflow)?;
            let new_to = self
                .balance(&tx.recipient)
                .checked_add(tx.amount)
                .ok_or(DagError::Overflow)?;
            (new_from, new_to)
        };
        self.balances.insert(tx.sender, new_from);
        if tx.sender != tx.recipient {
            self.balances.insert(tx.recipient, new_to);
        }
        self.next_nonce
            .insert(tx.sender, expected.saturating_add(1));
        mint_confirmed_tx(self, tx.fee, tx.sender, &tx.relay_nodes).map_err(|e| match e {
            EconomicError::Overflow => DagError::Overflow,
        })?;
        Ok(())
    }
}

/// Rank for the merge conflict rule: (cumulative weight, tx id).
fn conflict_rank(dag: &KronDAG, id: &TxHash) -> (u64, TxHash) {
    (dag.cumulative_weight(id), *id)
}

fn signed_genesis_tx() -> DagTransaction {
    let lattice = LatticeKeyPair::from_seed(GENESIS_SEED);
    let wallet = KronKeypair::from_lattice(lattice);
    DagTransaction::assemble(
        NULL_PARENT,
        NULL_PARENT,
        &wallet,
        wallet.public_key().address(),
        0,
        0,
        0,
    )
    .expect("genesis ML-DSA-44 sign")
}
