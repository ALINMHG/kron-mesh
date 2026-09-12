//! Strict DAG monetary policy. All values are integer minor units (6 decimals).
//! Never use IEEE-754 (`f32`/`f64`) for balances, fees, subsidy, or the cap.

use std::collections::BTreeMap;

use crate::types::Address;

/// Minor units per whole coin (fixed-point scale).
pub const UNITS_PER_COIN: u64 = 1_000_000;
/// Satoshi-KRON / micro-KRON: alias of [`UNITS_PER_COIN`] (1 KRON = 1_000_000).
pub const SATOSHI_KRON: u64 = UNITS_PER_COIN;

/// Maximum lifetime supply: 24 million coins. Protocol premine is exactly zero.
pub const HARD_CAP_COINS: u64 = 24_000_000;
pub const HARD_CAP: u64 = HARD_CAP_COINS.saturating_mul(UNITS_PER_COIN);
pub const PREMINE: u64 = 0;

/// 0.001 coin per applied user vertex, charged in minor units.
pub const FIXED_TRANSACTION_FEE: u64 = 1_000;
/// Alias used by the transfer path.
pub const FIXED_FEE: u64 = FIXED_TRANSACTION_FEE;

/// 0.1 KRON minted per confirmed DAG vertex before the first tx-count halving.
pub const INITIAL_TX_SUBSIDY: u64 = 100_000;

/// Confirmed global DAG tx count per subsidy era (~4 years of high activity).
pub const TX_HALVING_INTERVAL: u64 = 126_144_000;

/// DAG mesh split of `(tx subsidy + fee)`: miner phone vs relay phones.
pub const DAG_MINER_SHARE_PERCENT: u64 = 80;

/// Offline mesh: the phone marked `Mesh_Relay_Node` takes this cut.
pub const RELAY_SHARE_PERCENT: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicError {
    /// A `checked_add` / `checked_mul` overflowed.
    Overflow,
}

impl std::fmt::Display for EconomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => write!(f, "economic integer overflow"),
        }
    }
}

impl std::error::Error for EconomicError {}

/// Convert whole coins to minor units.
pub const fn coins(whole: u64) -> u64 {
    whole.saturating_mul(UNITS_PER_COIN)
}

/// 20% of `total` for a `Mesh_Relay_Node`. Integer rule: `(total * 20) / 100`.
pub const fn relay_share_of(total: u64) -> u64 {
    total.saturating_mul(RELAY_SHARE_PERCENT) / 100
}

/// Miner/sender remainder after the mesh-relay cut.
pub const fn remainder_after_relay(total: u64) -> u64 {
    total.saturating_sub(relay_share_of(total))
}

/// 20% mule / 80% remainder. Not a validator mining split.
pub const fn mesh_relay_split(total: u64) -> (u64, u64) {
    let relay = relay_share_of(total);
    (relay, total.saturating_sub(relay))
}

/// Miner-phone cut of a DAG `(subsidy + fee)` pool.
pub const fn dag_miner_share_of(total_tx_pool: u64) -> u64 {
    total_tx_pool.saturating_mul(DAG_MINER_SHARE_PERCENT) / 100
}

/// Relay-phone remainder so miner + relay == pool (when mul does not saturate).
pub const fn dag_relay_total_of(total_tx_pool: u64) -> u64 {
    total_tx_pool.saturating_sub(dag_miner_share_of(total_tx_pool))
}

/// DAG subsidy at `global_tx_count` given circulating `current_supply`.
///
/// `halvings = global_tx_count / TX_HALVING_INTERVAL`. After 64 halvings
/// emission is forced to zero. Clamped so `current_supply + subsidy ≤ HARD_CAP`.
pub const fn get_current_tx_subsidy(global_tx_count: u64, current_supply: u64) -> u64 {
    let halvings = global_tx_count / TX_HALVING_INTERVAL;
    if halvings >= 64 || current_supply >= HARD_CAP {
        return 0;
    }
    let subsidy = INITIAL_TX_SUBSIDY >> halvings;
    let room = HARD_CAP - current_supply;
    if subsidy > room {
        room
    } else {
        subsidy
    }
}

/// Confirmed user vertices remaining in the current subsidy era.
pub const fn txs_remaining_until_halving(dag_tx_count: u64) -> u64 {
    TX_HALVING_INTERVAL - (dag_tx_count % TX_HALVING_INTERVAL)
}

pub fn total_supply(accounts: &BTreeMap<Address, u64>) -> u64 {
    accounts.values().copied().sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_integer_and_exact() {
        assert_eq!(PREMINE, 0);
        assert_eq!(HARD_CAP, 24_000_000 * 1_000_000);
        assert_eq!(HARD_CAP, 24_000_000_000_000);
        assert_eq!(SATOSHI_KRON, UNITS_PER_COIN);
        assert_eq!(FIXED_TRANSACTION_FEE, 1_000);
        assert_eq!(FIXED_FEE, 1_000);
        assert_eq!(INITIAL_TX_SUBSIDY, 100_000);
        assert_eq!(TX_HALVING_INTERVAL, 126_144_000);
        assert_eq!(DAG_MINER_SHARE_PERCENT, 80);
        assert_eq!(RELAY_SHARE_PERCENT, 20);
        assert_eq!(relay_share_of(FIXED_TRANSACTION_FEE), 200);
        assert_eq!(remainder_after_relay(FIXED_TRANSACTION_FEE), 800);
        let (relay, rest) = mesh_relay_split(FIXED_TRANSACTION_FEE);
        assert_eq!(relay, 200);
        assert_eq!(rest, 800);
        assert_eq!(relay + rest, FIXED_TRANSACTION_FEE);
    }

    #[test]
    fn dag_tx_subsidy_halves_on_confirmed_count() {
        assert_eq!(get_current_tx_subsidy(0, 0), INITIAL_TX_SUBSIDY);
        assert_eq!(get_current_tx_subsidy(1, 0), INITIAL_TX_SUBSIDY);
        assert_eq!(
            get_current_tx_subsidy(TX_HALVING_INTERVAL - 1, 0),
            INITIAL_TX_SUBSIDY
        );
        assert_eq!(
            get_current_tx_subsidy(TX_HALVING_INTERVAL, 0),
            INITIAL_TX_SUBSIDY >> 1
        );
        assert_eq!(get_current_tx_subsidy(TX_HALVING_INTERVAL, 0), 50_000);
        assert_eq!(get_current_tx_subsidy(0, HARD_CAP), 0);
        assert_eq!(get_current_tx_subsidy(64 * TX_HALVING_INTERVAL, 0), 0);
        assert_eq!(get_current_tx_subsidy(0, HARD_CAP - 1), 1);
        let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
        assert_eq!(dag_miner_share_of(pool), 80_800);
        assert_eq!(dag_relay_total_of(pool), 20_200);
        assert_eq!(dag_miner_share_of(pool) + dag_relay_total_of(pool), pool);
        assert_eq!(dag_miner_share_of(FIXED_TRANSACTION_FEE), 800);
        assert_eq!(dag_relay_total_of(FIXED_TRANSACTION_FEE), 200);
        assert_eq!(txs_remaining_until_halving(0), TX_HALVING_INTERVAL);
        assert_eq!(txs_remaining_until_halving(1), TX_HALVING_INTERVAL - 1);
        assert_eq!(
            txs_remaining_until_halving(TX_HALVING_INTERVAL),
            TX_HALVING_INTERVAL
        );
    }
}
