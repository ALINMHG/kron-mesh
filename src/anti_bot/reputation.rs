//! Dynamic IP / identity reputation and datacenter Sybil filtering.
//!
//! Proof of Adjacency: phones that claim the same /24, especially inside the
//! conceptual cloud prefix list, are treated as a farm. Residential / mobile
//! prefixes keep score. All decisions are functions of attested fields.

use std::collections::BTreeMap;

use crate::anti_bot::attestation::{is_datacenter_ipv4, miner_node_id, DeviceScore};
use crate::anti_bot::profile::DeviceClass;
use crate::types::{Address, NodeId};

const SUBNET_CAP: usize = 2;
const START_SCORE: i32 = 100;

#[derive(Clone, Debug)]
pub struct NodeReputation {
    pub miner: Address,
    pub node_id: NodeId,
    pub class: DeviceClass,
    pub score: i32,
    pub subnet: u32,
    pub last_authenticity: u16,
}

impl NodeReputation {
    fn new(miner: Address, class: DeviceClass, ipv4: [u8; 4]) -> Self {
        Self {
            miner,
            node_id: miner_node_id(&miner),
            class,
            score: START_SCORE,
            subnet: ipv4_to_slash24(ipv4),
            last_authenticity: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReputationLedger {
    nodes: BTreeMap<Address, NodeReputation>,
}

impl ReputationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, miner: &Address) -> Option<&NodeReputation> {
        self.nodes.get(miner)
    }

    pub fn score_of(&self, miner: &Address) -> i32 {
        self.nodes.get(miner).map(|n| n.score).unwrap_or(START_SCORE)
    }

    pub fn apply_score(
        &mut self,
        miner: Address,
        class: DeviceClass,
        ipv4: [u8; 4],
        score: &DeviceScore,
    ) {
        let entry = self
            .nodes
            .entry(miner)
            .or_insert_with(|| NodeReputation::new(miner, class, ipv4));
        entry.class = class;
        entry.subnet = ipv4_to_slash24(ipv4);
        entry.last_authenticity = score.authenticity;
        let delta = (score.authenticity as i32 / 50) + (score.residential as i32 / 80) - 10;
        entry.score = (entry.score + delta).clamp(0, 1_000);
    }

    pub fn penalize(&mut self, miner: Address, class: DeviceClass, ipv4: [u8; 4], hard: bool) {
        let entry = self
            .nodes
            .entry(miner)
            .or_insert_with(|| NodeReputation::new(miner, class, ipv4));
        entry.score = if hard {
            0
        } else {
            (entry.score / 2).saturating_sub(25)
        };
    }

    /// Drop datacenter farms and cap each /24 to `SUBNET_CAP` identities.
    pub fn filter_sybil_subnet(&self, candidates: &[(Address, [u8; 4])]) -> Vec<Address> {
        let mut by_net: BTreeMap<u32, Vec<Address>> = BTreeMap::new();
        for (addr, ip) in candidates {
            if is_datacenter_ipv4(*ip) {
                continue;
            }
            by_net.entry(ipv4_to_slash24(*ip)).or_default().push(*addr);
        }
        let mut kept = Vec::new();
        for (_net, mut group) in by_net {
            if group.len() > SUBNET_CAP {
                group.sort_by_key(|a| (std::cmp::Reverse(self.score_of(a)), *a));
                group.truncate(SUBNET_CAP);
            }
            kept.extend(group);
        }
        kept.sort();
        kept
    }
}

pub fn ipv4_to_slash24(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes([ip[0], ip[1], ip[2], 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anti_bot::attestation::datacenter_ipv4;

    #[test]
    fn datacenter_identities_are_stripped() {
        let ledger = ReputationLedger::new();
        let miner = [1u8; 32];
        let kept = ledger.filter_sybil_subnet(&[(miner, datacenter_ipv4(&miner))]);
        assert!(kept.is_empty());
    }

    #[test]
    fn slash24_sybil_cap() {
        let ledger = ReputationLedger::new();
        let a = ([1u8; 32], [86, 10, 10, 1]);
        let b = ([2u8; 32], [86, 10, 10, 2]);
        let c = ([3u8; 32], [86, 10, 10, 3]);
        let kept = ledger.filter_sybil_subnet(&[a, b, c]);
        assert_eq!(kept.len(), 2);
    }
}
