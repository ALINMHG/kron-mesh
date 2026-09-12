//! Dual Kademlia table: core validators vs edge miners.
//!
//! Eclipse defence:
//! * at most two contacts per IPv4 /24 in a bucket
//! * edge nodes never evict their last core anchors
//! * incoming flood from one prefix is ignored once the cap is hit

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use crate::p2p::error::NetworkError;
use crate::p2p::overlay::NodeOverlayId;
use crate::p2p::peer::{ipv4_octets, slash24, ConnectionState, Peer, PeerRole};
use crate::types::Address;

const BUCKETS: usize = 16;
const K: usize = 8;
const MAX_PER_SLASH24: usize = 2;
const MIN_CORE_ANCHORS: usize = 4;

#[derive(Debug)]
pub struct RoutingTable {
    local_id: Address,
    local_overlay: NodeOverlayId,
    local_role: PeerRole,
    core: Vec<VecDeque<Peer>>,
    edge: Vec<VecDeque<Peer>>,
}

impl RoutingTable {
    pub fn new(local_id: Address, local_role: PeerRole) -> Self {
        Self {
            local_id,
            local_overlay: NodeOverlayId::from_address(&local_id),
            local_role,
            core: vec![VecDeque::with_capacity(K); BUCKETS],
            edge: vec![VecDeque::with_capacity(K); BUCKETS],
        }
    }

    pub fn local_id(&self) -> Address {
        self.local_id
    }

    pub fn local_overlay(&self) -> NodeOverlayId {
        self.local_overlay
    }

    pub fn insert(&mut self, mut peer: Peer) -> Result<(), NetworkError> {
        if peer.id == self.local_id || peer.overlay_id == self.local_overlay {
            return Err(NetworkError::RoutingDenied);
        }
        self.remove_overlay(&peer.overlay_id);
        peer.last_seen = Instant::now();
        peer.state = ConnectionState::Live;
        let idx = bucket_index(&self.local_id, &peer.id);
        let core_n: usize = self.core.iter().map(|b| b.len()).sum();
        let table = match peer.role {
            PeerRole::CoreValidator => &mut self.core,
            PeerRole::EdgeMiner => &mut self.edge,
        };
        let bucket = &mut table[idx];

        if let Some(pos) = bucket.iter().position(|p| p.id == peer.id) {
            bucket.remove(pos);
            bucket.push_back(peer);
            return Ok(());
        }

        if let Some(ip) = ipv4_octets(peer.addr) {
            let net = slash24(ip);
            let same = bucket
                .iter()
                .filter(|p| ipv4_octets(p.addr).is_some_and(|o| slash24(o) == net))
                .count();
            if same >= MAX_PER_SLASH24 {
                return Err(NetworkError::RoutingDenied);
            }
        }

        if bucket.len() < K {
            bucket.push_back(peer);
            return Ok(());
        }

        // Evict dead/quarantined first; never evict cores below the anchor floor
        // when we are an edge miner (otherwise a Sybil cloud isolates the phone).
        if let Some(pos) = bucket.iter().position(|p| {
            matches!(p.state, ConnectionState::Dead | ConnectionState::Quarantined)
        }) {
            bucket.remove(pos);
            bucket.push_back(peer);
            return Ok(());
        }

        if self.local_role == PeerRole::EdgeMiner
            && peer.role == PeerRole::EdgeMiner
            && core_n < MIN_CORE_ANCHORS
        {
            return Err(NetworkError::RoutingDenied);
        }

        if peer.role == PeerRole::CoreValidator {
            if let Some(pos) = bucket.iter().position(|p| p.role == PeerRole::EdgeMiner) {
                bucket.remove(pos);
                bucket.push_back(peer);
                return Ok(());
            }
        }

        Err(NetworkError::RoutingDenied)
    }

    pub fn core_count(&self) -> usize {
        self.core.iter().map(|b| b.len()).sum()
    }

    pub fn edge_count(&self) -> usize {
        self.edge.iter().map(|b| b.len()).sum()
    }

    pub fn live_peers(&self) -> Vec<Peer> {
        self.core
            .iter()
            .chain(self.edge.iter())
            .flatten()
            .filter(|p| p.state == ConnectionState::Live)
            .cloned()
            .collect()
    }

    /// k closest contacts. Edge queriers always receive core anchors first so
    /// they cannot be trapped in an IoT-only partition.
    pub fn closest(&self, target: &Address, k: usize) -> Vec<Peer> {
        let mut all = self.live_peers();
        all.sort_by_key(|p| xor_distance(&p.id, target));
        if self.local_role == PeerRole::EdgeMiner {
            let mut anchors: Vec<Peer> = self
                .core
                .iter()
                .flatten()
                .filter(|p| p.state == ConnectionState::Live)
                .cloned()
                .collect();
            anchors.sort_by_key(|p| xor_distance(&p.id, target));
            anchors.truncate(MIN_CORE_ANCHORS);
            let mut out = anchors;
            for p in all {
                if out.iter().all(|q| q.id != p.id) {
                    out.push(p);
                }
                if out.len() >= k {
                    break;
                }
            }
            out.truncate(k);
            out
        } else {
            all.truncate(k);
            all
        }
    }

    /// Fan-out set for gossip. Phones talk to a few cores + 1–2 edge neighbours.
    pub fn gossip_targets(&self, local_role: PeerRole) -> Vec<Peer> {
        match local_role {
            PeerRole::EdgeMiner => {
                let mut cores: Vec<_> = self
                    .core
                    .iter()
                    .flatten()
                    .filter(|p| p.state == ConnectionState::Live)
                    .cloned()
                    .collect();
                cores.truncate(3);
                let mut edges: Vec<_> = self
                    .edge
                    .iter()
                    .flatten()
                    .filter(|p| p.state == ConnectionState::Live)
                    .cloned()
                    .collect();
                edges.truncate(2);
                cores.extend(edges);
                cores
            }
            PeerRole::CoreValidator => {
                let mut v = self.live_peers();
                v.truncate(8);
                v
            }
        }
    }

    pub fn contains(&self, id: &Address) -> bool {
        self.live_peers().iter().any(|p| p.id == *id)
    }

    pub fn contains_overlay(&self, id: &NodeOverlayId) -> bool {
        *id == self.local_overlay
            || self.live_peers().iter().any(|p| p.overlay_id == *id)
    }

    pub fn lookup_addr(&self, id: &Address) -> Option<SocketAddr> {
        self.live_peers()
            .into_iter()
            .find(|p| p.id == *id)
            .map(|p| p.addr)
    }

    /// Socket is transport only. Identity is the Mesh ID.
    pub fn lookup_overlay(&self, id: &NodeOverlayId) -> Option<SocketAddr> {
        self.live_peers()
            .into_iter()
            .find(|p| p.overlay_id == *id)
            .map(|p| p.addr)
    }

    fn remove_overlay(&mut self, id: &NodeOverlayId) {
        for table in [&mut self.core, &mut self.edge] {
            for bucket in table.iter_mut() {
                if let Some(pos) = bucket.iter().position(|p| p.overlay_id == *id) {
                    bucket.remove(pos);
                    return;
                }
            }
        }
    }
}

fn bucket_index(local: &Address, remote: &Address) -> usize {
    let xor = xor_distance(local, remote);
    let mut bits = 0u32;
    for b in xor {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    if bits >= 256 {
        return 0;
    }
    ((255 - bits) as usize) / (256 / BUCKETS)
}

fn xor_distance(a: &Address, b: &Address) -> Address {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::lattice::LatticeKeyPair;
    use crate::anti_bot::profile::DeviceClass;
    use crate::p2p::peer::PeerRole;
    use rand::SeedableRng;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer_at(rng_seed: u64, ip: [u8; 4], role: PeerRole) -> Peer {
        let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
        let keys = LatticeKeyPair::generate(&mut rng);
        Peer {
            id: keys.public.address(),
            overlay_id: crate::p2p::overlay::NodeOverlayId::from_pubkey(&keys.public),
            public_key: keys.public,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), 9000),
            role,
            class: DeviceClass::IotSensor,
            reputation: 100,
            state: ConnectionState::Live,
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn slash24_cannot_eclipse_a_bucket() {
        let local = [0xAAu8; 32];
        let mut table = RoutingTable::new(local, PeerRole::EdgeMiner);
        let mut ok = 0;
        for i in 0..12u8 {
            let p = peer_at(10 + i as u64, [86, 10, 10, i + 1], PeerRole::EdgeMiner);
            if table.insert(p).is_ok() {
                ok += 1;
            }
        }
        assert!(ok <= MAX_PER_SLASH24);
    }

    #[test]
    fn edge_keeps_core_anchors() {
        let local = [0x11u8; 32];
        let mut table = RoutingTable::new(local, PeerRole::EdgeMiner);
        for i in 0..4u8 {
            let p = peer_at(
                100 + i as u64,
                [86, 1, i, 1],
                PeerRole::CoreValidator,
            );
            table.insert(p).unwrap();
        }
        assert_eq!(table.core_count(), 4);
        let closest = table.closest(&[0xFFu8; 32], 8);
        assert!(closest.iter().any(|p| p.role == PeerRole::CoreValidator));
    }

    #[test]
    fn lookup_is_by_overlay_id_not_lan_ip() {
        let local = [0x22u8; 32];
        let mut table = RoutingTable::new(local, PeerRole::EdgeMiner);
        let p = peer_at(3, [192, 168, 1, 50], PeerRole::EdgeMiner);
        let overlay = p.overlay_id;
        table.insert(p).unwrap();
        assert!(table.contains_overlay(&overlay));
        assert_eq!(
            table.lookup_overlay(&overlay).map(|a| a.ip().to_string()),
            Some("192.168.1.50".into())
        );
        let moved = peer_at(3, [10, 0, 0, 9], PeerRole::EdgeMiner);
        assert_eq!(moved.overlay_id, overlay);
        table.insert(moved).unwrap();
        assert_eq!(table.edge_count(), 1);
        assert_eq!(
            table.lookup_overlay(&overlay).map(|a| a.ip().to_string()),
            Some("10.0.0.9".into())
        );
    }
}
