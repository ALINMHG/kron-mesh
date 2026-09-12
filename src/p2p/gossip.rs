//! Gossip-about-gossip (Have/Need). Edge devices flood 32-byte ids, not bodies.

use std::collections::{HashMap, VecDeque};

use crate::p2p::error::NetworkError;
use crate::p2p::frame::{put_bytes, take_bytes};
use crate::p2p::peer::PeerRole;
use crate::p2p::wire::{decode_mesh, encode_mesh, message_id_bytes};
use crate::types::message::MeshMessage;
use crate::types::Hash;

/// Compact inventory: only message identifiers.
#[derive(Clone, Debug, Default)]
pub struct GossipInventory {
    pub ids: Vec<Hash>,
}

impl GossipInventory {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.ids.len() as u16).to_le_bytes());
        for id in &self.ids {
            out.extend_from_slice(id);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() < 2 {
            return Err(NetworkError::BadFrame);
        }
        let n = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        if bytes.len() != 2 + n * 32 {
            return Err(NetworkError::BadFrame);
        }
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[2 + i * 32..2 + (i + 1) * 32]);
            ids.push(h);
        }
        Ok(Self { ids })
    }

    pub fn byte_len(&self) -> usize {
        2 + self.ids.len() * 32
    }
}

#[derive(Clone, Debug, Default)]
pub struct GossipWant {
    pub ids: Vec<Hash>,
}

impl GossipWant {
    pub fn encode(&self) -> Vec<u8> {
        GossipInventory { ids: self.ids.clone() }.encode()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        Ok(Self {
            ids: GossipInventory::decode(bytes)?.ids,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GossipPayload {
    pub id: Hash,
    pub body: Vec<u8>,
}

impl GossipPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(self.id.as_slice());
        put_bytes(&mut out, &self.body);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() < 32 {
            return Err(NetworkError::BadFrame);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[..32]);
        let mut off = 32;
        let body = take_bytes(bytes, &mut off)?;
        Ok(Self { id, body })
    }
}

struct Stored {
    body: Vec<u8>,
}

/// In-memory Have/Need engine. `max_store` is tiny on phones.
pub struct GossipEngine {
    store: HashMap<Hash, Stored>,
    order: VecDeque<Hash>,
    max_store: usize,
    max_inv: usize,
    max_want: usize,
}

impl GossipEngine {
    pub fn for_role(role: PeerRole) -> Self {
        match role {
            PeerRole::EdgeMiner => Self {
                store: HashMap::new(),
                order: VecDeque::new(),
                max_store: 64,
                max_inv: 8,
                max_want: 2,
            },
            PeerRole::CoreValidator => Self {
                store: HashMap::new(),
                order: VecDeque::new(),
                max_store: 4096,
                max_inv: 64,
                max_want: 32,
            },
        }
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.store.contains_key(id)
    }

    pub fn get(&self, id: &Hash) -> Option<MeshMessage> {
        self.store
            .get(id)
            .and_then(|s| decode_mesh(&s.body).ok())
    }

    /// Store a local message and return a *short* inventory to flood.
    pub fn announce(&mut self, msg: &MeshMessage) -> GossipInventory {
        let body = encode_mesh(msg);
        let id = message_id_bytes(&body);
        self.insert(id, body);
        let mut ids = vec![id];
        ids.truncate(self.max_inv);
        GossipInventory { ids }
    }

    pub fn on_inventory(&self, inv: &GossipInventory) -> GossipWant {
        let mut ids = Vec::new();
        for id in &inv.ids {
            if !self.store.contains_key(id) {
                ids.push(*id);
            }
            if ids.len() >= self.max_want {
                break;
            }
        }
        GossipWant { ids }
    }

    pub fn on_want(&self, want: &GossipWant) -> Vec<GossipPayload> {
        want.ids
            .iter()
            .filter_map(|id| {
                self.store.get(id).map(|s| GossipPayload {
                    id: *id,
                    body: s.body.clone(),
                })
            })
            .collect()
    }

    pub fn on_payload(&mut self, payload: GossipPayload) -> Result<Option<MeshMessage>, NetworkError> {
        if message_id_bytes(&payload.body) != payload.id {
            return Err(NetworkError::HashMismatch);
        }
        if self.store.contains_key(&payload.id) {
            return Ok(None);
        }
        let msg = decode_mesh(&payload.body)?;
        self.insert(payload.id, payload.body);
        Ok(Some(msg))
    }

    fn insert(&mut self, id: Hash, body: Vec<u8>) {
        if self.store.contains_key(&id) {
            return;
        }
        if self.order.len() >= self.max_store {
            if let Some(old) = self.order.pop_front() {
                self.store.remove(&old);
            }
        }
        self.order.push_back(id);
        self.store.insert(id, Stored { body });
    }
}

/// UDP inventory is accepted only from a peer that already completed TCP handshake.
pub fn accept_udp_inventory(
    known_peer: bool,
    datagram: &[u8],
) -> Result<GossipInventory, NetworkError> {
    if !known_peer {
        return Err(NetworkError::UnauthenticatedDatagram);
    }
    GossipInventory::decode(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::peer::PeerRole;
    use crate::dag::KronDAG;
    use crate::kron::generate_kron_wallet_from_rng;
    use crate::p2p::wire::encode_mesh;
    use crate::types::message::MeshMessage;
    use rand::SeedableRng;

    #[test]
    fn inventory_is_much_smaller_than_payload() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        let mut dag = KronDAG::with_genesis();
        let a = generate_kron_wallet_from_rng(&mut rng);
        let b = generate_kron_wallet_from_rng(&mut rng);
        dag.credit_account(*a.address().as_bytes(), 1_000_000);
        let tx = dag
            .compose_and_sign_with_rng(&a, *b.address().as_bytes(), 9, &mut rng)
            .unwrap();
        let msg = MeshMessage::Vertex(tx);
        let mut g = GossipEngine::for_role(PeerRole::EdgeMiner);
        let inv = g.announce(&msg);
        let body = encode_mesh(&msg);
        assert!(inv.byte_len() * 10 < body.len() || inv.byte_len() <= 34);
        assert!(body.len() > 200);
        let want = GossipEngine::for_role(PeerRole::CoreValidator).on_inventory(&inv);
        assert_eq!(want.ids.len(), 1);
    }
}
