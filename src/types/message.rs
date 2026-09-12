//! Mesh gossip payloads. No ACS / RBC / ABA / commit certificates.

use crate::dag::DagTransaction;

/// Vertex gossiped between phones and the PC gateway.
#[derive(Clone, Debug)]
pub enum MeshMessage {
    Vertex(DagTransaction),
}

impl MeshMessage {
    pub fn vertex_id(&self) -> crate::dag::TxHash {
        match self {
            MeshMessage::Vertex(tx) => tx.id,
        }
    }
}
