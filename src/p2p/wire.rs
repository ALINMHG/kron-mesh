//! Encoding of mesh gossip messages (DAG vertices).

use crate::crypto::hash::sha256;
use crate::dag::DagTransaction;
use crate::p2p::error::NetworkError;
use crate::p2p::frame::{put_bytes, take_bytes};
use crate::types::message::MeshMessage;
use crate::types::Hash;

const TAG_VERTEX: u8 = 0;

pub fn encode_mesh(msg: &MeshMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        MeshMessage::Vertex(tx) => {
            out.push(TAG_VERTEX);
            put_bytes(&mut out, &tx.canonical_bytes());
        }
    }
    out
}

pub fn decode_mesh(bytes: &[u8]) -> Result<MeshMessage, NetworkError> {
    if bytes.is_empty() {
        return Err(NetworkError::BadFrame);
    }
    let tag = bytes[0];
    let mut off = 1;
    match tag {
        TAG_VERTEX => {
            let raw = take_bytes(bytes, &mut off)?;
            let tx = DagTransaction::from_canonical(&raw)?;
            Ok(MeshMessage::Vertex(tx))
        }
        _ => Err(NetworkError::BadFrame),
    }
}

pub fn message_id(msg: &MeshMessage) -> Hash {
    sha256(&encode_mesh(msg))
}

pub fn message_id_bytes(encoded: &[u8]) -> Hash {
    sha256(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::KronDAG;
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    #[test]
    fn vertex_roundtrip_and_id_stable() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        let mut dag = KronDAG::with_genesis();
        let a = generate_kron_wallet_from_rng(&mut rng);
        let b = generate_kron_wallet_from_rng(&mut rng);
        dag.credit_account(*a.address().as_bytes(), 1_000_000);
        let tx = dag
            .compose_and_sign_with_rng(&a, *b.address().as_bytes(), 3, &mut rng)
            .unwrap();
        let msg = MeshMessage::Vertex(tx);
        let bytes = encode_mesh(&msg);
        let back = decode_mesh(&bytes).unwrap();
        assert_eq!(message_id(&msg), message_id(&back));
        match back {
            MeshMessage::Vertex(t) => assert_eq!(t.amount, 3),
        }
    }
}
