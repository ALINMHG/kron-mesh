//! From-scratch P2P overlay (no libp2p): Kademlia-style routing, lattice
//! handshake, and Have/Need gossip of DAG vertices.

pub mod discovery;
pub mod error;
pub mod frame;
pub mod gossip;
pub mod handshake;
pub mod mesh;
pub mod noise;
pub mod node;
pub mod overlay;
pub mod peer;
pub mod routing;
pub mod wire;

pub use discovery::{
    beacon_port, decode_beacon, encode_beacon, format_hub_connect_error, spawn_hub_dial,
    spawn_lan_discovery, spawn_peer_link, DiscoveredPeer, DiscoveryConfig, LanBeacon,
    LanBeaconSocket,
};
pub use error::NetworkError;
pub use gossip::{accept_udp_inventory, GossipEngine, GossipInventory};
pub use handshake::{perform_secure_handshake, HandshakeConfig};
pub use mesh::{
    broadcast_wallet_tx, default_gateway_addr, mesh_sync_connect, serve_mesh_session, HubState,
    IsolatedDag, MeshGraph, MeshRole, MeshWireMessage, PROTOCOL_KRON_MESH,
};
pub use node::P2pNode;
pub use overlay::NodeOverlayId;
pub use peer::{Peer, PeerInfo, PeerRole};
pub use routing::RoutingTable;
pub use wire::{encode_mesh, message_id};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anti_bot::profile::DeviceClass;
    use crate::crypto::lattice::LatticeKeyPair;
    use crate::dag::KronDAG;
    use crate::kron::generate_kron_wallet_from_rng;
    use crate::types::message::MeshMessage;
    use rand::SeedableRng;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn lattice_handshake_over_localhost_tcp() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(77);
        let server_keys = LatticeKeyPair::generate(&mut rng);
        let client_keys = LatticeKeyPair::generate(&mut rng);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_hs = HandshakeConfig::honest(
            server_keys,
            PeerRole::CoreValidator,
            DeviceClass::PersonalComputer,
            false,
        );
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut session = crate::p2p::noise::NoiseSession::handshake(stream, false)?;
            perform_secure_handshake(&mut session, &server_hs)
        });
        thread::sleep(Duration::from_millis(30));
        let client = TcpStream::connect(addr).unwrap();
        let client_hs = HandshakeConfig::honest(
            client_keys,
            PeerRole::EdgeMiner,
            DeviceClass::LegacyMobile,
            true,
        );
        let mut session = crate::p2p::noise::NoiseSession::handshake(client, true).unwrap();
        let info = perform_secure_handshake(&mut session, &client_hs).unwrap();
        assert_eq!(info.peer.role, PeerRole::CoreValidator);
        assert!(info.score.is_strong());
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn have_need_gossips_vertex_between_two_nodes() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(88);
        let core = HandshakeConfig::honest(
            LatticeKeyPair::generate(&mut rng),
            PeerRole::CoreValidator,
            DeviceClass::PersonalComputer,
            false,
        );
        let edge = HandshakeConfig::honest(
            LatticeKeyPair::generate(&mut rng),
            PeerRole::EdgeMiner,
            DeviceClass::LegacyMobile,
            false,
        );
        let n1 = P2pNode::bind(core).unwrap();
        let n2 = P2pNode::bind(edge).unwrap();
        n2.connect(n1.addr).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert!(n1.peer_count() >= 1 || n2.peer_count() >= 1);

        let mut dag = KronDAG::with_genesis();
        let wallet = generate_kron_wallet_from_rng(&mut rng);
        let dest = generate_kron_wallet_from_rng(&mut rng);
        dag.credit_account(*wallet.address().as_bytes(), 1_000_000);
        let tx = dag
            .compose_and_sign_with_rng(&wallet, *dest.address().as_bytes(), 11, &mut rng)
            .unwrap();
        let id = n2.broadcast(MeshMessage::Vertex(tx));
        let mut seen = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(80));
            if n1.has(&id) {
                seen = true;
                break;
            }
        }
        assert!(seen, "gateway should fetch the DAG vertex by Have/Need");
        n1.shutdown();
        n2.shutdown();
    }
}
