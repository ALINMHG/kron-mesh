//! Two isolated KronDAG instances exchange vertices over loopback bytes only.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::broadcast_wallet_tx;
use new_blockchain::crypto::lattice::LatticeKeyPair;
use new_blockchain::dag::{DagTransaction, KronDAG};
use new_blockchain::explorer::ExplorerApi;
use new_blockchain::generate_kron_wallet_from_rng;
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::mesh::{
    bind_mesh_listener, mesh_sync_connect, IsolatedDag, MeshGraph, MeshRole, HubState,
};
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::P2pNode;
use rand::SeedableRng;

#[test]
fn two_isolated_dags_sync_over_loopback_bytes() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5749_5245);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);

    let mut dag_a = KronDAG::with_genesis();
    dag_a.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx_a = dag_a
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 4_000, &mut rng)
        .unwrap();
    dag_a.attach_and_verify_tx(tx_a.clone()).unwrap();

    let mut dag_b = KronDAG::with_genesis();
    dag_b.credit_account(*bob.address().as_bytes(), 1_000_000);
    let tx_b = dag_b
        .compose_and_sign_with_rng(&bob, *alice.address().as_bytes(), 3_000, &mut rng)
        .unwrap();
    dag_b.attach_and_verify_tx(tx_b.clone()).unwrap();

    assert_ne!(dag_a.vertex_set(), dag_b.vertex_set());

    let graph_a: Arc<dyn MeshGraph> = Arc::new(IsolatedDag::new(dag_a));
    let graph_b: Arc<dyn MeshGraph> = Arc::new(IsolatedDag::new(dag_b));
    let (addr, handle) = bind_mesh_listener(graph_b.clone()).unwrap();
    mesh_sync_connect(addr, graph_a.clone(), MeshRole::Test).unwrap();
    handle.join().unwrap();

    assert_eq!(graph_a.vertex_set(), graph_b.vertex_set());
    assert!(graph_a.contains(&tx_a.id) && graph_a.contains(&tx_b.id));
    assert!(graph_b.contains(&tx_a.id) && graph_b.contains(&tx_b.id));
}

#[test]
fn wallet_broadcast_appears_on_hub_and_explorer() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5741_4C54);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);

    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 8_000, &mut rng)
        .unwrap();

    let hub = HubState::new(KronDAG::with_genesis());
    {
        let mut locked = hub.lock_dag();
        locked.credit_account(*alice.address().as_bytes(), 1_000_000);
    }
    let graph: Arc<dyn MeshGraph> = hub.clone();
    let (addr, handle) = bind_mesh_listener(graph).unwrap();
    thread::sleep(Duration::from_millis(30));
    broadcast_wallet_tx(addr, &tx).expect("wallet KRMS submit");
    handle.join().unwrap();

    assert!(hub.contains(&tx.id));
    let mut api = ExplorerApi::new();
    api.sync_from_dag(&hub.lock_dag());
    let indexed = api.get_transaction_by_hash(tx.id).expect("explorer /api/tx");
    assert_eq!(indexed.amount, 8_000);
    assert_eq!(indexed.from, tx.sender_kron1);
}

#[test]
fn hub_listen_accepts_inbound_mesh_without_follow() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4855_4231);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let mut phone_dag = KronDAG::with_genesis();
    phone_dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = phone_dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 2_000, &mut rng)
        .unwrap();
    phone_dag.attach_and_verify_tx(tx.clone()).unwrap();

    let hs = HandshakeConfig::honest(
        LatticeKeyPair::generate(&mut rng),
        PeerRole::CoreValidator,
        DeviceClass::PersonalComputer,
        false,
    );
    let hub_node = P2pNode::bind(hs).unwrap();
    // Same protocol genesis on both sides (VPS hub never --follow).
    let hub = HubState::new(KronDAG::with_genesis());
    hub_node.attach_graph(hub.clone());
    thread::sleep(Duration::from_millis(40));

    let phone = HubState::new(phone_dag);
    mesh_sync_connect(hub_node.addr, phone.clone(), MeshRole::Hub)
        .expect("phone kron-mesh/1 must be accepted by a listening hub");
    assert!(
        hub.contains(&tx.id),
        "hub must merge the inbound phone vertex"
    );
    hub_node.shutdown();
}

#[test]
fn follow_mesh_sync_through_shared_p2p_port() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4630_4C4C);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 4_000, &mut rng)
        .unwrap();
    dag.attach_and_verify_tx(tx.clone()).unwrap();

    let hs = HandshakeConfig::honest(
        LatticeKeyPair::generate(&mut rng),
        PeerRole::EdgeMiner,
        DeviceClass::LegacyMobile,
        false,
    );
    let node = P2pNode::bind(hs).unwrap();
    let hub = HubState::new(dag);
    node.attach_graph(hub.clone());
    thread::sleep(Duration::from_millis(40));

    let viewer = HubState::new(KronDAG::with_genesis());
    mesh_sync_connect(node.addr, viewer.clone(), MeshRole::Hub)
        .expect("PC --follow must sync over the phone listen port");
    assert!(viewer.contains(&tx.id), "viewer must receive the phone vertex");
    node.shutdown();
}

#[test]
fn unauthenticated_vertex_inject_is_rejected() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x554E_4155);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = dag
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 1_000, &mut rng)
        .unwrap();

    let hs = HandshakeConfig::honest(
        LatticeKeyPair::generate(&mut rng),
        PeerRole::CoreValidator,
        DeviceClass::PersonalComputer,
        false,
    );
    let hub_node = P2pNode::bind(hs).unwrap();
    let hub = HubState::new(KronDAG::with_genesis());
    {
        let mut locked = hub.lock_dag();
        locked.credit_account(*alice.address().as_bytes(), 1_000_000);
    }
    hub_node.attach_graph(hub.clone());
    thread::sleep(Duration::from_millis(40));

    let mut raw = std::net::TcpStream::connect_timeout(&hub_node.addr, Duration::from_secs(2))
        .expect("tcp");
    let _ = new_blockchain::p2p::frame::configure_socket(&mut raw);
    let body = tx.canonical_bytes();
    new_blockchain::p2p::mesh::write_mesh_frame(&mut raw, new_blockchain::p2p::mesh::MK_DAG_TX, &body)
        .ok();
    thread::sleep(Duration::from_millis(80));
    assert!(
        !hub.contains(&tx.id),
        "cleartext KRMS vertex must not be ingested"
    );
    hub_node.shutdown();
}

#[test]
fn signed_tx_roundtrip_is_dag_transaction_not_shared_map() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let a = generate_kron_wallet_from_rng(&mut rng);
    let b = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*a.address().as_bytes(), 50_000);
    let tx = dag
        .compose_and_sign_with_rng(&a, *b.address().as_bytes(), 1_000, &mut rng)
        .unwrap();
    let bytes = tx.canonical_bytes();
    let back = DagTransaction::from_canonical(&bytes).unwrap();
    assert_eq!(back.id, tx.id);
}
