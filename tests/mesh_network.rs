//! Two isolated KronDAG instances exchange vertices over loopback bytes only.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use new_blockchain::broadcast_wallet_tx;
use new_blockchain::dag::{DagTransaction, KronDAG};
use new_blockchain::explorer::ExplorerApi;
use new_blockchain::generate_kron_wallet_from_rng;
use new_blockchain::p2p::mesh::{
    bind_mesh_listener, mesh_sync_connect, IsolatedDag, MeshGraph, MeshRole, HubState,
};
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
