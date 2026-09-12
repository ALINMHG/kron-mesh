//! Demo DAG used so the explorer UI is not blank before the first live vertex.

use crate::dag::KronDAG;
use crate::explorer::api::ExplorerApi;
use crate::kron::generate_kron_wallet_from_rng;
use rand::SeedableRng;

/// Deterministic demo phones (seed `KRON`) so the README can name the addresses.
pub fn seed_demo_if_empty(api: &mut ExplorerApi) -> bool {
    let stats = api.get_network_stats();
    if stats.dag_tx_count > 0 || stats.vertex_count > 1 {
        return false;
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4B52_4F4E);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*alice.address().as_bytes(), 1_000_000);
    let tx = match dag.compose_and_sign_with_rng(
        &alice,
        *bob.address().as_bytes(),
        50_000,
        &mut rng,
    ) {
        Ok(tx) => tx,
        Err(_) => return false,
    };
    if dag.attach_and_verify_tx(tx).is_err() {
        return false;
    }
    api.sync_from_dag(&dag);
    true
}
