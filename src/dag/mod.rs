//! KRON Mobile Mesh DAG engine (`kron_dag_engine`).
//!
//! Unlike a linear chain, phones attach transactions that each cryptographically
//! approve **two parents**. This module has no traditional server-produced blocks.
//!
//! # Signature scheme
//! DAG vertices are signed with **NIST ML-DSA-44** (FIPS 204 / Dilithium2) through
//! [`crate::crypto::lattice::LatticeSecretKey::sign`] and verified with
//! [`crate::crypto::lattice::LatticePublicKey::verify`]. That is the same lattice
//! scheme the live wallet uses today (`sign_transaction_natively`). Educational
//! LWE is never used for DAG payloads.
//!
//! # Genesis
//! IOTA-style: the genesis vertex has dummy parents [`NULL_PARENT`] /
//! [`NULL_PARENT`] (all-zero hashes). It is not a user transfer (fee 0). Every
//! later vertex must name two parents that already exist in the DAG.

mod engine;
mod error;
mod minting;
mod reconciliation;
mod sync;
mod tx;
mod wallet_relay;

pub use engine::{AttachingDevice, KronDAG};
pub use error::DagError;
pub use minting::{
    apply_dag_minting_as_miner, apply_dag_minting_from_sender, apply_dag_minting_natively,
};
pub use reconciliation::{compute_dag_diff, SyncInventory};
pub use sync::{
    exchange_and_merge, mesh_handshake, mesh_relay_split, relay_share, MeshPhone, MeshSession,
    MeshSyncEngine, NodeId, OfflineLink, RelayLedger, SyncError, HANDSHAKE_RETRIES,
};
pub use tx::{
    relay_proof_message, DagTransaction, RelayNodeId, RelayProof, GENESIS_SEED, NULL_PARENT, TxHash,
};
pub use wallet_relay::{
    relay_intercept_and_sign, relay_wallet_id, start_wallet_relay_mode, wallet_relay_step,
    MeshInterface, RelayMempool, WalletRelaySession, RELAY_DUTY_SLEEP_SECS_DEFAULT,
    RELAY_DUTY_SLEEP_SECS_MAX, RELAY_DUTY_SLEEP_SECS_MIN, RELAY_MEMPOOL_CAP,
};

pub use crate::economics::{
    get_current_tx_subsidy, relay_share_of, INITIAL_TX_SUBSIDY, RELAY_SHARE_PERCENT,
    TX_HALVING_INTERVAL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::{FIXED_TRANSACTION_FEE, INITIAL_TX_SUBSIDY};
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    const PHONE_CREDIT: u64 = 1_000_000;
    const SEND_AMOUNT: u64 = 10_000;

    fn five_phones(rng: &mut rand::rngs::StdRng) -> Vec<crate::kron::KronKeypair> {
        (0..5).map(|_| generate_kron_wallet_from_rng(rng)).collect()
    }

    #[test]
    fn test_kron_dag_mesh_flow() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4B52_4F4E_4441_47);
        let mut dag = KronDAG::with_genesis();
        let genesis = dag.genesis_id();
        let genesis_weight_before = dag.cumulative_weight(&genesis);
        let vertices_before = dag.vertex_count();
        assert_eq!(vertices_before, 1);
        assert_eq!(genesis_weight_before, 1);
        assert!(dag.tips_are_consistent());

        let phones = five_phones(&mut rng);
        for phone in &phones {
            dag.credit_account(*phone.address().as_bytes(), PHONE_CREDIT);
            assert_eq!(dag.balance(phone.address().as_bytes()), PHONE_CREDIT);
        }

        let mut attached = Vec::new();
        for (i, phone) in phones.iter().enumerate() {
            let dest = *phones[(i + 1) % phones.len()].address().as_bytes();
            let tx = dag
                .compose_and_sign_with_rng(phone, dest, SEND_AMOUNT, &mut rng)
                .expect("phone compose+sign");
            assert!(tx.sender_kron1.starts_with("kron1"));
            assert_eq!(tx.fee, FIXED_TRANSACTION_FEE);
            assert_ne!(tx.parent_1, NULL_PARENT);
            dag.attach_and_verify_tx(tx.clone()).expect("attach");
            attached.push(tx);
        }

        assert_eq!(dag.vertex_count(), vertices_before + 5);
        assert!(dag.vertex_count() > vertices_before);
        assert!(dag.tips_are_consistent());
        for tip in dag.tips() {
            assert!(!dag.has_children(tip), "tip {tip:?} must have no children");
        }

        for (i, tx) in attached.iter().enumerate() {
            let closure = dag.parent_closure(tx.id);
            assert!(
                closure.contains(&genesis),
                "phone {i} parent closure must reach genesis"
            );
            assert!(dag.get(&tx.parent_1).is_some());
            assert!(dag.get(&tx.parent_2).is_some());
            if i > 0 {
                let earlier = &attached[..i];
                let refs_earlier = earlier.iter().any(|prev| {
                    tx.parent_1 == prev.id
                        || tx.parent_2 == prev.id
                        || closure.contains(&prev.id)
                });
                assert!(
                    refs_earlier || closure.contains(&genesis),
                    "later tx must reference earlier history via parents"
                );
            }
        }

        let genesis_weight_after = dag.cumulative_weight(&genesis);
        assert!(
            genesis_weight_after > genesis_weight_before,
            "genesis cumulative weight {genesis_weight_after} must exceed {genesis_weight_before}"
        );

        for phone in &phones {
            assert_eq!(dag.next_nonce(phone.address().as_bytes()), 1);
            // Ring: each phone sends and receives `SEND_AMOUNT`. The fee is
            // redistributed with the tx subsidy to the confirming miner phone
            // (no relays on local attach), so the ledger rises by the subsidy.
            assert_eq!(
                dag.balance(phone.address().as_bytes()),
                PHONE_CREDIT + INITIAL_TX_SUBSIDY
            );
        }
        assert_eq!(dag.dag_tx_count, 5);
        assert_eq!(dag.current_supply, 5 * INITIAL_TX_SUBSIDY);
    }

    #[test]
    fn attach_rejects_unknown_parent_and_double_spend() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut dag = KronDAG::with_genesis();
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);

        let mut orphan = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), SEND_AMOUNT, &mut rng)
            .unwrap();
        orphan.parent_1 = [0x11; 32];
        orphan.refresh_id();
        assert!(matches!(
            dag.attach_and_verify_tx(orphan),
            Err(DagError::UnknownParent(_))
        ));

        let tx = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), SEND_AMOUNT, &mut rng)
            .unwrap();
        let tx_id = tx.id;
        dag.attach_and_verify_tx(tx.clone()).unwrap();
        assert_eq!(
            dag.attach_and_verify_tx(tx),
            Err(DagError::DuplicateTx(tx_id))
        );
        // Re-check double-spend via a second spend at nonce 0 (already consumed).
        let (p1, p2) = dag.select_parents_with_rng(&mut rng);
        let replay = DagTransaction::user_transfer(
            p1,
            p2,
            &alice,
            *bob.address().as_bytes(),
            SEND_AMOUNT,
            0,
        )
        .unwrap();
        assert!(matches!(
            dag.attach_and_verify_tx(replay),
            Err(DagError::DoubleSpend { nonce: 0 })
        ));
    }

    #[test]
    fn attach_rejects_bad_signature_and_low_balance() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let mut dag = KronDAG::with_genesis();
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        dag.credit_account(*alice.address().as_bytes(), 500);

        let poor = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), SEND_AMOUNT, &mut rng)
            .unwrap();
        assert_eq!(
            dag.attach_and_verify_tx(poor),
            Err(DagError::InsufficientBalance)
        );

        dag.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        let mut tx = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), SEND_AMOUNT, &mut rng)
            .unwrap();
        tx.amount = SEND_AMOUNT + 1;
        tx.refresh_id();
        assert_eq!(
            dag.attach_and_verify_tx(tx),
            Err(DagError::InvalidSignature)
        );
    }

    /// §47 — two isolated phone DAGs meet over a simulated BLE hop.
    /// Phone A walks to Phone B and is the mule (`Mesh_Relay_Node`).
    #[test]
    fn test_kron_mountain_offline_sync() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D4F_554E_5441_49);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);

        let mut shared = KronDAG::with_genesis();
        let genesis = shared.genesis_id();
        shared.credit_account(*alice.address().as_bytes(), PHONE_CREDIT);
        shared.credit_account(*bob.address().as_bytes(), PHONE_CREDIT);

        let mut dag_a = shared.clone();
        let mut dag_b = shared;
        assert_eq!(dag_a.genesis_id(), dag_b.genesis_id());
        assert_eq!(dag_a.vertex_set(), dag_b.vertex_set());

        let tx_a = dag_a
            .compose_and_sign_with_rng(
                &alice,
                *bob.address().as_bytes(),
                SEND_AMOUNT,
                &mut rng,
            )
            .expect("A compose");
        dag_a.attach_and_verify_tx(tx_a.clone()).expect("A attach");

        let tx_b = dag_b
            .compose_and_sign_with_rng(
                &bob,
                *alice.address().as_bytes(),
                SEND_AMOUNT,
                &mut rng,
            )
            .expect("B compose");
        dag_b.attach_and_verify_tx(tx_b.clone()).expect("B attach");

        assert!(!dag_a.contains(&tx_b.id));
        assert!(!dag_b.contains(&tx_a.id));
        assert_ne!(tx_a.id, tx_b.id);

        let phone_a = crate::dag::MeshPhone::from_wallet(&alice);
        let phone_b = crate::dag::MeshPhone::from_wallet(&bob);
        let session = crate::dag::OfflineLink::new()
            .mesh_handshake(&phone_a, &phone_b)
            .expect("lattice anti-bot handshake");
        assert_eq!(session.phone_a, phone_a.id());
        assert_eq!(session.phone_b, phone_b.id());

        // A walked to B: A is Mesh_Relay_Node for every vertex that crossed the air.
        let mule = phone_a.id();

        let inv_a = crate::dag::SyncInventory::from_dag(&dag_a, phone_a.id());
        let (need_b, have_b) = crate::dag::compute_dag_diff(&dag_b, &inv_a);
        assert!(need_b.contains(&tx_a.id), "B must Need A's local tx");
        assert!(!need_b.contains(&genesis), "must not Need shared genesis");
        assert!(have_b.contains(&tx_b.id), "B should Have its isolated tx");
        assert!(!have_b.contains(&genesis));

        let inv_b = crate::dag::SyncInventory::from_dag(&dag_b, phone_b.id());
        let (need_a, have_a) = crate::dag::compute_dag_diff(&dag_a, &inv_b);
        assert!(need_a.contains(&tx_b.id));
        assert!(have_a.contains(&tx_a.id));

        let bodies_for_b = dag_a.transactions_for(&need_b);
        let bodies_for_a = dag_b.transactions_for(&need_a);
        assert_eq!(
            dag_b.merge_offline_graphs(bodies_for_b, mule).unwrap(),
            1
        );
        assert_eq!(
            dag_a.merge_offline_graphs(bodies_for_a, mule).unwrap(),
            1
        );

        assert_eq!(dag_a.vertex_set(), dag_b.vertex_set());
        assert!(dag_a.contains(&tx_a.id) && dag_a.contains(&tx_b.id));
        assert!(dag_b.contains(&tx_a.id) && dag_b.contains(&tx_b.id));
        assert!(
            dag_a.get(&tx_a.id).is_some() && dag_a.get(&tx_b.id).is_some(),
            "parallel offline branches must both remain (no linear fork-choice)"
        );
        assert!(dag_a.tips().contains(&tx_a.id) && dag_a.tips().contains(&tx_b.id));
        assert!(dag_b.tips().contains(&tx_a.id) && dag_b.tips().contains(&tx_b.id));

        assert_eq!(dag_b.relay_node(&tx_a.id), Some(mule));
        assert_eq!(dag_a.relay_node(&tx_b.id), Some(mule));
        let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
        let relay_cut = crate::economics::dag_relay_total_of(pool);
        assert_eq!(relay_cut, 20_200);
        assert_eq!(dag_b.relay_credit(&mule), relay_cut);
        assert_eq!(dag_a.relay_credit(&mule), relay_cut);
        assert_eq!(crate::economics::RELAY_SHARE_PERCENT, 20);
    }
}
