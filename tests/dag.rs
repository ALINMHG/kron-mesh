//! Integration coverage for the KRON Mobile Mesh DAG engine.

use new_blockchain::dag::{
    apply_dag_minting_as_miner, compute_dag_diff, DagError, KronDAG, MeshInterface, MeshPhone,
    OfflineLink, SyncError, SyncInventory, NULL_PARENT,
};
use new_blockchain::economics::{
    dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, relay_share_of,
    FIXED_TRANSACTION_FEE, HARD_CAP, INITIAL_TX_SUBSIDY, RELAY_SHARE_PERCENT,
};
use new_blockchain::generate_kron_wallet_from_rng;
use new_blockchain::kron::{start_wallet_relay_service, KronWallet};
use new_blockchain::{
    enforce_observation, enforce_real_mobile, HostArch, HostObservation, ShieldError,
};
use rand::SeedableRng;

#[test]
fn test_kron_dag_mesh_flow() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D45_5348_4441_47);
    let mut dag = KronDAG::with_genesis();
    let genesis = dag.genesis_id();
    let weight_before = dag.cumulative_weight(&genesis);
    let n_before = dag.vertex_count();

    let phones: Vec<_> = (0..5)
        .map(|_| generate_kron_wallet_from_rng(&mut rng))
        .collect();
    for phone in &phones {
        dag.credit_account(*phone.address().as_bytes(), 1_000_000);
    }

    let mut ids = Vec::new();
    for (i, phone) in phones.iter().enumerate() {
        let dest = *phones[(i + 1) % 5].address().as_bytes();
        let tx = dag
            .compose_and_sign_with_rng(phone, dest, 10_000, &mut rng)
            .expect("compose");
        assert!(tx.sender_kron1.starts_with("kron1"));
        assert_eq!(tx.fee, FIXED_TRANSACTION_FEE);
        assert_ne!(tx.parent_1, NULL_PARENT);
        dag.attach_and_verify_tx(tx.clone()).expect("attach");
        ids.push(tx.id);
    }

    assert_eq!(dag.vertex_count(), n_before + 5);
    assert!(dag.tips_are_consistent());
    for tip in dag.tips() {
        assert!(!dag.has_children(tip));
    }
    for id in &ids {
        let closure = dag.parent_closure(*id);
        assert!(closure.contains(&genesis));
    }
    assert!(dag.cumulative_weight(&genesis) > weight_before);
}

#[test]
fn mesh_rejects_conflicting_nonce() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    let mut dag = KronDAG::with_genesis();
    let a = generate_kron_wallet_from_rng(&mut rng);
    let b = generate_kron_wallet_from_rng(&mut rng);
    dag.credit_account(*a.address().as_bytes(), 1_000_000);
    let first = dag
        .compose_and_sign_with_rng(&a, *b.address().as_bytes(), 1_000, &mut rng)
        .unwrap();
    dag.attach_and_verify_tx(first).unwrap();
    let (p1, p2) = dag.select_parents_with_rng(&mut rng);
    let replay = new_blockchain::dag::DagTransaction::user_transfer(
        p1,
        p2,
        &a,
        *b.address().as_bytes(),
        1_000,
        0,
    )
    .unwrap();
    assert!(matches!(
        dag.attach_and_verify_tx(replay),
        Err(DagError::DoubleSpend { nonce: 0 })
    ));
}

/// §47 `test_kron_mountain_offline_sync` — isolated islands, BLE meetup, 20% mule.
#[test]
fn test_kron_mountain_offline_sync() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D54_4E5F_4441_47);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);

    let mut shared = KronDAG::with_genesis();
    let genesis = shared.genesis_id();
    shared.credit_account(*alice.address().as_bytes(), 1_000_000);
    shared.credit_account(*bob.address().as_bytes(), 1_000_000);

    let mut dag_a = shared.clone();
    let mut dag_b = shared;
    assert_eq!(dag_a.genesis_id(), genesis);
    assert_eq!(dag_b.genesis_id(), genesis);

    let tx_a = dag_a
        .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 10_000, &mut rng)
        .unwrap();
    dag_a.attach_and_verify_tx(tx_a.clone()).unwrap();

    let tx_b = dag_b
        .compose_and_sign_with_rng(&bob, *alice.address().as_bytes(), 10_000, &mut rng)
        .unwrap();
    dag_b.attach_and_verify_tx(tx_b.clone()).unwrap();

    let phone_a = MeshPhone::from_wallet(&alice);
    let phone_b = MeshPhone::from_wallet(&bob);
    OfflineLink::new()
        .mesh_handshake(&phone_a, &phone_b)
        .expect("anti-bot lattice handshake");
    let mule = phone_a.id();

    let inv_a = SyncInventory::from_dag(&dag_a, phone_a.id());
    let (need_b, have_b) = compute_dag_diff(&dag_b, &inv_a);
    assert!(need_b.contains(&tx_a.id));
    assert!(!need_b.contains(&genesis));
    assert!(have_b.contains(&tx_b.id));

    let inv_b = SyncInventory::from_dag(&dag_b, phone_b.id());
    let (need_a, _have_a) = compute_dag_diff(&dag_a, &inv_b);
    assert!(need_a.contains(&tx_b.id));

    assert_eq!(
        dag_b
            .merge_offline_graphs(dag_a.transactions_for(&need_b), mule)
            .unwrap(),
        1
    );
    assert_eq!(
        dag_a
            .merge_offline_graphs(dag_b.transactions_for(&need_a), mule)
            .unwrap(),
        1
    );

    assert_eq!(dag_a.vertex_set(), dag_b.vertex_set());
    assert!(dag_a.contains(&tx_a.id) && dag_a.contains(&tx_b.id));
    assert!(dag_b.contains(&tx_a.id) && dag_b.contains(&tx_b.id));
    assert!(dag_a.tips().contains(&tx_a.id) && dag_a.tips().contains(&tx_b.id));

    assert_eq!(dag_b.relay_node(&tx_a.id), Some(mule));
    assert_eq!(dag_a.relay_node(&tx_b.id), Some(mule));
    assert_eq!(relay_share_of(FIXED_TRANSACTION_FEE), 200);
    let relay_cut = dag_relay_total_of(INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE);
    assert_eq!(relay_cut, 20_200);
    // Unsigned mule sidecar is recorded; 20% pays only proven relays.
    assert_eq!(dag_b.relay_credit(&mule), 0);
    assert_eq!(dag_a.relay_credit(&mule), 0);
    assert_eq!(RELAY_SHARE_PERCENT, 20);
}

/// Three isolated phone mountains, parallel txs, BLE merge, local 80/20.
#[test]
fn test_offline_mesh_merging() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x334_5048_4F4E_45);
    let a = generate_kron_wallet_from_rng(&mut rng);
    let b = generate_kron_wallet_from_rng(&mut rng);
    let c = generate_kron_wallet_from_rng(&mut rng);
    let addr_a = *a.address().as_bytes();
    let addr_b = *b.address().as_bytes();
    let addr_c = *c.address().as_bytes();

    const CREDIT: u64 = 1_000_000;
    const SEND: u64 = 10_000;
    let pool = INITIAL_TX_SUBSIDY + FIXED_TRANSACTION_FEE;
    assert_eq!(dag_miner_share_of(pool), 80_800);
    assert_eq!(dag_relay_total_of(pool), 20_200);

    let mut shared = KronDAG::with_genesis();
    shared.credit_account(addr_a, CREDIT);
    shared.credit_account(addr_b, CREDIT);
    shared.credit_account(addr_c, CREDIT);
    let baseline = shared.clone();

    let mut dag_a = shared.clone();
    let mut dag_b = shared.clone();
    let mut dag_c = shared;

    // Parallel offline spends (no internet). Each mountain attaches locally.
    let tx_a = dag_a
        .compose_and_sign_with_rng(&a, addr_b, SEND, &mut rng)
        .unwrap();
    dag_a.attach_and_verify_tx(tx_a.clone()).unwrap();
    let tx_b = dag_b
        .compose_and_sign_with_rng(&b, addr_c, SEND, &mut rng)
        .unwrap();
    dag_b.attach_and_verify_tx(tx_b.clone()).unwrap();
    let tx_c = dag_c
        .compose_and_sign_with_rng(&c, addr_a, SEND, &mut rng)
        .unwrap();
    dag_c.attach_and_verify_tx(tx_c.clone()).unwrap();

    assert!(!dag_a.contains(&tx_b.id) && !dag_a.contains(&tx_c.id));
    assert!(!dag_b.contains(&tx_a.id) && !dag_b.contains(&tx_c.id));
    assert!(!dag_c.contains(&tx_a.id) && !dag_c.contains(&tx_b.id));

    let phone_a = MeshPhone::from_wallet(&a);
    let phone_b = MeshPhone::from_wallet(&b);
    let phone_c = MeshPhone::from_wallet(&c);
    let link = OfflineLink::new();
    link.mesh_handshake(&phone_a, &phone_b)
        .expect("BLE A↔B");
    link.mesh_handshake(&phone_b, &phone_c)
        .expect("BLE B↔C");
    link.mesh_handshake(&phone_a, &phone_c)
        .expect("BLE A↔C");
    let mule = phone_a.id();

    // A is the Bluetooth mule: carry missing vertices onto each mountain.
    fn ble_import(local: &mut KronDAG, remote: &KronDAG, mule: [u8; 32]) -> u32 {
        let inv = SyncInventory::from_dag(remote, mule);
        let (need, _) = compute_dag_diff(local, &inv);
        local
            .merge_offline_graphs(remote.transactions_for(&need), mule)
            .expect("BLE merge")
    }

    assert_eq!(ble_import(&mut dag_a, &dag_b, mule), 1);
    assert_eq!(ble_import(&mut dag_a, &dag_c, mule), 1);
    assert_eq!(ble_import(&mut dag_b, &dag_a, mule), 2);
    assert_eq!(ble_import(&mut dag_c, &dag_a, mule), 2);

    // Duplicate merge is ignored.
    assert_eq!(
        dag_a
            .merge_offline_graphs(vec![tx_b.clone(), tx_c.clone()], mule)
            .unwrap(),
        0
    );

    assert_eq!(dag_a.vertex_set(), dag_b.vertex_set());
    assert_eq!(dag_b.vertex_set(), dag_c.vertex_set());
    for dag in [&dag_a, &dag_b, &dag_c] {
        assert!(dag.contains(&tx_a.id) && dag.contains(&tx_b.id) && dag.contains(&tx_c.id));
        assert!(
            dag.tips().contains(&tx_a.id)
                || dag.parent_closure(tx_b.id).contains(&tx_a.id)
                || dag.parent_closure(tx_c.id).contains(&tx_a.id)
        );
        // Parallel branches remain (no linear fork-choice / no ACS).
        assert!(dag.get(&tx_a.id).is_some() && dag.get(&tx_b.id).is_some());
        assert!(dag.tips_are_consistent());
    }

    // Imported vertices record the mule sidecar; 20% requires a signed proof.
    assert_eq!(dag_a.relay_node(&tx_b.id), Some(mule));
    assert_eq!(dag_a.relay_node(&tx_c.id), Some(mule));
    assert_eq!(dag_a.relay_credit(&mule), 0);

    // No proven relays → each miner keeps the whole pool. A also receives SEND from C.
    let expected_a = CREDIT - SEND - FIXED_TRANSACTION_FEE + pool + SEND;
    assert_eq!(dag_a.balance(&addr_a), expected_a);

    let expected_b_on_a = CREDIT + SEND - SEND - FIXED_TRANSACTION_FEE + pool;
    assert_eq!(dag_a.balance(&addr_b), expected_b_on_a);
    let expected_c_on_a = CREDIT + SEND - SEND - FIXED_TRANSACTION_FEE + pool;
    assert_eq!(dag_a.balance(&addr_c), expected_c_on_a);

    // Offline double-spend: stored as conflict; exactly one spend stays in balances.
    let rogue = baseline;
    let conflict = rogue
        .compose_and_sign_with_rng(&a, addr_c, SEND, &mut rng)
        .unwrap();
    assert_eq!(conflict.nonce, 0);
    dag_a
        .merge_offline_graphs(vec![conflict.clone()], mule)
        .expect("conflict is stored, not aborted");
    assert!(dag_a.contains(&conflict.id));
    assert!(dag_a.is_conflict(&conflict.id) || dag_a.is_conflict(&tx_a.id));
    assert_ne!(dag_a.is_conflict(&conflict.id), dag_a.is_conflict(&tx_a.id));
}

#[test]
fn test_double_spend_resolved_after_merge() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4453_5045_4E44);
    let alice = generate_kron_wallet_from_rng(&mut rng);
    let bob = generate_kron_wallet_from_rng(&mut rng);
    let carol = generate_kron_wallet_from_rng(&mut rng);
    let addr_a = *alice.address().as_bytes();
    let addr_b = *bob.address().as_bytes();
    let addr_c = *carol.address().as_bytes();

    let mut shared = KronDAG::with_genesis();
    shared.credit_account(addr_a, 1_000_000);
    let mut dag_a = shared.clone();
    let mut dag_b = shared;

    const SEND: u64 = 10_000;
    let tx_bob = dag_a
        .compose_and_sign_with_rng(&alice, addr_b, SEND, &mut rng)
        .unwrap();
    dag_a.attach_and_verify_tx(tx_bob.clone()).unwrap();
    let tx_carol = dag_b
        .compose_and_sign_with_rng(&alice, addr_c, SEND, &mut rng)
        .unwrap();
    dag_b.attach_and_verify_tx(tx_carol.clone()).unwrap();
    assert_eq!(tx_bob.nonce, tx_carol.nonce);

    let mule = *alice.address().as_bytes();
    dag_a
        .merge_offline_graphs(vec![tx_carol.clone()], mule)
        .unwrap();
    dag_b
        .merge_offline_graphs(vec![tx_bob.clone()], mule)
        .unwrap();

    assert_eq!(dag_a.vertex_set(), dag_b.vertex_set());
    assert!(dag_a.contains(&tx_bob.id) && dag_a.contains(&tx_carol.id));

    let bob_got = dag_a.balance(&addr_b) >= SEND;
    let carol_got = dag_a.balance(&addr_c) >= SEND;
    assert_eq!(
        u8::from(bob_got) + u8::from(carol_got),
        1,
        "exactly one spend must affect balances"
    );
    assert_eq!(dag_a.balance(&addr_b), dag_b.balance(&addr_b));
    assert_eq!(dag_a.balance(&addr_c), dag_b.balance(&addr_c));
    assert!(dag_a.is_conflict(&tx_bob.id) ^ dag_a.is_conflict(&tx_carol.id));
}

/// Hard cap reached → subsidy 0; 80/20 of the 1000 fee still pays the network.
#[test]
fn test_hard_cap_and_fee_only_phase() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4841_5244_4341_50);
    let miner = generate_kron_wallet_from_rng(&mut rng);
    let dest = generate_kron_wallet_from_rng(&mut rng);
    let relay = generate_kron_wallet_from_rng(&mut rng);

    let mut dag = KronDAG::with_genesis();
    dag.current_supply = HARD_CAP;
    dag.credit_account(*miner.address().as_bytes(), 1_000_000);

    assert_eq!(get_current_tx_subsidy(dag.dag_tx_count, dag.current_supply), 0);

    let mut tx = dag
        .compose_and_sign_with_rng(
            &miner,
            *dest.address().as_bytes(),
            10_000,
            &mut rng,
        )
        .unwrap();
    tx = new_blockchain::dag::relay_intercept_and_sign(tx, &relay);
    dag.attach_and_verify_tx(tx).unwrap();

    assert_eq!(dag.current_supply, HARD_CAP, "supply must not grow");
    assert_eq!(dag.dag_tx_count, 1);
    assert_eq!(get_current_tx_subsidy(0, HARD_CAP), 0);
    assert_eq!(dag_miner_share_of(FIXED_TRANSACTION_FEE), 800);
    assert_eq!(dag_relay_total_of(FIXED_TRANSACTION_FEE), 200);
    // Miner paid 10_000 + 1000, received 800 of the fee.
    assert_eq!(
        dag.balance(miner.address().as_bytes()),
        1_000_000 - 10_000 - 1_000 + 800
    );
    assert_eq!(dag.balance(relay.address().as_bytes()), 200);
    assert_eq!(dag.relay_credit(relay.address().as_bytes()), 200);
    assert_eq!(dag.balance(dest.address().as_bytes()), 10_000);
}

/// x86 / emulator / Sybil host cannot attach as miner; attacker is isolated.
#[test]
fn test_pc_emulator_rejection() {
    let sybil = enforce_observation(&HostObservation::x86_emulator()).expect_err("PC Sybil");
    assert!(sybil.is_critical());
    assert_eq!(sybil, ShieldError::PcArchitecture);

    if HostArch::detect().is_pc_class() {
        let err = enforce_real_mobile().expect_err("this Windows x86 box must fail closed");
        assert!(err.is_critical());
        assert_eq!(err, ShieldError::PcArchitecture);
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5359_4249_4C78);
    let attacker = generate_kron_wallet_from_rng(&mut rng);
    let victim = generate_kron_wallet_from_rng(&mut rng);
    let mut dag = KronDAG::with_genesis();
    dag.credit_account(*attacker.address().as_bytes(), 1_000_000);
    let tx = dag
        .compose_and_sign_with_rng(
            &attacker,
            *victim.address().as_bytes(),
            10_000,
            &mut rng,
        )
        .unwrap();
    let tx_id = tx.id;

    let host_gate = enforce_real_mobile();
    if host_gate.is_err() {
        let attach_err = dag.attach_and_verify_tx_as_miner(tx.clone());
        assert!(
            matches!(attach_err, Err(DagError::Shield(ref e)) if e.is_critical()),
            "miner attach must be a critical shield error, got {attach_err:?}"
        );
        assert!(
            !dag.contains(&tx_id),
            "attacker must be isolated (vertex not attached)"
        );
        assert_eq!(dag.dag_tx_count, 0);
        assert_eq!(dag.current_supply, 0);

        let merge_err =
            dag.merge_offline_graphs_as_relay(vec![tx.clone()], *attacker.address().as_bytes());
        assert!(matches!(merge_err, Err(SyncError::Shield(e)) if e.is_critical()));
        assert!(!dag.contains(&tx_id));

        let mint_err =
            apply_dag_minting_as_miner(&mut dag, &tx, *attacker.address().as_bytes(), &[]);
        assert!(matches!(mint_err, Err(DagError::Shield(e)) if e.is_critical()));
        assert_eq!(dag.current_supply, 0);

        let mut mesh = MeshInterface::for_tests();
        mesh.request_stop();
        let relay_err = start_wallet_relay_service(&attacker, &mut mesh).unwrap_err();
        assert!(relay_err.is_critical());

        let mut wallet = KronWallet::from_keypair(attacker.clone());
        wallet.enable_miner_mode();
        let loop_err = new_blockchain::run_active_miner_loop(
            &wallet,
            &mut dag,
            *victim.address().as_bytes(),
            1,
        )
        .unwrap_err();
        assert!(loop_err.is_critical());
        assert!(!dag.contains(&tx_id));
    } else {
        assert!(
            !HostArch::detect().is_pc_class(),
            "x86 host must never pass enforce_real_mobile"
        );
    }

    // Reading / ledger-replay tests still run on this PC.
    dag.attach_and_verify_tx(tx).unwrap();
    assert!(dag.contains(&tx_id));
}
