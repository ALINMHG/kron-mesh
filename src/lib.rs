//! KRON Mesh — asynchronous mobile DAG ledger.
//!
//! Vertices are [`dag::DagTransaction`] (two parents, `kron1`, fee 1000, ML-DSA-44).
//! Confirmation is cumulative weight + tips. Minting is
//! [`dag::apply_dag_minting_natively`] (0.1 KRON/tx, 80% miner phone / 20% relays).
//! Phones are the network. The PC is an optional read-only explorer.
//! Mining/relay attach is refused at runtime on x86 (`enforce_real_mobile`).

pub mod anti_bot;
pub mod crypto;
pub mod dag;
pub mod economics;
pub mod explorer;
pub mod kron;
pub mod listen;
pub mod p2p;
pub mod persist;
pub mod shield;
pub mod types;

pub use anti_bot::{
    validate_mining_cadence, verify_hardware_authenticity, DeviceAttestation, DeviceClass,
    DeviceScore, HardwareProfile, SecurityError,
};

pub use crypto::lattice::{LatticeKeyPair, LatticeSignature};
pub use crypto::mobile_only::{
    enforce_device_attestation, enforce_observation, enforce_real_mobile, HostArch,
    HostObservation, ShieldError,
};
pub use economics::{
    dag_miner_share_of, dag_relay_total_of, get_current_tx_subsidy, mesh_relay_split,
    relay_share_of, txs_remaining_until_halving, DAG_MINER_SHARE_PERCENT, FIXED_TRANSACTION_FEE,
    HARD_CAP, INITIAL_TX_SUBSIDY, PREMINE, RELAY_SHARE_PERCENT, SATOSHI_KRON, TX_HALVING_INTERVAL,
    UNITS_PER_COIN,
};
pub use dag::{
    apply_dag_minting_as_miner, apply_dag_minting_from_sender, apply_dag_minting_natively,
    relay_intercept_and_sign, start_wallet_relay_mode, AttachingDevice, DagTransaction, KronDAG,
    MeshInterface, RelayMempool, RelayProof, WalletRelaySession,
};
pub use kron::{
    derive_kron_address, generate_kron_wallet, generate_kron_wallet_from_rng, get_kron_metadata,
    miner_tick, run_active_miner_loop, sign_transaction_natively, start_wallet_relay_service,
    verify_transaction_signature, AssetMetadata, KronAddress, KronKeypair, KronVisualSpec,
    KronWallet, MinerLoopOutcome, MinerTickOutcome, MinerTickStatus, NETWORK_NAME, TICKER,
};
pub use p2p::{
    broadcast_wallet_tx, default_gateway_addr, mesh_sync_connect, perform_secure_handshake,
    GossipInventory, HubState, IsolatedDag, MeshGraph, MeshRole, MeshWireMessage, NodeOverlayId,
    P2pNode, Peer, RoutingTable, PROTOCOL_KRON_MESH,
};
pub use explorer::{
    get_kron_asset_metadata, ExplorerApi, ExplorerEngine, FeeSplit, IndexedTransaction,
    IndexedVertex, MeshState, NetworkStats, TxHash, WalletSnapshot,
};
pub use persist::{DagSnapshot, DagStore, WalRecord};

/// Line + flush so Termux / redirected stdout shows progress immediately.
pub fn kron_log(prefix: &str, msg: impl std::fmt::Display) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "[{prefix}] {msg}");
    let _ = out.flush();
}

/// Same as [`kron_log`] on stderr (errors, bind failures).
pub fn kron_elog(prefix: &str, msg: impl std::fmt::Display) {
    use std::io::Write;
    let mut out = std::io::stderr();
    let _ = writeln!(out, "[{prefix}] {msg}");
    let _ = out.flush();
}
