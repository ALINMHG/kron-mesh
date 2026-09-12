//! KRON Network brand, `kron1` wallet, relay service, and phone miner loop.
//!
//! Ledger identities remain 32-byte [`crate::types::Address`] hashes of the
//! versioned ML-DSA-44 public key. `kron1…` is the official Bech32 display form.

pub mod metadata;
pub mod miner;
pub mod phrase;
pub mod wallet;

mod bech32;

pub use metadata::{get_kron_metadata, AssetMetadata, KronVisualSpec, KRON_ICON_DESCRIPTOR};
pub use miner::{run_active_miner_loop, MinerLoopOutcome};
pub use phrase::{
    generate_recovery_wallet, load_mnemonic, load_phone_wallet, load_saved_address,
    phone_wallet_exists, save_phone_wallet,
};
pub use wallet::{
    derive_kron_address, generate_kron_wallet, generate_kron_wallet_from_rng,
    sign_transaction_natively, start_wallet_relay_service, verify_transaction_signature,
    KronAddress, KronKeypair, KronWallet, LatticePrivateKey,
};

/// Wallet mesh-relay service (`kron_wallet_relay_service`). Types live in
/// [`crate::dag`] so this module does not form a kron ↔ dag import cycle.
pub use crate::dag::{
    relay_intercept_and_sign, start_wallet_relay_mode, wallet_relay_step, MeshInterface,
    RelayMempool, RelayProof, WalletRelaySession,
};

/// Official network name.
pub const NETWORK_NAME: &str = "KRON Network";
/// Official ticker.
pub const TICKER: &str = "KRON";
/// One Satoshi-KRON (micro-KRON) equals one minor unit.
pub const SATOSHI_KRON: u64 = crate::economics::SATOSHI_KRON;
