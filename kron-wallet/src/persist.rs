//! Local wallet file in `%APPDATA%\KRON\wallet.json` (never the Desktop).
//!
//! Version 2 stores BIP39 entropy (32 bytes → 24 words) plus the derived
//! lattice keypair. Legacy v1 files (raw keys, no mnemonic) are archived to
//! `wallet.json.bak` and replaced so the next open can backup a recovery phrase.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use new_blockchain::crypto::lattice::{LatticeKeyPair, LatticePublicKey, LatticeSecretKey};
use new_blockchain::kron::KronKeypair;
use serde::{Deserialize, Serialize};

use crate::mnemonic::RecoveryPhrase;

const WALLET_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    #[serde(default)]
    entropy_hex: Option<String>,
    public_hex: String,
    secret_hex: String,
    nonce: u64,
    #[serde(default)]
    mnemonic_backed_up: bool,
}

#[derive(Debug)]
pub enum WalletIoError {
    Io(io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Crypto(new_blockchain::crypto::lattice::CryptoError),
    UnsupportedVersion(u32),
    MissingEntropy,
    KeyMismatch,
}

impl std::fmt::Display for WalletIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wallet file: {e}"),
            Self::Json(e) => write!(f, "wallet JSON: {e}"),
            Self::Hex(e) => write!(f, "wallet hex: {e}"),
            Self::Crypto(e) => write!(f, "lattice keys: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wallet version: {v}"),
            Self::MissingEntropy => write!(f, "wallet has no recovery-phrase entropy"),
            Self::KeyMismatch => {
                write!(f, "stored keys do not match the recovery-phrase entropy")
            }
        }
    }
}

impl From<io::Error> for WalletIoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for WalletIoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<hex::FromHexError> for WalletIoError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

impl From<new_blockchain::crypto::lattice::CryptoError> for WalletIoError {
    fn from(e: new_blockchain::crypto::lattice::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// `%APPDATA%\KRON\wallet.json` on Windows.
pub fn default_wallet_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("KRON").join("wallet.json")
}

pub struct LoadedWallet {
    pub keypair: KronKeypair,
    pub nonce: u64,
    pub entropy: [u8; 32],
    /// True when this process created a new mnemonic wallet.
    #[allow(dead_code)]
    pub created: bool,
    /// Show the first-run backup + confirmation flow.
    pub needs_onboarding: bool,
    /// True when a legacy file was moved to `*.bak` and replaced.
    pub archived_legacy: bool,
}

/// Load an existing mnemonic wallet or create one. Legacy files are archived.
pub fn load_or_create() -> Result<LoadedWallet, WalletIoError> {
    load_or_create_at(&default_wallet_path())
}

pub fn load_or_create_at(path: &Path) -> Result<LoadedWallet, WalletIoError> {
    if path.exists() {
        match load_v2_at(path) {
            Ok((keypair, nonce, entropy, backed_up)) => {
                return Ok(LoadedWallet {
                    keypair,
                    nonce,
                    entropy,
                    created: false,
                    needs_onboarding: !backed_up,
                    archived_legacy: false,
                });
            }
            Err(WalletIoError::MissingEntropy) | Err(WalletIoError::UnsupportedVersion(1)) => {
                archive_legacy(path)?;
                return create_new_at(path, true);
            }
            Err(e) => {
                // A v1 file deserializes but reports version 1.
                if looks_like_legacy(path) {
                    archive_legacy(path)?;
                    return create_new_at(path, true);
                }
                return Err(e);
            }
        }
    }
    create_new_at(path, false)
}

pub fn save(
    keypair: &KronKeypair,
    nonce: u64,
    entropy: &[u8; 32],
    mnemonic_backed_up: bool,
) -> Result<(), WalletIoError> {
    save_at(
        &default_wallet_path(),
        keypair,
        nonce,
        entropy,
        mnemonic_backed_up,
    )
}

fn looks_like_legacy(path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(file) = serde_json::from_str::<WalletFile>(&raw) else {
        return false;
    };
    file.version == 1 || file.entropy_hex.as_deref().unwrap_or("").is_empty()
}

fn archive_legacy(path: &Path) -> Result<PathBuf, WalletIoError> {
    let mut bak = path.with_extension("json.bak");
    if bak.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        bak = path.with_extension(format!("json.bak.{stamp}"));
    }
    fs::copy(path, &bak)?;
    fs::remove_file(path)?;
    Ok(bak)
}

fn create_new_at(path: &Path, archived_legacy: bool) -> Result<LoadedWallet, WalletIoError> {
    let phrase = RecoveryPhrase::generate();
    let keypair = phrase.keypair();
    let entropy = phrase.entropy();
    save_at(path, &keypair, 0, &entropy, false)?;
    Ok(LoadedWallet {
        keypair,
        nonce: 0,
        entropy,
        created: true,
        needs_onboarding: true,
        archived_legacy,
    })
}

fn load_v2_at(path: &Path) -> Result<(KronKeypair, u64, [u8; 32], bool), WalletIoError> {
    let raw = fs::read_to_string(path)?;
    let file: WalletFile = serde_json::from_str(&raw)?;
    if file.version == 1 {
        return Err(WalletIoError::UnsupportedVersion(1));
    }
    if file.version != WALLET_VERSION {
        return Err(WalletIoError::UnsupportedVersion(file.version));
    }
    let entropy_hex = file.entropy_hex.as_deref().unwrap_or("").trim();
    if entropy_hex.is_empty() {
        return Err(WalletIoError::MissingEntropy);
    }
    let entropy_bytes = hex::decode(entropy_hex)?;
    if entropy_bytes.len() != 32 {
        return Err(WalletIoError::MissingEntropy);
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_bytes);

    let derived = LatticeKeyPair::from_seed(entropy);
    let stored_ok = match (
        hex::decode(file.public_hex.trim()),
        hex::decode(file.secret_hex.trim()),
    ) {
        (Ok(pk_hex), Ok(sk_hex)) => {
            match (
                LatticePublicKey::from_bytes(&pk_hex),
                LatticeSecretKey::from_bytes(&sk_hex),
            ) {
                (Ok(public), Ok(secret)) => public == derived.public && secret == derived.secret,
                _ => false,
            }
        }
        _ => false,
    };
    // Same BIP39 entropy always yields the live ML-DSA-44 key. A v2 file that
    // still stored toy-LWE bytes is migrated in place.
    if !stored_ok {
        let _ = save_at(path, &KronKeypair::from_lattice(derived.clone()), file.nonce, &entropy, file.mnemonic_backed_up);
    }
    let keypair = KronKeypair::from_lattice(derived);
    Ok((keypair, file.nonce, entropy, file.mnemonic_backed_up))
}

fn save_at(
    path: &Path,
    keypair: &KronKeypair,
    nonce: u64,
    entropy: &[u8; 32],
    mnemonic_backed_up: bool,
) -> Result<(), WalletIoError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = WalletFile {
        version: WALLET_VERSION,
        entropy_hex: Some(hex::encode(entropy)),
        public_hex: hex::encode(keypair.public_key().to_bytes()),
        secret_hex: hex::encode(keypair.lattice().secret.to_bytes()),
        nonce,
        mnemonic_backed_up,
    };
    let json = serde_json::to_string_pretty(&file)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use new_blockchain::crypto::lattice::LatticeKeyPair;
    use new_blockchain::generate_kron_wallet;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "kron-wallet-{tag}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("json.bak"));
        let _ = fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn new_wallet_has_entropy_and_roundtrips() {
        let path = temp_path("new");
        cleanup(&path);
        let loaded = load_or_create_at(&path).expect("create");
        assert!(loaded.created);
        assert!(loaded.needs_onboarding);
        assert!(!loaded.archived_legacy);
        let phrase = RecoveryPhrase::from_entropy(loaded.entropy).unwrap();
        assert_eq!(phrase.words().len(), 24);
        assert_eq!(
            phrase.keypair().public_key().to_bytes(),
            loaded.keypair.public_key().to_bytes()
        );

        save_at(&path, &loaded.keypair, 7, &loaded.entropy, true).unwrap();
        let again = load_or_create_at(&path).expect("reload");
        assert!(!again.created);
        assert!(!again.needs_onboarding);
        assert_eq!(again.nonce, 7);
        assert_eq!(again.entropy, loaded.entropy);
        assert_eq!(
            LatticeKeyPair::from_seed(again.entropy).public,
            *again.keypair.public_key()
        );
        cleanup(&path);
    }

    #[test]
    fn legacy_v1_is_archived_and_replaced() {
        let path = temp_path("legacy");
        cleanup(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let old = generate_kron_wallet();
        let v1 = serde_json::json!({
            "version": 1,
            "public_hex": hex::encode(old.public_key().to_bytes()),
            "secret_hex": hex::encode(old.lattice().secret.to_bytes()),
            "nonce": 3u64,
        });
        fs::write(&path, serde_json::to_string_pretty(&v1).unwrap()).unwrap();

        let loaded = load_or_create_at(&path).expect("migrate");
        assert!(loaded.created);
        assert!(loaded.needs_onboarding);
        assert!(loaded.archived_legacy);
        assert_ne!(
            loaded.keypair.public_key().to_bytes(),
            old.public_key().to_bytes()
        );
        assert!(path.with_extension("json.bak").exists());
        let bak: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path.with_extension("json.bak")).unwrap())
                .unwrap();
        assert_eq!(bak["version"], 1);
        assert_eq!(bak["nonce"], 3);
        cleanup(&path);
    }
}
