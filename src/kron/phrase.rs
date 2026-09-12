//! BIP39 24-word recovery phrase for Termux / phone wallets.
//!
//! The 32-byte entropy is the ML-DSA-44 seed. The phrase is shown once at
//! generate time and is **not** written to disk. Later launches print only
//! the `kron1` address. Seed bytes are chmod 600 and XOR-obscured when
//! `KRON_WALLET_PASS` is set.

use std::fs;
use std::path::Path;

use bip39::Mnemonic;
use rand::RngCore;

use crate::crypto::hash::sha256_parts;
use crate::crypto::lattice::LatticeKeyPair;
use crate::kron::{KronAddress, KronKeypair};

/// Passphrase used to XOR-obscure `wallet.seed` (Termux-friendly, no OS keystore).
pub const KRON_WALLET_PASS_ENV: &str = "KRON_WALLET_PASS";

/// Fresh 24-word phrase + matching Dilithium wallet.
pub fn generate_recovery_wallet() -> (KronKeypair, String, [u8; 32]) {
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("32-byte entropy is valid BIP39");
    let wallet = KronKeypair::from_lattice(LatticeKeyPair::from_seed(entropy));
    (wallet, mnemonic.to_string(), entropy)
}

fn xor_seed(entropy: &[u8; 32], pass: &str) -> [u8; 32] {
    let key = sha256_parts(&[b"kron-wallet-xor-v1", pass.as_bytes()]);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = entropy[i] ^ key[i];
    }
    out
}

fn restrict_secret_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

/// Persist seed and address. Does **not** write `wallet.mnemonic`.
///
/// If `KRON_WALLET_PASS` is set, the seed hex is XOR-obscured with that
/// passphrase. `phrase` is accepted so callers can show it once; it is not stored.
pub fn save_phone_wallet(
    dir: &Path,
    entropy: &[u8; 32],
    _phrase: &str,
    address: &KronAddress,
) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let seed_path = dir.join("wallet.seed");
    let stored = match std::env::var(KRON_WALLET_PASS_ENV) {
        Ok(pass) if !pass.is_empty() => xor_seed(entropy, &pass),
        _ => *entropy,
    };
    let protected = std::env::var(KRON_WALLET_PASS_ENV)
        .ok()
        .filter(|p| !p.is_empty())
        .is_some();
    let header = if protected {
        "# KRON phone wallet ML-DSA-44 seed (XOR-obscured; KRON_WALLET_PASS)\n"
    } else {
        "# KRON phone wallet ML-DSA-44 seed (keep private)\n"
    };
    let body = format!("{header}{}\n", hex::encode(stored));
    fs::write(&seed_path, body).map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    restrict_secret_file(&seed_path);
    let _ = fs::write(dir.join("address.txt"), format!("{}\n", address.as_str()));
    // Never write wallet.mnemonic. Legacy files are left untouched.
    Ok(())
}

pub fn phone_wallet_exists(dir: &Path) -> bool {
    dir.join("wallet.seed").exists() || dir.join("identity.seed").exists()
}

pub fn load_phone_wallet(dir: &Path) -> Result<KronKeypair, String> {
    let seed_path = if dir.join("wallet.seed").exists() {
        dir.join("wallet.seed")
    } else {
        dir.join("identity.seed")
    };
    let raw = fs::read_to_string(&seed_path).map_err(|e| format!("read {}: {e}", seed_path.display()))?;
    let hex_str = raw
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .unwrap_or("")
        .trim();
    let bytes = hex::decode(hex_str).map_err(|e| format!("wallet seed hex: {e}"))?;
    if bytes.len() != 32 {
        return Err("wallet seed must be 32 bytes (64 hex chars)".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    if let Ok(pass) = std::env::var(KRON_WALLET_PASS_ENV) {
        if !pass.is_empty() {
            seed = xor_seed(&seed, &pass);
        }
    }
    Ok(KronKeypair::from_lattice(LatticeKeyPair::from_seed(seed)))
}

pub fn load_saved_address(dir: &Path) -> Option<String> {
    let raw = fs::read_to_string(dir.join("address.txt")).ok()?;
    let line = raw.lines().find(|l| !l.trim().is_empty())?;
    Some(line.trim().to_string())
}

/// Reveal a stored 24-word file only if a legacy `wallet.mnemonic` exists.
/// New wallets do not persist the phrase.
pub fn load_mnemonic(dir: &Path) -> Result<String, String> {
    let path = dir.join("wallet.mnemonic");
    if !path.exists() {
        return Err(
            "recovery phrase is not stored on disk — write the 24 words down when generated"
                .into(),
        );
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(raw.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_phrase_is_24_words_and_kron1() {
        let (wallet, phrase, entropy) = generate_recovery_wallet();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(wallet.address().as_str().starts_with("kron1"));
        let restored = KronKeypair::from_lattice(LatticeKeyPair::from_seed(entropy));
        assert_eq!(restored.address().as_str(), wallet.address().as_str());
    }

    #[test]
    fn generate_does_not_write_mnemonic_file() {
        let dir = std::env::temp_dir().join(format!(
            "kron-wallet-nomnem-{}-{}",
            std::process::id(),
            0x4D4E
        ));
        let _ = fs::remove_dir_all(&dir);
        let (wallet, phrase, entropy) = generate_recovery_wallet();
        save_phone_wallet(&dir, &entropy, &phrase, &wallet.address()).unwrap();
        assert!(!dir.join("wallet.mnemonic").exists());
        assert!(dir.join("wallet.seed").exists());
        let loaded = load_phone_wallet(&dir).unwrap();
        assert_eq!(loaded.address().as_str(), wallet.address().as_str());
        assert!(load_mnemonic(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
