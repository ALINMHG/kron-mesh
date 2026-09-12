//! BIP39 24-word recovery phrase for Termux / phone wallets.
//!
//! The 32-byte entropy is the ML-DSA-44 seed. The phrase is shown once at
//! generate time; later launches print only the `kron1` address unless the
//! user asks (`--show-mnemonic`).

use std::fs;
use std::path::Path;

use bip39::Mnemonic;
use rand::RngCore;

use crate::crypto::lattice::LatticeKeyPair;
use crate::kron::{KronAddress, KronKeypair};

/// Fresh 24-word phrase + matching Dilithium wallet.
pub fn generate_recovery_wallet() -> (KronKeypair, String, [u8; 32]) {
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("32-byte entropy is valid BIP39");
    let wallet = KronKeypair::from_lattice(LatticeKeyPair::from_seed(entropy));
    (wallet, mnemonic.to_string(), entropy)
}

/// Persist seed, address, and mnemonic. Does not print the phrase.
pub fn save_phone_wallet(dir: &Path, entropy: &[u8; 32], phrase: &str, address: &KronAddress) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let seed_path = dir.join("wallet.seed");
    let body = format!(
        "# KRON phone wallet ML-DSA-44 seed (keep private)\n{}\n",
        hex::encode(entropy)
    );
    fs::write(&seed_path, body).map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    let mpath = dir.join("wallet.mnemonic");
    fs::write(&mpath, format!("{phrase}\n")).map_err(|e| format!("write {}: {e}", mpath.display()))?;
    let _ = fs::write(dir.join("address.txt"), format!("{}\n", address.as_str()));
    let _ = fs::write(dir.join("mnemonic.shown"), "1\n");
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
    Ok(KronKeypair::from_lattice(LatticeKeyPair::from_seed(seed)))
}

pub fn load_saved_address(dir: &Path) -> Option<String> {
    let raw = fs::read_to_string(dir.join("address.txt")).ok()?;
    let line = raw.lines().find(|l| !l.trim().is_empty())?;
    Some(line.trim().to_string())
}

/// Reveal the stored 24 words only when the user asked.
pub fn load_mnemonic(dir: &Path) -> Result<String, String> {
    let path = dir.join("wallet.mnemonic");
    let raw = fs::read_to_string(&path).map_err(|_| {
        "no recovery phrase on disk — generate a wallet first".to_string()
    })?;
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
}
