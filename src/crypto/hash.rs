//! Domain-separated SHA-256 helpers used for Fiat-Shamir, digests, and coins.

use sha2::{Digest, Sha256};

use crate::types::Hash;

/// Single-shot SHA-256.
pub fn sha256(data: &[u8]) -> Hash {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA-256 over concatenated parts without extra allocation of a joined buffer
/// when the caller already has slices.
pub fn sha256_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Hex encoding for logs and tests.
pub fn hex_hash(hash: &Hash) -> String {
    hex::encode(hash)
}
