//! Production identities are **NIST ML-DSA-44** (FIPS 204 / Dilithium2).
//!
//! `LatticeKeyPair` / `LatticePublicKey` / `LatticeSignature` are Dilithium-backed
//! despite the historic names. Bech32 `kron1` is SHA-256 of the versioned public
//! key bytes. Educational module-LWE below is **only** PoUCW mining work
//! (`expand_matrix_sized`, `matrix_vec`) — never a live tx or P2P signature.
//!
//! Versioned envelope: byte `2` = ML-DSA-44. Version `1` (toy LWE) is rejected.

use fips204::ml_dsa_44::{self, PrivateKey, PublicKey};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use rand::{CryptoRng, Rng};
use thiserror::Error;

use crate::crypto::hash::sha256;

/// Rejected educational LWE wire tag (live node refuses these).
pub const SCHEME_TOY_LWE: u8 = 1;
/// NIST ML-DSA-44 / Dilithium2.
pub const SCHEME_MLDSA44: u8 = 2;
/// FIPS 204 context string (domain separation, not a timestamp).
const ML_DSA_CTX: &[u8] = b"KRON";

/// Secret / error dimension used by the educational PoUCW matrix.
#[allow(dead_code)]
pub const N: usize = 32;
/// Number of LWE samples (rows of A) in the educational construction.
#[allow(dead_code)]
pub const M: usize = 48;
/// Prime modulus shared with Dilithium rounding (PoUCW only).
pub const Q: i64 = 8_380_417;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("ML-DSA signature verification failed")]
    VerifyFailed,
    #[error("signing aborted after {0} attempts")]
    SigningAborted(usize),
    #[error("malformed ML-DSA key or signature")]
    InvalidEncoding,
    #[error("rejected obsolete toy-LWE key or signature (need ML-DSA-44)")]
    ObsoleteScheme,
}

/// Dilithium public key (ML-DSA-44). Address = SHA-256 of [`Self::to_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticePublicKey {
    raw: Vec<u8>,
}

/// Dilithium secret key bytes (never logged).
#[derive(Clone, PartialEq, Eq)]
pub struct LatticeSecretKey {
    raw: Vec<u8>,
}

impl std::fmt::Debug for LatticeSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LatticeSecretKey")
            .field("scheme", &"ML-DSA-44")
            .field("len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

/// Node / wallet identity. NIST ML-DSA-44, not the old toy LWE signer.
#[derive(Clone)]
pub struct LatticeKeyPair {
    pub public: LatticePublicKey,
    pub secret: LatticeSecretKey,
}

impl std::fmt::Debug for LatticeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LatticeKeyPair")
            .field("public", &self.public)
            .field("scheme", &"ML-DSA-44")
            .finish_non_exhaustive()
    }
}

/// Versioned ML-DSA-44 detached signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeSignature {
    pub bytes: Vec<u8>,
}

impl LatticeSignature {
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }
}

impl LatticeKeyPair {
    /// Sample a fresh ML-DSA-44 key from `rng` (32-byte seed → FIPS keygen).
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn sign(&self, message: &[u8]) -> Result<LatticeSignature, CryptoError> {
        self.secret.sign(message)
    }

    /// Deterministic ML-DSA-44 from 32-byte BIP39 / identity seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&seed);
        Self {
            public: LatticePublicKey {
                raw: pk.into_bytes().to_vec(),
            },
            secret: LatticeSecretKey {
                raw: sk.into_bytes().to_vec(),
            },
        }
    }
}

impl LatticeSecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_blob(SCHEME_MLDSA44, &self.raw)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let raw = decode_blob(bytes, ml_dsa_44::SK_LEN)?;
        let arr: [u8; ml_dsa_44::SK_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding)?;
        PrivateKey::try_from_bytes(arr).map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self { raw })
    }

    pub fn sign(&self, message: &[u8]) -> Result<LatticeSignature, CryptoError> {
        let arr: [u8; ml_dsa_44::SK_LEN] = self
            .raw
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let sk = PrivateKey::try_from_bytes(arr).map_err(|_| CryptoError::InvalidEncoding)?;
        let sig = sk
            .try_sign(message, ML_DSA_CTX)
            .map_err(|_| CryptoError::SigningAborted(1))?;
        Ok(LatticeSignature {
            bytes: sig.to_vec(),
        })
    }
}

impl LatticePublicKey {
    pub fn verify(&self, message: &[u8], signature: &LatticeSignature) -> bool {
        let Ok(arr) = <[u8; ml_dsa_44::PK_LEN]>::try_from(self.raw.as_slice()) else {
            return false;
        };
        let Ok(pk) = PublicKey::try_from_bytes(arr) else {
            return false;
        };
        if signature.bytes.len() != ml_dsa_44::SIG_LEN {
            return false;
        }
        let Ok(sig) = <[u8; ml_dsa_44::SIG_LEN]>::try_from(signature.bytes.as_slice()) else {
            return false;
        };
        pk.verify(message, &sig, ML_DSA_CTX)
    }

    /// Canonical encoding: version ‖ length ‖ raw ML-DSA-44 public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_blob(SCHEME_MLDSA44, &self.raw)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let raw = decode_blob(bytes, ml_dsa_44::PK_LEN)?;
        let arr: [u8; ml_dsa_44::PK_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding)?;
        PublicKey::try_from_bytes(arr).map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self { raw })
    }

    /// Device address = SHA-256(versioned public key). 32 bytes, no chain lookup.
    pub fn address(&self) -> crate::types::Address {
        sha256(&self.to_bytes())
    }

    /// Bytes consumed by a versioned public-key encoding at `bytes[off..]`.
    pub fn encoded_len(bytes: &[u8], off: usize) -> Result<usize, CryptoError> {
        blob_len(bytes, off, ml_dsa_44::PK_LEN)
    }
}

impl LatticeSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_blob(SCHEME_MLDSA44, &self.bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let raw = decode_blob(bytes, ml_dsa_44::SIG_LEN)?;
        Ok(Self { bytes: raw })
    }
}

fn encode_blob(scheme: u8, raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + raw.len());
    out.push(scheme);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(raw);
    out
}

fn blob_len(bytes: &[u8], off: usize, expected: usize) -> Result<usize, CryptoError> {
    if bytes.len() < off + 5 {
        return Err(CryptoError::InvalidEncoding);
    }
    match bytes[off] {
        SCHEME_TOY_LWE => return Err(CryptoError::ObsoleteScheme),
        SCHEME_MLDSA44 => {}
        _ => return Err(CryptoError::InvalidEncoding),
    }
    let n = u32::from_le_bytes(bytes[off + 1..off + 5].try_into().unwrap()) as usize;
    if n != expected {
        return Err(CryptoError::InvalidEncoding);
    }
    if bytes.len() < off + 5 + n {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(5 + n)
}

fn decode_blob(bytes: &[u8], expected: usize) -> Result<Vec<u8>, CryptoError> {
    let n = blob_len(bytes, 0, expected)?;
    Ok(bytes[5..n].to_vec())
}

/// Expand `A ∈ Z_q^{M×N}` from a public seed (IoT devices never store A).
pub fn expand_matrix(seed: &[u8; 32]) -> Vec<Vec<i64>> {
    expand_matrix_sized(seed, M, N)
}

/// Expand a custom-sized public matrix. Used by difficulty-sharded micro-mining
/// so an old phone works on a tiny `A` while a PC works on a larger one.
pub fn expand_matrix_sized(seed: &[u8; 32], rows: usize, cols: usize) -> Vec<Vec<i64>> {
    let mut a = vec![vec![0i64; cols]; rows];
    let total = rows.saturating_mul(cols);
    if total == 0 {
        return a;
    }
    let mut idx = 0usize;
    let mut counter = 0u32;
    while idx < total {
        let mut block = [0u8; 36];
        block[..32].copy_from_slice(seed);
        block[32..].copy_from_slice(&counter.to_le_bytes());
        let h = sha256(&block);
        for chunk in h.chunks_exact(4) {
            if idx >= total {
                break;
            }
            let raw = u32::from_le_bytes(chunk.try_into().unwrap()) as i64;
            let i = idx / cols;
            let j = idx % cols;
            a[i][j] = raw % Q;
            idx += 1;
        }
        counter += 1;
    }
    a
}

/// Matrix-vector product modulo `Q` (centered). One call is the verifier's
/// dominant cost in Proof-of-Useful-Cryptographic-Work.
///
/// AArch64 uses a NEON load / two-wide accumulate fast path. x86 and unit
/// tests use the scalar implementation (math only — not mining admission).
pub fn matrix_vec(a: &[Vec<i64>], v: &[i64]) -> Vec<i64> {
    #[cfg(target_arch = "aarch64")]
    {
        matrix_vec_neon(a, v)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        matrix_vec_scalar(a, v)
    }
}

/// Portable mat-vec. Always available so x86 tests can check the math.
pub fn matrix_vec_scalar(a: &[Vec<i64>], v: &[i64]) -> Vec<i64> {
    a.iter()
        .map(|row| {
            let acc: i64 = row
                .iter()
                .zip(v.iter())
                .map(|(ai, vi)| ai.wrapping_mul(*vi))
                .sum();
            centered_mod(acc, Q)
        })
        .collect()
}

#[cfg(target_arch = "aarch64")]
fn matrix_vec_neon(a: &[Vec<i64>], v: &[i64]) -> Vec<i64> {
    a.iter()
        .map(|row| centered_mod(unsafe { neon_dot(row, v) }, Q))
        .collect()
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon_dot(row: &[i64], v: &[i64]) -> i64 {
    use std::arch::aarch64::{vgetq_lane_s64, vld1q_s64};
    let n = row.len().min(v.len());
    let mut acc = 0i64;
    let mut i = 0usize;
    while i + 2 <= n {
        let a = vld1q_s64(row.as_ptr().add(i));
        let b = vld1q_s64(v.as_ptr().add(i));
        let a0 = vgetq_lane_s64(a, 0);
        let a1 = vgetq_lane_s64(a, 1);
        let b0 = vgetq_lane_s64(b, 0);
        let b1 = vgetq_lane_s64(b, 1);
        acc = acc.wrapping_add(a0.wrapping_mul(b0));
        acc = acc.wrapping_add(a1.wrapping_mul(b1));
        i += 2;
    }
    while i < n {
        acc = acc.wrapping_add(row[i].wrapping_mul(v[i]));
        i += 1;
    }
    acc
}

pub fn infinity_norm(v: &[i64]) -> i64 {
    v.iter().map(|x| x.abs()).max().unwrap_or(0)
}

pub fn centered_mod(x: i64, q: i64) -> i64 {
    let mut r = x % q;
    if r < 0 {
        r += q;
    }
    if r > q / 2 {
        r -= q;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let kp = LatticeKeyPair::generate(&mut rng);
        let msg = b"iot-transfer-1";
        let sig = kp.sign(msg).expect("sign");
        assert!(kp.public.verify(msg, &sig));
        assert!(!kp.public.verify(b"tampered", &sig));
    }

    #[test]
    fn encoding_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let kp = LatticeKeyPair::generate(&mut rng);
        let sig = kp.sign(b"enc").unwrap();
        let pk2 = LatticePublicKey::from_bytes(&kp.public.to_bytes()).unwrap();
        let sk2 = LatticeSecretKey::from_bytes(&kp.secret.to_bytes()).unwrap();
        let sig2 = LatticeSignature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(kp.public, pk2);
        assert_eq!(kp.secret, sk2);
        assert_eq!(sig, sig2);
        assert!(pk2.verify(b"enc", &sig2));
        let restored = LatticeKeyPair {
            public: pk2,
            secret: sk2,
        };
        let sig3 = restored.sign(b"restored").unwrap();
        assert!(restored.public.verify(b"restored", &sig3));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let a = LatticeKeyPair::from_seed([0x4B; 32]);
        let b = LatticeKeyPair::from_seed([0x4B; 32]);
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret, b.secret);
        let other = LatticeKeyPair::from_seed([0x52; 32]);
        assert_ne!(a.public, other.public);
    }

    #[test]
    fn many_signatures_verify() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let kp = LatticeKeyPair::generate(&mut rng);
        for i in 0..12u32 {
            let msg = i.to_le_bytes();
            let sig = kp.sign(&msg).unwrap();
            assert!(kp.public.verify(&msg, &sig));
        }
    }

    #[test]
    fn matrix_vec_matches_scalar_on_this_host() {
        let seed = [3u8; 32];
        let a = expand_matrix(&seed);
        let v: Vec<i64> = (0..N).map(|i| i as i64 - 8).collect();
        assert_eq!(matrix_vec(&a, &v), matrix_vec_scalar(&a, &v));
    }

    #[test]
    fn toy_lwe_envelope_is_rejected() {
        let mut fake = vec![SCHEME_TOY_LWE];
        fake.extend_from_slice(&(32u32).to_le_bytes());
        fake.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            LatticePublicKey::from_bytes(&fake).unwrap_err(),
            CryptoError::ObsoleteScheme
        );
        assert_eq!(
            LatticeSignature::from_bytes(&fake).unwrap_err(),
            CryptoError::ObsoleteScheme
        );
    }
}
