//! Stable overlay identity — a Unique Local IPv6 (`fd00::/8`) derived from
//! the node's ML-DSA public key.
//!
//! This is **not** a globally routed address. ISPs/IANA own public IPv4/IPv6;
//! a Rust process cannot allocate one. Phones use this Mesh ID in the routing
//! table. The optional public entry is a VPS you pay for (`--bootstrap`).

use std::fmt;

use crate::crypto::lattice::LatticePublicKey;
use crate::types::Address;

/// 16-byte mesh overlay id, shown as an IPv6 ULA (`fdxx:…`) or `kron://…`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeOverlayId {
    bytes: [u8; 16],
}

impl NodeOverlayId {
    /// `fd` + first 15 bytes of SHA-256(versioned ML-DSA pubkey).
    ///
    /// [`LatticePublicKey::address`] is that SHA-256, so this matches
    /// [`Self::from_address`].
    pub fn from_pubkey(pk: &LatticePublicKey) -> Self {
        Self::from_address(&pk.address())
    }

    /// Same derivation from the 32-byte ledger address.
    pub fn from_address(addr: &Address) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1..].copy_from_slice(&addr[..15]);
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Uncompressed ULA text (`fd12:3456:…`). Not a public IP.
    pub fn to_ula(&self) -> String {
        let b = self.bytes;
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }

    /// `kron://` + hex of the 16-byte overlay id.
    pub fn to_kron_uri(&self) -> String {
        format!("kron://{}", hex::encode(self.bytes))
    }

    /// `kron://kron1…` display form (wallet address, not a routable host).
    pub fn kron_uri_with_bech32(kron1: &str) -> String {
        format!("kron://{kron1}")
    }
}

impl fmt::Display for NodeOverlayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_ula())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::lattice::LatticeKeyPair;
    use rand::SeedableRng;

    #[test]
    fn different_keys_yield_different_overlay_ids() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D45_5348);
        let a = LatticeKeyPair::generate(&mut rng);
        let b = LatticeKeyPair::generate(&mut rng);
        let id_a = NodeOverlayId::from_pubkey(&a.public);
        let id_b = NodeOverlayId::from_pubkey(&b.public);
        assert_ne!(id_a, id_b);
        assert_ne!(id_a.to_ula(), id_b.to_ula());
    }

    #[test]
    fn same_key_is_stable_ula_and_matches_address_derivation() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D45_5349);
        let keys = LatticeKeyPair::generate(&mut rng);
        let once = NodeOverlayId::from_pubkey(&keys.public);
        let again = NodeOverlayId::from_pubkey(&keys.public);
        assert_eq!(once, again);
        assert_eq!(once, NodeOverlayId::from_address(&keys.public.address()));
        assert!(once.to_ula().starts_with("fd"), "{}", once.to_ula());
        assert_eq!(once.as_bytes()[0], 0xfd);
        assert!(once.to_kron_uri().starts_with("kron://"));
        assert_eq!(once.to_ula().matches(':').count(), 7);
    }
}
