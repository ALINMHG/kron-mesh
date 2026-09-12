//! KRON wallet engine: Bech32 `kron1` addresses over ML-DSA-44 public keys.
//!
//! `kron1` encodes SHA-256 of the versioned Dilithium public key. Signing is
//! NIST ML-DSA-44 (not the educational LWE used only for PoUCW mining).

use rand::{CryptoRng, Rng};

use crate::crypto::lattice::{
    LatticeKeyPair, LatticePublicKey, LatticeSecretKey, LatticeSignature,
};
use crate::kron::bech32::{decode_kron, encode_kron, Bech32Error};
use crate::dag::DagTransaction;
use crate::types::Address;

/// Wallet-facing private key. Wraps the Dilithium secret together with the
/// matching public key so `sign_transaction_natively` can call ML-DSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticePrivateKey {
    secret: LatticeSecretKey,
    public: LatticePublicKey,
}

impl LatticePrivateKey {
    pub fn from_keypair(kp: &LatticeKeyPair) -> Self {
        Self {
            secret: kp.secret.clone(),
            public: kp.public.clone(),
        }
    }

    pub fn secret(&self) -> &LatticeSecretKey {
        &self.secret
    }

    pub fn public(&self) -> &LatticePublicKey {
        &self.public
    }
}

/// KRON wallet keypair. Thin wrapper around the existing lattice keypair.
#[derive(Clone, Debug)]
pub struct KronKeypair {
    inner: LatticeKeyPair,
}

impl KronKeypair {
    pub fn from_lattice(inner: LatticeKeyPair) -> Self {
        Self { inner }
    }

    pub fn lattice(&self) -> &LatticeKeyPair {
        &self.inner
    }

    pub fn into_lattice(self) -> LatticeKeyPair {
        self.inner
    }

    pub fn public_key(&self) -> &LatticePublicKey {
        &self.inner.public
    }

    pub fn private_key(&self) -> LatticePrivateKey {
        LatticePrivateKey::from_keypair(&self.inner)
    }

    /// Official `kron1…` display address plus the 32-byte ledger key.
    pub fn address(&self) -> KronAddress {
        KronAddress::from_public_key(&self.inner.public)
    }
}

impl From<LatticeKeyPair> for KronKeypair {
    fn from(inner: LatticeKeyPair) -> Self {
        Self::from_lattice(inner)
    }
}

impl From<KronKeypair> for LatticeKeyPair {
    fn from(kp: KronKeypair) -> Self {
        kp.inner
    }
}

/// Official formatted string plus the inner 32-byte ledger [`Address`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KronAddress {
    encoded: String,
    bytes: Address,
}

impl KronAddress {
    pub fn from_hash(bytes: Address) -> Self {
        Self {
            encoded: encode_kron(&bytes),
            bytes,
        }
    }

    pub fn from_public_key(public_key: &LatticePublicKey) -> Self {
        Self::from_hash(public_key.address())
    }

    /// Parse a `kron1…` string. Accepts all-lower or all-upper (BIP-173).
    /// Whitespace, newlines, and zero-width marks are stripped so a Termux
    /// wrap (`kron1…` split across lines) still parses.
    pub fn parse(s: &str) -> Result<Self, Bech32Error> {
        let bytes = decode_kron(s)?;
        // Re-encode so the stored string is the canonical lowercase form.
        Ok(Self::from_hash(bytes))
    }

    pub fn as_bytes(&self) -> &Address {
        &self.bytes
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn into_string(self) -> String {
        self.encoded
    }
}

impl std::fmt::Display for KronAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl std::str::FromStr for KronAddress {
    type Err = Bech32Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Generate a KRON wallet using the OS CSPRNG (`rand::rngs::OsRng`).
pub fn generate_kron_wallet() -> KronKeypair {
    generate_kron_wallet_from_rng(&mut rand::rngs::OsRng)
}

/// Deterministic keygen for tests and seeded simulations.
pub fn generate_kron_wallet_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> KronKeypair {
    KronKeypair::from_lattice(LatticeKeyPair::generate(rng))
}

/// Official display address. Always starts with `kron1`.
pub fn derive_kron_address(public_key: &LatticePublicKey) -> String {
    KronAddress::from_public_key(public_key).into_string()
}

/// Phone wallet: `kron1` Bech32 identity plus optional explicit miner mode.
///
/// Default is relay/sleep. Heavy lattice attach runs only after
/// [`Self::enable_miner_mode`] and [`crate::crypto::mobile_only::enforce_real_mobile`].
#[derive(Clone, Debug)]
pub struct KronWallet {
    keys: KronKeypair,
    miner_mode: bool,
}

impl KronWallet {
    pub fn from_keypair(keys: KronKeypair) -> Self {
        Self {
            keys,
            miner_mode: false,
        }
    }

    pub fn generate() -> Self {
        Self::from_keypair(generate_kron_wallet())
    }

    pub fn generate_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::from_keypair(generate_kron_wallet_from_rng(rng))
    }

    pub fn address(&self) -> KronAddress {
        self.keys.address()
    }

    pub fn keypair(&self) -> &KronKeypair {
        &self.keys
    }

    pub fn miner_mode(&self) -> bool {
        self.miner_mode
    }

    /// Opt in to the active miner loop (phone-only).
    pub fn enable_miner_mode(&mut self) {
        self.miner_mode = true;
    }

    /// Sleep/wake relay. Refuses this host when it is a PC/emulator.
    pub fn start_wallet_relay_service(
        &self,
        mesh: &mut crate::dag::MeshInterface,
    ) -> Result<crate::dag::WalletRelaySession, crate::crypto::mobile_only::ShieldError> {
        start_wallet_relay_service(&self.keys, mesh)
    }
}

/// Production relay entry: admit a real mobile host, then the duty loop.
pub fn start_wallet_relay_service(
    wallet_keys: &KronKeypair,
    mesh_interface: &mut crate::dag::MeshInterface,
) -> Result<crate::dag::WalletRelaySession, crate::crypto::mobile_only::ShieldError> {
    crate::crypto::mobile_only::enforce_real_mobile()?;
    Ok(crate::dag::start_wallet_relay_mode(
        wallet_keys,
        mesh_interface,
    ))
}

/// Sign an arbitrary transaction payload with the existing lattice scheme.
pub fn sign_transaction_natively(
    tx_payload: &[u8],
    private_key: &LatticePrivateKey,
) -> LatticeSignature {
    private_key
        .secret
        .sign(tx_payload)
        .expect("ML-DSA-44 signing aborted")
}

/// True only if the lattice signature verifies and the sender is the 32-byte
/// hash encoded by `derive_kron_address(pubkey)` (`kron1…` payload).
pub fn verify_transaction_signature(tx: &DagTransaction) -> bool {
    if !tx.verify_signature() {
        return false;
    }
    let encoded = derive_kron_address(&tx.public_key);
    match KronAddress::parse(&encoded) {
        Ok(addr) => addr.as_bytes() == &tx.sender && encoded.starts_with("kron1"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::FIXED_TRANSACTION_FEE;
    use crate::kron::get_kron_metadata;
    use rand::SeedableRng;

    #[test]
    fn test_kron_wallet_lifecycle() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4B524F4E); // "KRON"
        let wallet = generate_kron_wallet_from_rng(&mut rng);
        let dest = generate_kron_wallet_from_rng(&mut rng);

        let encoded = derive_kron_address(wallet.public_key());
        assert!(encoded.starts_with("kron1"), "address must be kron1…: {encoded}");
        let parsed = KronAddress::parse(&encoded).expect("round-trip parse");
        assert_eq!(parsed.as_bytes(), &wallet.public_key().address());
        assert_eq!(parsed.as_str(), encoded.as_str());
        let pasted = format!("\r\n{encoded} \n");
        assert_eq!(
            KronAddress::parse(&pasted).expect("trim paste").as_str(),
            encoded.as_str()
        );

        // Native fee is 0.001 KRON = 1_000 Satoshi-KRON (ledger charges on apply).
        assert_eq!(FIXED_TRANSACTION_FEE, 1_000);

        let genesis = crate::dag::KronDAG::with_genesis();
        let (p1, p2) = (genesis.genesis_id(), genesis.genesis_id());
        let mut tx = crate::dag::DagTransaction::user_transfer(
            p1,
            p2,
            &wallet,
            *dest.address().as_bytes(),
            50_000,
            0,
        )
        .expect("unsigned skeleton");

        let native_sig = sign_transaction_natively(&tx.unsigned_bytes(), &wallet.private_key());
        tx.signature = native_sig;
        assert!(verify_transaction_signature(&tx));

        let mut tampered = tx.clone();
        tampered.amount ^= 1;
        tampered.refresh_id();
        assert!(!verify_transaction_signature(&tampered));

        let wrong = generate_kron_wallet_from_rng(&mut rng);
        let mut wrong_key = tx.clone();
        wrong_key.signature =
            sign_transaction_natively(&tx.unsigned_bytes(), &wrong.private_key());
        assert!(!verify_transaction_signature(&wrong_key));
    }

    #[test]
    fn test_kron_metadata_brand() {
        let meta = get_kron_metadata();
        assert_eq!(meta.ticker, "KRON");
        assert_eq!(meta.name, "KRON Network");
    }

    #[test]
    fn generate_derive_parse_same_bytes() {
        let wallet = generate_kron_wallet();
        let encoded = derive_kron_address(wallet.public_key());
        assert!(encoded.starts_with("kron1"));
        assert_eq!(encoded.len(), crate::kron::bech32::KRON1_LEN);
        let parsed = KronAddress::parse(&encoded).expect("derive → parse");
        assert_eq!(parsed.as_bytes(), &wallet.public_key().address());
        assert_eq!(parsed.as_str(), encoded);
    }

    #[test]
    fn whitespace_wrapped_paste_still_parses() {
        let wallet = generate_kron_wallet();
        let encoded = derive_kron_address(wallet.public_key());
        let mut wrapped = String::new();
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i % 16 == 0 {
                wrapped.push_str(" \n");
            }
            wrapped.push(ch);
        }
        let parsed = KronAddress::parse(&wrapped).expect("wrapped Termux paste");
        assert_eq!(parsed.as_bytes(), &wallet.public_key().address());
        assert_eq!(parsed.as_str(), encoded);
    }

    #[test]
    fn truncated_address_fails_clearly() {
        let wallet = generate_kron_wallet();
        let encoded = derive_kron_address(wallet.public_key());
        let truncated = &encoded[..40];
        let err = KronAddress::parse(truncated).expect_err("truncated must fail");
        assert_eq!(err, Bech32Error::InvalidChecksum);
        let msg = err.to_string();
        assert!(msg.contains("63"), "{msg}");
        assert!(msg.contains("one line"), "{msg}");
        let cli = err.cli_message(truncated);
        assert!(cli.contains("40"), "{cli}");
        assert!(cli.contains("63"), "{cli}");
        assert!(cli.contains("one line"), "{cli}");
    }

    #[test]
    fn kron_wallet_is_relay_by_default() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5741_4C54);
        let mut w = KronWallet::generate_from_rng(&mut rng);
        assert!(w.address().as_str().starts_with("kron1"));
        assert!(!w.miner_mode());
        w.enable_miner_mode();
        assert!(w.miner_mode());
    }
}
