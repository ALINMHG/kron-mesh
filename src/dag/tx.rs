//! DAG vertex: a phone-signed transfer that approves two parents.

use crate::crypto::hash::{sha256, sha256_parts};
use crate::crypto::lattice::{LatticePublicKey, LatticeSecretKey, LatticeSignature};
use crate::economics::FIXED_TRANSACTION_FEE;
use crate::kron::{derive_kron_address, KronAddress, KronKeypair};
use crate::types::Address;

use super::error::DagError;

/// SHA-256 identifier of a DAG vertex (the unsigned payload hash).
pub type TxHash = [u8; 32];

/// Carrier identity stored on the vertex sidecar (mesh [`super::NodeId`]).
/// Not part of the sender-signed body.
pub type RelayNodeId = Address;

/// ML-DSA-44 proof that a phone carried this vertex. Signed over
/// [`relay_proof_message`], never over the sender payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayProof {
    pub node: Address,
    pub public_key: LatticePublicKey,
    pub sig: LatticeSignature,
}

/// Domain-separated preimage for a relay carrier proof:
/// `H("kron-relay-v1" ‖ tx.hash ‖ relay_pk)`.
pub fn relay_proof_message(tx_id: &TxHash, relay_pk: &LatticePublicKey) -> [u8; 32] {
    sha256_parts(&[b"kron-relay-v1", tx_id, &relay_pk.to_bytes()])
}

/// Dummy parent used only by the genesis vertex (IOTA-style: no real parents).
pub const NULL_PARENT: TxHash = [0u8; 32];

/// Deterministic seed for the protocol genesis key (not a user wallet).
pub const GENESIS_SEED: [u8; 32] = *b"KRON-MOBILE-MESH-DAG-GENESIS\0\0\0\0";

/// A mesh transfer. Unique id is the SHA-256 of [`Self::unsigned_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagTransaction {
    pub id: TxHash,
    pub parent_1: TxHash,
    pub parent_2: TxHash,
    /// Official `kron1…` Bech32 of [`Self::sender`].
    pub sender_kron1: String,
    pub sender: Address,
    /// Official `kron1…` Bech32 of [`Self::recipient`].
    pub recipient_kron1: String,
    pub recipient: Address,
    /// Minor units (never IEEE-754).
    pub amount: u64,
    /// Always [`FIXED_TRANSACTION_FEE`] for user txs; 0 on genesis.
    pub fee: u64,
    /// Account-model nonce (UTXO-less double-spend tag).
    pub nonce: u64,
    pub public_key: LatticePublicKey,
    pub signature: LatticeSignature,
    /// Phones that intercepted this vertex in relay mode. **Not** hashed into
    /// [`Self::unsigned_bytes`] — mutating this cannot break the sender sig.
    pub relay_nodes: Vec<RelayNodeId>,
    /// Matching carrier proofs (same order as intercepts). Sidecar / proofs
    /// vec; attach still verifies only the original sender signature.
    pub relay_proofs: Vec<RelayProof>,
}

impl DagTransaction {
    /// Bytes that are hashed and ML-DSA-signed. Display strings are derived
    /// and are not part of the payload.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32 + 8 + 8 + 8 + 64);
        out.extend_from_slice(&self.parent_1);
        out.extend_from_slice(&self.parent_2);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.public_key.to_bytes());
        out
    }

    pub fn compute_id(unsigned: &[u8]) -> TxHash {
        sha256(unsigned)
    }

    pub fn is_genesis(&self) -> bool {
        self.parent_1 == NULL_PARENT && self.parent_2 == NULL_PARENT
    }

    pub fn refresh_id(&mut self) {
        self.id = Self::compute_id(&self.unsigned_bytes());
    }

    /// Relays that have a matching valid carrier proof (payout set).
    pub fn proven_relay_nodes(&self) -> Vec<RelayNodeId> {
        if !self.verify_relay_proofs() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.relay_proofs.len());
        for proof in &self.relay_proofs {
            if !out.contains(&proof.node) {
                out.push(proof.node);
            }
        }
        out
    }

    /// Verify every [`RelayProof`]. Empty nodes **and** empty proofs is valid
    /// (local attach, miner keeps the 20%). Nodes without matching proofs fail.
    pub fn verify_relay_proofs(&self) -> bool {
        if self.relay_nodes.is_empty() {
            return self.relay_proofs.is_empty();
        }
        if self.relay_proofs.is_empty() {
            return false;
        }
        for node in &self.relay_nodes {
            if !self.relay_proofs.iter().any(|p| p.node == *node) {
                return false;
            }
        }
        for proof in &self.relay_proofs {
            if proof.public_key.address() != proof.node {
                return false;
            }
            if !self.relay_nodes.contains(&proof.node) {
                return false;
            }
            let msg = relay_proof_message(&self.id, &proof.public_key);
            if !proof.public_key.verify(&msg, &proof.sig) {
                return false;
            }
        }
        true
    }

    /// True when the lattice signature matches the sender public key and the
    /// `kron1` / 32-byte address pair is consistent with that key.
    pub fn verify_signature(&self) -> bool {
        if self.public_key.address() != self.sender {
            return false;
        }
        if derive_kron_address(&self.public_key) != self.sender_kron1 {
            return false;
        }
        if KronAddress::from_hash(self.recipient).as_str() != self.recipient_kron1 {
            return false;
        }
        self.public_key
            .verify(&self.unsigned_bytes(), &self.signature)
    }

    /// Build an unsigned skeleton, hash it, then sign with `secret`.
    pub fn assemble(
        parent_1: TxHash,
        parent_2: TxHash,
        wallet: &KronKeypair,
        recipient: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Result<Self, DagError> {
        let public_key = wallet.public_key().clone();
        let sender = public_key.address();
        let sender_kron1 = derive_kron_address(&public_key);
        let recipient_kron1 = KronAddress::from_hash(recipient).into_string();
        let mut tx = Self {
            id: [0u8; 32],
            parent_1,
            parent_2,
            sender_kron1,
            sender,
            recipient_kron1,
            recipient,
            amount,
            fee,
            nonce,
            public_key,
            signature: LatticeSignature::empty(),
            relay_nodes: Vec::new(),
            relay_proofs: Vec::new(),
        };
        tx.refresh_id();
        tx.sign(&wallet.lattice().secret)?;
        Ok(tx)
    }

    fn sign(&mut self, secret: &LatticeSecretKey) -> Result<(), DagError> {
        self.signature = secret.sign(&self.unsigned_bytes())?;
        Ok(())
    }

    /// Wire encoding for gossip / WAL. Display `kron1` strings are derived.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.unsigned_bytes();
        let sig = self.signature.to_bytes();
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&sig);
        out.extend_from_slice(&(self.relay_nodes.len() as u32).to_le_bytes());
        for node in &self.relay_nodes {
            out.extend_from_slice(node);
        }
        out.extend_from_slice(&(self.relay_proofs.len() as u32).to_le_bytes());
        for proof in &self.relay_proofs {
            out.extend_from_slice(&proof.node);
            let pk = proof.public_key.to_bytes();
            out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
            out.extend_from_slice(&pk);
            let sb = proof.sig.to_bytes();
            out.extend_from_slice(&(sb.len() as u32).to_le_bytes());
            out.extend_from_slice(&sb);
        }
        out
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self, DagError> {
        use crate::crypto::lattice::CryptoError;
        if bytes.len() < 32 + 32 + 32 + 32 + 8 + 8 + 8 {
            return Err(DagError::Sign(CryptoError::InvalidEncoding));
        }
        let mut off = 0;
        let mut parent_1 = [0u8; 32];
        parent_1.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let mut parent_2 = [0u8; 32];
        parent_2.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let amount = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let fee = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let nonce = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let pk_len = LatticePublicKey::encoded_len(bytes, off).map_err(DagError::Sign)?;
        if bytes.len() < off + pk_len + 4 {
            return Err(DagError::Sign(CryptoError::InvalidEncoding));
        }
        let public_key = LatticePublicKey::from_bytes(&bytes[off..off + pk_len])?;
        off += pk_len;
        let slen = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if bytes.len() < off + slen {
            return Err(DagError::Sign(CryptoError::InvalidEncoding));
        }
        let signature = LatticeSignature::from_bytes(&bytes[off..off + slen])?;
        off += slen;
        if bytes.len() < off + 4 {
            return Err(DagError::Sign(CryptoError::InvalidEncoding));
        }
        let n_relays = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut relay_nodes = Vec::with_capacity(n_relays);
        for _ in 0..n_relays {
            if bytes.len() < off + 32 {
                return Err(DagError::Sign(CryptoError::InvalidEncoding));
            }
            let mut node = [0u8; 32];
            node.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            relay_nodes.push(node);
        }
        if bytes.len() < off + 4 {
            return Err(DagError::Sign(CryptoError::InvalidEncoding));
        }
        let n_proofs = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut relay_proofs = Vec::with_capacity(n_proofs);
        for _ in 0..n_proofs {
            if bytes.len() < off + 32 + 4 {
                return Err(DagError::Sign(CryptoError::InvalidEncoding));
            }
            let mut node = [0u8; 32];
            node.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let pk_len = LatticePublicKey::encoded_len(bytes, off).map_err(DagError::Sign)?;
            if bytes.len() < off + pk_len + 4 {
                return Err(DagError::Sign(CryptoError::InvalidEncoding));
            }
            let public_key = LatticePublicKey::from_bytes(&bytes[off..off + pk_len])?;
            off += pk_len;
            let slen = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if bytes.len() < off + slen {
                return Err(DagError::Sign(CryptoError::InvalidEncoding));
            }
            let sig = LatticeSignature::from_bytes(&bytes[off..off + slen])?;
            off += slen;
            relay_proofs.push(RelayProof {
                node,
                public_key,
                sig,
            });
        }
        let sender_kron1 = derive_kron_address(&public_key);
        let recipient_kron1 = KronAddress::from_hash(recipient).into_string();
        let mut tx = Self {
            id: [0u8; 32],
            parent_1,
            parent_2,
            sender_kron1,
            sender,
            recipient_kron1,
            recipient,
            amount,
            fee,
            nonce,
            public_key,
            signature,
            relay_nodes,
            relay_proofs,
        };
        tx.refresh_id();
        Ok(tx)
    }

    /// User transfer: fee is always [`FIXED_TRANSACTION_FEE`] (1000 = 0.001 KRON).
    pub fn user_transfer(
        parent_1: TxHash,
        parent_2: TxHash,
        wallet: &KronKeypair,
        recipient: Address,
        amount: u64,
        nonce: u64,
    ) -> Result<Self, DagError> {
        Self::assemble(
            parent_1,
            parent_2,
            wallet,
            recipient,
            amount,
            FIXED_TRANSACTION_FEE,
            nonce,
        )
    }
}
