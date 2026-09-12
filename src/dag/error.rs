//! Errors from tip selection, attach, and local-ledger checks.

use thiserror::Error;

use crate::crypto::lattice::CryptoError;
use crate::crypto::mobile_only::ShieldError;

use super::tx::TxHash;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagError {
    #[error("unknown parent {0:?}")]
    UnknownParent(TxHash),
    #[error("ML-DSA-44 signature is not valid for the sender")]
    InvalidSignature,
    #[error("sender cannot cover amount + fee")]
    InsufficientBalance,
    #[error("double-spend: nonce {nonce} already used or not next for sender")]
    DoubleSpend { nonce: u64 },
    #[error("transaction {0:?} is already in the DAG")]
    DuplicateTx(TxHash),
    #[error("genesis parents are only valid as the first vertex")]
    InvalidGenesis,
    #[error("user transfers must pay FIXED_TRANSACTION_FEE (1000)")]
    InvalidFee,
    #[error("sender address does not match the public key")]
    AddressMismatch,
    #[error("integer overflow on amount, fee, or balance")]
    Overflow,
    #[error("relay carrier proof is not valid")]
    InvalidRelayProof,
    #[error("lattice signing failed: {0}")]
    Sign(#[from] CryptoError),
    #[error("phone-only shield: {0}")]
    Shield(#[from] ShieldError),
}
