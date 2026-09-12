//! Core identifiers. Ledger money is integer minor units only.

pub mod message;

/// 32-byte digest (SHA-256).
pub type Hash = [u8; 32];
/// Account address: SHA-256 of a versioned ML-DSA-44 public key.
pub type Address = [u8; 32];
/// Compact numeric id used by cadence / reputation tables.
pub type NodeId = u32;
