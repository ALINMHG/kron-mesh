//! Mesh anti-Sybil: hardware quotes, paced attach, Proof of Adjacency.
//!
//! Used by the Noise handshake and BLE-style mesh meetup. There is no ACS
//! epoch admission and no block-sealing coinbase.

pub mod attestation;
pub mod cadence;
pub mod profile;
pub mod reputation;

pub use attestation::{
    miner_node_id, residential_ipv4, verify_hardware_authenticity, DeviceAttestation, DeviceScore,
    SecurityError,
};
pub use cadence::PacedVerifier;
pub use profile::{DeviceClass, HardwareProfile};
pub use reputation::{NodeReputation, ReputationLedger};

use std::time::Duration;

/// Duration vs. claimed device class (handshake / mesh attach pacing).
pub fn validate_mining_cadence(
    paced: &mut PacedVerifier,
    node_id: crate::types::NodeId,
    submission_time: Duration,
) -> bool {
    paced.validate_mining_cadence(node_id, submission_time)
}
