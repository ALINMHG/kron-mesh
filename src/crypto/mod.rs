//! Cryptographic layer: hashing, NIST ML-DSA-44, and the phone-only shield.

pub mod hash;
pub mod lattice;
pub mod mobile_only;

pub use mobile_only::{
    enforce_device_attestation, enforce_real_mobile, HostArch, HostObservation, ShieldError,
};
