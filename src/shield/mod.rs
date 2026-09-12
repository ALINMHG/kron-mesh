//! `kron_crypto_shield` surface. Implementation lives in
//! [`crate::crypto::mobile_only`] so the library still builds on x86.

pub use crate::crypto::mobile_only::{
    cache_looks_like_emulator, cloud_environment_detected, cloud_environment_from_pairs,
    enforce_device_attestation, enforce_observation, enforce_real_mobile, probe_cache_latencies,
    HostArch, HostObservation, ShieldError, CLOUD_ENV_KEYS,
};
