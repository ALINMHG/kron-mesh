//! Phone-only host admission (`mobile_only_enforcer`).
//!
//! The **library compiles on x86_64** (this Windows PC included). Mining,
//! relay attach, and minting-from-a-PC-identity are rejected at runtime.
//! Reading the DAG and running ledger/economics tests is allowed.

use thiserror::Error;

use crate::anti_bot::attestation::verify_hardware_authenticity;
use crate::anti_bot::profile::DeviceClass;
use crate::anti_bot::{DeviceAttestation, SecurityError};

/// Environment keys that mean this process is a cloud/VM tenant. Fail closed.
pub const CLOUD_ENV_KEYS: &[&str] = &[
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
    "KUBERNETES",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "ECS_CONTAINER_METADATA_URI",
    "ECS_CONTAINER_METADATA_URI_V4",
    "GOOGLE_CLOUD_PROJECT",
    "GCLOUD_PROJECT",
    "FUNCTION_TARGET",
    "K_SERVICE",
    "AZURE_FUNCTIONS_ENVIRONMENT",
    "WEBSITE_INSTANCE_ID",
];

/// Critical shield failure. Every variant is admission-critical.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShieldError {
    #[error("critical: mining/relay/mint is phone-only; host is x86/PC")]
    PcArchitecture,
    #[error("critical: L1/L2 cache timing matches a VM or emulator")]
    EmulatorTiming,
    #[error("critical: cloud/datacenter environment variables present")]
    CloudEnvironment,
    #[error("critical: device attestation is datacenter/PC class")]
    DatacenterClass,
    #[error("critical: active miner loop requires explicit miner mode")]
    MinerModeRequired,
    #[error("critical: miner/relay attach was refused")]
    AttachFailed,
}

impl ShieldError {
    /// All shield failures isolate the attacker (no miner admission).
    pub fn is_critical(&self) -> bool {
        true
    }
}

/// Process ISA used by [`enforce_real_mobile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostArch {
    X86_64,
    X86,
    Aarch64,
    Other,
}

impl HostArch {
    pub fn detect() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::Other
        }
    }

    pub fn is_pc_class(self) -> bool {
        matches!(self, Self::X86_64 | Self::X86)
    }
}

/// Snapshot of this process (or a constructed Sybil/PC attempt).
#[derive(Clone, Debug)]
pub struct HostObservation {
    pub arch: HostArch,
    pub cache_samples: Vec<u64>,
    pub cloud: bool,
    pub device_class: DeviceClass,
}

impl HostObservation {
    /// Measure this process. Safe to call on x86 — it does not `compile_error`.
    pub fn probe_this_process() -> Self {
        Self {
            arch: HostArch::detect(),
            cache_samples: probe_cache_latencies(),
            cloud: cloud_environment_detected(),
            device_class: DeviceClass::PersonalComputer,
        }
    }

    /// Synthetic x86/emulator farm (used by tests on any host).
    pub fn x86_emulator() -> Self {
        Self {
            arch: HostArch::X86_64,
            cache_samples: vec![40, 40, 40, 40, 40, 40, 40, 40],
            cloud: false,
            device_class: DeviceClass::PersonalComputer,
        }
    }
}

/// Admit this host as a real mobile miner/relay. On `x86_64` this is always
/// `Err` (critical). On `aarch64` a cache probe must not look like an emulator.
pub fn enforce_real_mobile() -> Result<(), ShieldError> {
    enforce_observation(&HostObservation::probe_this_process())
}

/// Same policy as [`enforce_real_mobile`] over an explicit observation.
pub fn enforce_observation(obs: &HostObservation) -> Result<(), ShieldError> {
    if obs.cloud || cloud_environment_detected() {
        return Err(ShieldError::CloudEnvironment);
    }
    match obs.arch {
        HostArch::X86_64 | HostArch::X86 => Err(ShieldError::PcArchitecture),
        HostArch::Other => Err(ShieldError::PcArchitecture),
        HostArch::Aarch64 => {
            if cache_looks_like_emulator(&obs.cache_samples) {
                return Err(ShieldError::EmulatorTiming);
            }
            Ok(())
        }
    }
}

/// Anti-bot quote gate: reject PC / datacenter class and VM fingerprints.
pub fn enforce_device_attestation(att: &DeviceAttestation) -> Result<(), ShieldError> {
    if att.class == DeviceClass::PersonalComputer {
        return Err(ShieldError::DatacenterClass);
    }
    verify_hardware_authenticity(att).map_err(|e| match e {
        SecurityError::DatacenterCluster | SecurityError::NotPhoneMiner => {
            ShieldError::DatacenterClass
        }
        SecurityError::VirtualMachineFingerprint | SecurityError::EmulatorTiming => {
            ShieldError::EmulatorTiming
        }
        _ => ShieldError::DatacenterClass,
    })?;
    Ok(())
}

/// True when a known cloud/k8s/AWS/GCP/Azure variable is set and non-empty.
pub fn cloud_environment_detected() -> bool {
    cloud_environment_from_pairs(CLOUD_ENV_KEYS.iter().filter_map(|k| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| (*k, v))
    }))
}

/// Pure helper so tests do not mutate the process environment.
pub fn cloud_environment_from_pairs<I, K, V>(pairs: I) -> bool
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    for (k, v) in pairs {
        let key = k.as_ref();
        if v.as_ref().is_empty() {
            continue;
        }
        if CLOUD_ENV_KEYS.iter().any(|known| *known == key) {
            return true;
        }
    }
    false
}

/// L1/L2 pointer-chase samples in CPU-counter ticks (integer, never money).
pub fn probe_cache_latencies() -> Vec<u64> {
    const SAMPLES: usize = 8;
    const WORDS: usize = 32 * 1024; // 256 KiB of u64 — above typical L1
    let mut buf = vec![0u64; WORDS];
    let stride = 17usize;
    for i in 0..WORDS {
        buf[i] = ((i + stride) % WORDS) as u64;
    }
    let mut out = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        out.push(cache_chase(&buf));
    }
    out
}

fn cache_chase(buf: &[u64]) -> u64 {
    let n = buf.len();
    if n == 0 {
        return 0;
    }
    let start = read_ticks();
    let mut idx = 0u64;
    // Bound the walk so unit tests stay cheap on Windows.
    let steps = n.min(4096);
    for _ in 0..steps {
        idx = buf[idx as usize % n];
    }
    std::hint::black_box(idx);
    read_ticks().saturating_sub(start)
}

fn read_ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            core::arch::x86_64::_mm_lfence();
            let t = core::arch::x86_64::_rdtsc();
            core::arch::x86_64::_mm_lfence();
            t
        }
    }
    #[cfg(target_arch = "x86")]
    {
        unsafe { core::arch::x86::_rdtsc() }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let t: u64;
        unsafe {
            core::arch::asm!("mrs {t}, cntvct_el0", t = out(reg) t);
        }
        t
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        std::time::Instant::now().elapsed().as_nanos() as u64
    }
}

/// Too-clean timings (zero variance / identical samples) look like a VM.
pub fn cache_looks_like_emulator(samples: &[u64]) -> bool {
    if samples.len() < 4 {
        return true;
    }
    if samples.windows(2).all(|w| w[0] == w[1]) {
        return true;
    }
    integer_variance(samples) == 0
}

fn integer_variance(samples: &[u64]) -> u64 {
    if samples.len() < 2 {
        return 0;
    }
    let n = samples.len() as u64;
    let mean = samples.iter().copied().sum::<u64>() / n;
    let acc: u64 = samples
        .iter()
        .map(|x| {
            let d = x.abs_diff(mean);
            d.saturating_mul(d)
        })
        .sum();
    acc / (n - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_observation_is_critical() {
        let err = enforce_observation(&HostObservation::x86_emulator()).unwrap_err();
        assert!(err.is_critical());
        assert_eq!(err, ShieldError::PcArchitecture);
    }

    #[test]
    fn cloud_pairs_fail_closed() {
        assert!(cloud_environment_from_pairs([("AWS_REGION", "us-east-1")]));
        assert!(cloud_environment_from_pairs([("KUBERNETES_SERVICE_HOST", "10.0.0.1")]));
        assert!(!cloud_environment_from_pairs([("PATH", "/usr/bin")]));
        assert!(!cloud_environment_from_pairs([("AWS_REGION", "")]));
    }

    #[test]
    fn clean_cache_samples_look_like_emulator() {
        assert!(cache_looks_like_emulator(&[10, 10, 10, 10]));
        assert!(cache_looks_like_emulator(&[1, 2]));
        assert!(!cache_looks_like_emulator(&[100, 140, 90, 210, 130, 180, 70, 160]));
    }

    #[test]
    fn this_windows_x86_host_is_rejected() {
        if HostArch::detect().is_pc_class() {
            let err = enforce_real_mobile().unwrap_err();
            assert!(err.is_critical());
            assert_eq!(err, ShieldError::PcArchitecture);
        }
    }
}
