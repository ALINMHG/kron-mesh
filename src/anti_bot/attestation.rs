//! Hardware attestation inspired by Android Keystore / Apple DeviceCheck / TEE quotes.
//!
//! This PoC does **not** talk to a real TEE. It models the *measurements* those
//! systems expose (probe jitter, cache-chase latency, clock skew, core count)
//! and a lattice-signed quote over them. Validators decide with a pure function
//! of the quote so aBFT nodes cannot fork on observer-local clocks.

use thiserror::Error;

use crate::crypto::hash::sha256_parts;
use crate::anti_bot::profile::{DeviceClass, HardwareProfile};
use crate::types::{Address, Hash};

const MIN_SAMPLES: usize = 4;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecurityError {
    #[error("attestation quote or encoding is invalid")]
    AttestationInvalid,
    #[error("timing fingerprint matches a VM or emulator (zero jitter / too perfect)")]
    VirtualMachineFingerprint,
    #[error("claimed class is incompatible with core count or probe speed")]
    EmulatorTiming,
    #[error("endpoint sits in a datacenter prefix or rack-scale adjacency cluster")]
    DatacenterCluster,
    #[error("submission cadence is impossible for the declared hardware class")]
    ImpossibleCadence,
    #[error("identity is quarantined after repeated bot/ASIC flags")]
    Quarantined,
    #[error("too many distinct miners from the same IP subnet (Sybil)")]
    SybilSubnet,
    #[error("mining is phone-only; this hardware class is not admitted")]
    NotPhoneMiner,
}

/// 0–1000 authenticity score plus Proof-of-Adjacency hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceScore {
    pub authenticity: u16,
    pub residential: u16,
    pub extra_difficulty_bits: u32,
    pub flags: Vec<&'static str>,
}

impl DeviceScore {
    pub fn is_strong(&self) -> bool {
        self.authenticity >= 400 && self.residential >= 250
    }
}

/// Signed-in-substance hardware measurements (covered by the mining solution
/// lattice signature). Think of `quote` as a mock TEE attestation digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAttestation {
    pub miner: Address,
    pub class: DeviceClass,
    pub logical_cores: u16,
    pub advertised_mhz: u32,
    /// Nanoseconds for a fixed lattice mat-vec probe (repeated).
    pub lattice_probe_ns: Vec<u64>,
    /// Cache-line chase latencies. Hypervisors often flatten this distribution.
    pub cache_probe_ns: Vec<u64>,
    /// Apparent ppm error of the device clock vs. monotonic time.
    pub clock_skew_ppm: Vec<i32>,
    pub ipv4: [u8; 4],
    /// RTTs (ms) to protocol beacons. Sub-millisecond clusters scream "same rack".
    pub adjacency_rtt_ms: Vec<u16>,
    pub mining_duration_ns: u64,
    pub quote: Hash,
}

impl DeviceAttestation {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.miner);
        out.push(self.class as u8);
        out.extend_from_slice(&self.logical_cores.to_le_bytes());
        out.extend_from_slice(&self.advertised_mhz.to_le_bytes());
        push_u64s(&mut out, &self.lattice_probe_ns);
        push_u64s(&mut out, &self.cache_probe_ns);
        out.push(self.clock_skew_ppm.len() as u8);
        for s in &self.clock_skew_ppm {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out.extend_from_slice(&self.ipv4);
        out.push(self.adjacency_rtt_ms.len() as u8);
        for r in &self.adjacency_rtt_ms {
            out.extend_from_slice(&r.to_le_bytes());
        }
        out.extend_from_slice(&self.mining_duration_ns.to_le_bytes());
        out
    }

    pub fn seal_quote(&mut self) {
        self.quote = sha256_parts(&[b"tee-quote-v1", &self.canonical_bytes()]);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes();
        out.extend_from_slice(&self.quote);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), SecurityError> {
        if bytes.len() < 32 + 1 + 2 + 4 + 1 {
            return Err(SecurityError::AttestationInvalid);
        }
        let mut off = 0;
        let mut miner = [0u8; 32];
        miner.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let class = DeviceClass::from_u8(bytes[off]).ok_or(SecurityError::AttestationInvalid)?;
        off += 1;
        let logical_cores = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let advertised_mhz = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let (lattice_probe_ns, n1) = read_u64s(&bytes[off..])?;
        off += n1;
        let (cache_probe_ns, n2) = read_u64s(&bytes[off..])?;
        off += n2;
        if bytes.len() < off + 1 {
            return Err(SecurityError::AttestationInvalid);
        }
        let nskew = bytes[off] as usize;
        off += 1;
        if bytes.len() < off + nskew * 4 + 4 + 1 {
            return Err(SecurityError::AttestationInvalid);
        }
        let mut clock_skew_ppm = Vec::with_capacity(nskew);
        for _ in 0..nskew {
            clock_skew_ppm.push(i32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()));
            off += 4;
        }
        let mut ipv4 = [0u8; 4];
        ipv4.copy_from_slice(&bytes[off..off + 4]);
        off += 4;
        let nrtt = bytes[off] as usize;
        off += 1;
        if bytes.len() < off + nrtt * 2 + 8 + 32 {
            return Err(SecurityError::AttestationInvalid);
        }
        let mut adjacency_rtt_ms = Vec::with_capacity(nrtt);
        for _ in 0..nrtt {
            adjacency_rtt_ms.push(u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()));
            off += 2;
        }
        let mining_duration_ns = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let mut quote = [0u8; 32];
        quote.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        Ok((
            Self {
                miner,
                class,
                logical_cores,
                advertised_mhz,
                lattice_probe_ns,
                cache_probe_ns,
                clock_skew_ppm,
                ipv4,
                adjacency_rtt_ms,
                mining_duration_ns,
                quote,
            },
            off,
        ))
    }

    /// Class-consistent noisy measurements. Used by honest miners so a PC
    /// *simulating* an IoT shard still attests as that shard (production would
    /// replace this with a real TEE quote that cannot be forged).
    pub fn simulate_honest(
        profile: &HardwareProfile,
        miner: Address,
        ipv4: [u8; 4],
        mining_duration_ns: u64,
    ) -> Self {
        let seed = sha256_parts(&[&miner, &[profile.class as u8], &mining_duration_ns.to_le_bytes()]);
        let (cores, mhz, lat_base, cache_base, rtt_base) = match profile.class {
            DeviceClass::IotSensor => (1u16, 48u32, 180_000u64, 900u64, 85u16),
            DeviceClass::LegacyMobile => (4, 400, 70_000, 420, 45),
            DeviceClass::PersonalComputer => (8, 2500, 8_000, 120, 18),
        };
        let mut att = Self {
            miner,
            class: profile.class,
            logical_cores: cores,
            advertised_mhz: mhz,
            lattice_probe_ns: (0..6)
                .map(|i| jitter(&seed, i, lat_base, lat_base / 8))
                .collect(),
            cache_probe_ns: (0..6)
                .map(|i| jitter(&seed, 16 + i, cache_base, cache_base / 5 + 1))
                .collect(),
            clock_skew_ppm: (0..4)
                .map(|i| (jitter(&seed, 32 + i, 50, 20) as i32) - 40 + (i as i32) * 3)
                .collect(),
            ipv4,
            adjacency_rtt_ms: (0..4)
                .map(|i| {
                    let j = jitter(&seed, 48 + i, rtt_base as u64, 12);
                    j.min(u16::MAX as u64) as u16
                })
                .collect(),
            mining_duration_ns: mining_duration_ns.max(25_000),
            quote: [0u8; 32],
        };
        att.seal_quote();
        att
    }

    /// Perfect timings, huge core count, rack RTTs, AWS-like prefix — a VM farm.
    pub fn datacenter_bot(miner: Address, class: DeviceClass, ipv4: [u8; 4]) -> Self {
        let mut att = Self {
            miner,
            class,
            logical_cores: 64,
            advertised_mhz: 3200,
            lattice_probe_ns: vec![80, 80, 80, 80, 80, 80],
            cache_probe_ns: vec![40, 40, 40, 40],
            clock_skew_ppm: vec![0, 0, 0, 0],
            ipv4,
            adjacency_rtt_ms: vec![1, 1, 1, 1],
            mining_duration_ns: 500,
            quote: [0u8; 32],
        };
        att.seal_quote();
        att
    }
}

/// Map a miner address to a stable `NodeId` for paced-mining bookkeeping.
pub fn miner_node_id(addr: &Address) -> crate::types::NodeId {
    u32::from_le_bytes(addr[0..4].try_into().unwrap())
}

pub fn residential_ipv4(addr: &Address) -> [u8; 4] {
    // 86.0.0.0/8 is treated as residential ISP space in the conceptual filter.
    [86, addr[5] | 1, addr[6], addr[7]]
}

pub fn datacenter_ipv4(addr: &Address) -> [u8; 4] {
    [3, addr[5], addr[6], addr[7]]
}

fn jitter(seed: &Hash, idx: u32, base: u64, spread: u64) -> u64 {
    let h = sha256_parts(&[seed, &idx.to_le_bytes(), b"jitter"]);
    let r = u64::from_le_bytes(h[0..8].try_into().unwrap());
    let span = spread.max(1).saturating_mul(2).saturating_add(1);
    base.saturating_add(r % span).saturating_sub(spread)
}

fn push_u64s(out: &mut Vec<u8>, xs: &[u64]) {
    out.push(xs.len() as u8);
    for x in xs {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

fn read_u64s(bytes: &[u8]) -> Result<(Vec<u64>, usize), SecurityError> {
    if bytes.is_empty() {
        return Err(SecurityError::AttestationInvalid);
    }
    let n = bytes[0] as usize;
    let need = 1 + n * 8;
    if bytes.len() < need {
        return Err(SecurityError::AttestationInvalid);
    }
    let mut v = Vec::with_capacity(n);
    let mut off = 1;
    for _ in 0..n {
        v.push(u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()));
        off += 8;
    }
    Ok((v, off))
}

fn mean_u64(xs: &[u64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().map(|x| *x as f64).sum::<f64>() / xs.len() as f64
}

fn variance_u64(xs: &[u64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean_u64(xs);
    xs.iter()
        .map(|x| {
            let d = *x as f64 - m;
            d * d
        })
        .sum::<f64>()
        / (xs.len() as f64)
}

/// Conceptual public-cloud unicast space. Aggressive by design.
pub fn is_datacenter_ipv4(ip: [u8; 4]) -> bool {
    matches!(ip[0], 3 | 13 | 18 | 34 | 35 | 52 | 54 | 104)
}

/// Verify a hardware quote. Fail closed on VM / emulator / DC fingerprints.
pub fn verify_hardware_authenticity(
    attestation: &DeviceAttestation,
) -> Result<DeviceScore, SecurityError> {
    let expected = sha256_parts(&[b"tee-quote-v1", &attestation.canonical_bytes()]);
    if expected != attestation.quote {
        return Err(SecurityError::AttestationInvalid);
    }
    if attestation.lattice_probe_ns.len() < MIN_SAMPLES
        || attestation.cache_probe_ns.len() < MIN_SAMPLES
        || attestation.clock_skew_ppm.len() < 2
        || attestation.adjacency_rtt_ms.len() < 2
    {
        return Err(SecurityError::AttestationInvalid);
    }

    let lat_var = variance_u64(&attestation.lattice_probe_ns);
    let cache_var = variance_u64(&attestation.cache_probe_ns);
    if lat_var < 1.0 || cache_var < 1.0 {
        return Err(SecurityError::VirtualMachineFingerprint);
    }
    if attestation.clock_skew_ppm.iter().all(|s| *s == 0) {
        return Err(SecurityError::VirtualMachineFingerprint);
    }

    let max_cores = match attestation.class {
        DeviceClass::IotSensor => 2,
        DeviceClass::LegacyMobile => 8,
        DeviceClass::PersonalComputer => 32,
    };
    if attestation.logical_cores == 0 || attestation.logical_cores > max_cores {
        return Err(SecurityError::EmulatorTiming);
    }

    let lat_mean = mean_u64(&attestation.lattice_probe_ns);
    let min_probe = match attestation.class {
        DeviceClass::IotSensor => 20_000.0,
        DeviceClass::LegacyMobile => 8_000.0,
        DeviceClass::PersonalComputer => 400.0,
    };
    if lat_mean < min_probe {
        return Err(SecurityError::EmulatorTiming);
    }

    if is_datacenter_ipv4(attestation.ipv4) {
        return Err(SecurityError::DatacenterCluster);
    }
    if attestation
        .adjacency_rtt_ms
        .iter()
        .all(|r| *r <= 2)
        && attestation.adjacency_rtt_ms.len() >= MIN_SAMPLES
    {
        return Err(SecurityError::DatacenterCluster);
    }

    if attestation.mining_duration_ns < min_duration_ns(attestation.class) {
        return Err(SecurityError::ImpossibleCadence);
    }

    let mut flags = Vec::new();
    let mut authenticity: u16 = 850;
    let mut residential: u16 = 800;
    if lat_var < 500.0 {
        authenticity = authenticity.saturating_sub(120);
        flags.push("low-jitter");
    }
    let rtt_mean = attestation.adjacency_rtt_ms.iter().map(|r| *r as u32).sum::<u32>()
        / attestation.adjacency_rtt_ms.len() as u32;
    if rtt_mean < 8 {
        residential = residential.saturating_sub(200);
        flags.push("low-rtt");
    }
    if attestation.ipv4[0] == 86 || attestation.ipv4[0] == 92 || attestation.ipv4[0] == 188 {
        flags.push("residential-prefix");
    }

    Ok(DeviceScore {
        authenticity,
        residential,
        extra_difficulty_bits: 0,
        flags,
    })
}

pub fn min_duration_ns(class: DeviceClass) -> u64 {
    match class {
        DeviceClass::IotSensor => 20_000,
        DeviceClass::LegacyMobile => 15_000,
        DeviceClass::PersonalComputer => 8_000,
    }
}

pub fn min_cadence(class: DeviceClass) -> std::time::Duration {
    std::time::Duration::from_nanos(min_duration_ns(class))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_phone_attestation_passes() {
        let miner = [7u8; 32];
        let att = DeviceAttestation::simulate_honest(
            &HardwareProfile::legacy_mobile(),
            miner,
            residential_ipv4(&miner),
            80_000,
        );
        let score = verify_hardware_authenticity(&att).unwrap();
        assert!(score.is_strong());
    }

    #[test]
    fn vm_farm_is_rejected() {
        let miner = [9u8; 32];
        let att = DeviceAttestation::datacenter_bot(miner, DeviceClass::LegacyMobile, datacenter_ipv4(&miner));
        let err = verify_hardware_authenticity(&att).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::VirtualMachineFingerprint
                | SecurityError::EmulatorTiming
                | SecurityError::DatacenterCluster
                | SecurityError::ImpossibleCadence
        ));
    }
}
