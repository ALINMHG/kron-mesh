//! Paced mining / inverse-PoW: punish bursts that a claimed device cannot sustain.
//!
//! Consistency over epochs is rewarded; a "legacy phone" that suddenly emits
//! server-class cadences is flagged Bot/ASIC and quarantined.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use crate::anti_bot::attestation::{min_cadence, miner_node_id, SecurityError};
use crate::anti_bot::profile::DeviceClass;
use crate::types::{Address, NodeId};

const HISTORY: usize = 8;
const QUARANTINE_EPOCHS: u64 = 8;

#[derive(Clone, Debug)]
struct CadenceRecord {
    class: DeviceClass,
    samples: VecDeque<Duration>,
    pub pace_bump: u32,
    pub quarantined_until: u64,
    pub bot_flags: u32,
}

impl CadenceRecord {
    fn new(class: DeviceClass) -> Self {
        Self {
            class,
            samples: VecDeque::new(),
            pace_bump: 0,
            quarantined_until: 0,
            bot_flags: 0,
        }
    }
}

/// Per-identity submission clock. Updated only from *finalized* aBFT batches
/// so every honest validator sees the same history.
#[derive(Clone, Debug, Default)]
pub struct PacedVerifier {
    by_node: BTreeMap<NodeId, Address>,
    by_miner: BTreeMap<Address, CadenceRecord>,
}

impl PacedVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_quarantined(&self, miner: &Address, epoch: u64) -> bool {
        self.by_miner
            .get(miner)
            .is_some_and(|r| r.quarantined_until > epoch)
    }

    pub fn pace_bump(&self, miner: &Address) -> u32 {
        self.by_miner.get(miner).map(|r| r.pace_bump).unwrap_or(0)
    }

    pub fn bot_flags(&self, miner: &Address) -> u32 {
        self.by_miner.get(miner).map(|r| r.bot_flags).unwrap_or(0)
    }

    /// User-facing entry: `NodeId` plus wall/logical duration of the last job.
    pub fn validate_mining_cadence(&mut self, node_id: NodeId, submission_time: Duration) -> bool {
        let Some(addr) = self.by_node.get(&node_id).copied() else {
            return submission_time >= Duration::from_micros(8);
        };
        let class = self
            .by_miner
            .get(&addr)
            .map(|r| r.class)
            .unwrap_or(DeviceClass::PersonalComputer);
        self.check(&addr, class, submission_time, 0, false)
    }

    pub fn preview(
        &self,
        miner: &Address,
        class: DeviceClass,
        submission_time: Duration,
        epoch: u64,
    ) -> Result<(), SecurityError> {
        if self.is_quarantined(miner, epoch) {
            return Err(SecurityError::Quarantined);
        }
        if submission_time < min_cadence(class) {
            return Err(SecurityError::ImpossibleCadence);
        }
        if let Some(rec) = self.by_miner.get(miner) {
            if rec.samples.len() >= 3 {
                let identical = rec.samples.iter().take(3).all(|d| *d == submission_time);
                if identical {
                    return Err(SecurityError::VirtualMachineFingerprint);
                }
                let ema: u128 = rec.samples.iter().map(|d| d.as_nanos()).sum::<u128>()
                    / rec.samples.len() as u128;
                if ema > 0 && submission_time.as_nanos() * 10 < ema {
                    return Err(SecurityError::ImpossibleCadence);
                }
            }
        }
        Ok(())
    }

    pub fn commit_sample(
        &mut self,
        miner: Address,
        class: DeviceClass,
        submission_time: Duration,
        epoch: u64,
        violated: bool,
    ) {
        self.check(&miner, class, submission_time, epoch, true);
        let rec = self.by_miner.get_mut(&miner).expect("inserted");
        if violated {
            rec.pace_bump = rec.pace_bump.saturating_add(1).saturating_mul(2).min(12);
            rec.bot_flags = rec.bot_flags.saturating_add(1);
            if rec.pace_bump >= 4 || rec.bot_flags >= 2 {
                rec.quarantined_until = epoch.saturating_add(QUARANTINE_EPOCHS);
            }
        } else if rec.pace_bump > 0 {
            rec.pace_bump -= 1;
        }
    }

    fn check(
        &mut self,
        miner: &Address,
        class: DeviceClass,
        submission_time: Duration,
        epoch: u64,
        record: bool,
    ) -> bool {
        let id = miner_node_id(miner);
        self.by_node.insert(id, *miner);
        let rec = self
            .by_miner
            .entry(*miner)
            .or_insert_with(|| CadenceRecord::new(class));
        rec.class = class;
        if rec.quarantined_until > epoch {
            return false;
        }
        let ok = submission_time >= min_cadence(class);
        if record {
            rec.samples.push_back(submission_time);
            if rec.samples.len() > HISTORY {
                rec.samples.pop_front();
            }
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_burst_is_flagged() {
        let mut paced = PacedVerifier::new();
        let miner = [3u8; 32];
        let slow = Duration::from_millis(5);
        paced.commit_sample(miner, DeviceClass::LegacyMobile, slow, 0, false);
        paced.commit_sample(miner, DeviceClass::LegacyMobile, slow, 1, false);
        paced.commit_sample(miner, DeviceClass::LegacyMobile, slow, 2, false);
        let err = paced
            .preview(&miner, DeviceClass::LegacyMobile, Duration::from_nanos(500), 3)
            .unwrap_err();
        assert_eq!(err, SecurityError::ImpossibleCadence);
    }
}
