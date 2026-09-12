//! Device class used by the mesh handshake and hardware attestation.
//!
//! This is not a block-sealing miner profile. Phones attach DAG vertices;
//! the PC is a gateway. `LegacyMobile` is the phone class (`--phone`).

/// Declared device class, bound into the handshake HELLO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DeviceClass {
    /// MCU / battery sensor.
    IotSensor = 0,
    /// Phone / Termux. Only this class may attach as a mesh miner.
    LegacyMobile = 1,
    /// Desktop / laptop gateway (does not mint).
    PersonalComputer = 2,
}

impl DeviceClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::IotSensor),
            1 => Some(Self::LegacyMobile),
            2 => Some(Self::PersonalComputer),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::IotSensor => "iot-sensor",
            Self::LegacyMobile => "legacy-mobile",
            Self::PersonalComputer => "pc",
        }
    }

    /// Phone-only mesh work. A future Android app should replace simulated
    /// quotes with SafetyNet / Play Integrity / TEE.
    pub fn is_phone_miner(self) -> bool {
        matches!(self, Self::LegacyMobile)
    }
}

/// Self-reported capability envelope used to simulate a hardware quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareProfile {
    pub class: DeviceClass,
    pub ram_kib: u32,
    pub estimated_mhz: u32,
    pub battery_aware: bool,
}

impl HardwareProfile {
    pub fn iot_sensor() -> Self {
        Self {
            class: DeviceClass::IotSensor,
            ram_kib: 32,
            estimated_mhz: 48,
            battery_aware: true,
        }
    }

    pub fn legacy_mobile() -> Self {
        Self {
            class: DeviceClass::LegacyMobile,
            ram_kib: 256,
            estimated_mhz: 400,
            battery_aware: true,
        }
    }

    pub fn smartphone() -> Self {
        Self::legacy_mobile()
    }

    pub fn personal_computer() -> Self {
        Self {
            class: DeviceClass::PersonalComputer,
            ram_kib: 4096,
            estimated_mhz: 2500,
            battery_aware: false,
        }
    }

    pub fn detect() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if cfg!(target_pointer_width = "32") && cores <= 2 {
            Self::legacy_mobile()
        } else if cores <= 1 {
            Self::iot_sensor()
        } else if cores <= 4 {
            Self::legacy_mobile()
        } else {
            Self::personal_computer()
        }
    }
}
