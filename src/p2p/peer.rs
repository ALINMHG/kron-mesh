//! Peer identity and connection state.

use std::net::SocketAddr;
use std::time::Instant;

use crate::anti_bot::DeviceScore;
use crate::crypto::lattice::LatticePublicKey;
use crate::anti_bot::profile::DeviceClass;
use crate::p2p::overlay::NodeOverlayId;
use crate::types::Address;

/// Gateway (PC) stays in a separate overlay from phones so a phone cannot
/// be eclipsed by a cloud of fake IoT identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerRole {
    CoreValidator = 0,
    EdgeMiner = 1,
}

impl PeerRole {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::CoreValidator),
            1 => Some(Self::EdgeMiner),
            _ => None,
        }
    }

    pub fn from_class(class: DeviceClass) -> Self {
        match class {
            DeviceClass::PersonalComputer => Self::CoreValidator,
            DeviceClass::IotSensor | DeviceClass::LegacyMobile => Self::EdgeMiner,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    Live,
    Quarantined,
    Dead,
}

/// Live (or recently seen) overlay contact.
#[derive(Clone, Debug)]
pub struct Peer {
    pub id: Address,
    /// Mesh ID (ULA). Routing looks up this, not the LAN `192.168` address.
    pub overlay_id: NodeOverlayId,
    pub public_key: LatticePublicKey,
    pub addr: SocketAddr,
    pub role: PeerRole,
    pub class: DeviceClass,
    pub reputation: i32,
    pub state: ConnectionState,
    pub last_seen: Instant,
}

/// Handshake result returned to the caller after lattice + attestation checks.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer: Peer,
    pub score: DeviceScore,
}

pub fn ipv4_octets(addr: SocketAddr) -> Option<[u8; 4]> {
    match addr {
        SocketAddr::V4(v) => Some(v.ip().octets()),
        SocketAddr::V6(_) => None,
    }
}

pub fn slash24(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes([ip[0], ip[1], ip[2], 0])
}

pub fn is_loopback(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v) => v.ip().is_loopback(),
        SocketAddr::V6(v) => v.ip().is_loopback(),
    }
}
