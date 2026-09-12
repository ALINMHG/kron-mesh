//! Post-quantum handshake over Noise XX. Dilithium identity + hardware attestation.

use rand::RngCore;

use crate::anti_bot::attestation::is_datacenter_ipv4;
use crate::anti_bot::{verify_hardware_authenticity, DeviceAttestation, DeviceScore};
use crate::crypto::hash::sha256_parts;
use crate::crypto::lattice::{LatticeKeyPair, LatticePublicKey, LatticeSignature};
use crate::anti_bot::profile::{DeviceClass, HardwareProfile};
use crate::p2p::error::NetworkError;
use crate::p2p::frame::{KIND_ACK, KIND_AUTH, KIND_CHALLENGE, KIND_HELLO, KIND_REJECT};
use crate::p2p::noise::NoiseSession;
use crate::p2p::overlay::NodeOverlayId;
use crate::p2p::peer::{ipv4_octets, is_loopback, ConnectionState, Peer, PeerInfo, PeerRole};
use crate::types::Address;

/// Local identity presented during the handshake.
#[derive(Clone)]
pub struct HandshakeConfig {
    pub keys: LatticeKeyPair,
    pub role: PeerRole,
    pub class: DeviceClass,
    pub attestation: DeviceAttestation,
    pub banned_ipv4: Vec<[u8; 4]>,
    pub min_authenticity: u16,
    pub initiator: bool,
}

impl HandshakeConfig {
    pub fn peer_id(&self) -> Address {
        self.keys.public.address()
    }

    pub fn overlay_id(&self) -> NodeOverlayId {
        NodeOverlayId::from_pubkey(&self.keys.public)
    }

    pub fn honest(
        keys: LatticeKeyPair,
        role: PeerRole,
        class: DeviceClass,
        initiator: bool,
    ) -> Self {
        let id = keys.public.address();
        let profile = match class {
            DeviceClass::IotSensor => HardwareProfile::iot_sensor(),
            DeviceClass::LegacyMobile => HardwareProfile::legacy_mobile(),
            DeviceClass::PersonalComputer => HardwareProfile::personal_computer(),
        };
        let attestation = DeviceAttestation::simulate_honest(
            &profile,
            id,
            crate::anti_bot::residential_ipv4(&id),
            80_000,
        );
        Self {
            keys,
            role,
            class,
            attestation,
            banned_ipv4: Vec::new(),
            min_authenticity: 400,
            initiator,
        }
    }
}

/// Run Dilithium auth on an already-Noise-wrapped TCP session.
///
/// Steps:
/// 1. Instant TCP drop if the socket IP is banned / non-loopback datacenter.
/// 2. Exchange HELLO (Dilithium pubkey + TEE-style attestation) inside Noise.
/// 3. Responder issues a random nonce; initiator signs the transcript
///    (nonces ‖ ids ‖ Noise handshake hash).
/// 4. Mutual ACK. HELLO role is Gateway (PC) or Phone (edge).
pub fn perform_secure_handshake(
    session: &mut NoiseSession,
    local: &HandshakeConfig,
) -> Result<PeerInfo, NetworkError> {
    let remote_addr = session.peer_addr()?;
    reject_socket(remote_addr, local)?;

    if local.initiator {
        initiator_flow(session, local)
    } else {
        responder_flow(session, local)
    }
}

fn reject_socket(
    remote_addr: std::net::SocketAddr,
    local: &HandshakeConfig,
) -> Result<(), NetworkError> {
    if let Some(ip) = ipv4_octets(remote_addr) {
        if local.banned_ipv4.iter().any(|b| *b == ip) {
            return Err(NetworkError::Handshake("banned ip"));
        }
        if !is_loopback(remote_addr) && is_datacenter_ipv4(ip) {
            return Err(NetworkError::Handshake("datacenter ip"));
        }
    }
    Ok(())
}

fn initiator_flow(
    session: &mut NoiseSession,
    local: &HandshakeConfig,
) -> Result<PeerInfo, NetworkError> {
    let mut client_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_nonce);
    session.write_frame(KIND_HELLO, &encode_hello(local, &client_nonce))?;

    let (kind, payload) = session.read_frame()?;
    if kind == KIND_REJECT {
        return Err(NetworkError::Handshake("remote rejected hello"));
    }
    if kind != KIND_CHALLENGE {
        return Err(NetworkError::BadFrame);
    }
    let ch = decode_challenge(&payload)?;
    verify_attestation(&ch.attestation, &ch.pk, local.min_authenticity)?;

    let transcript = handshake_transcript(
        &client_nonce,
        &ch.server_nonce,
        &local.keys.public.address(),
        &ch.pk.address(),
        &session.handshake_hash,
    );
    let sig = local.keys.sign(&transcript)?;
    session.write_frame(KIND_AUTH, &sig.to_bytes())?;

    let (kind, payload) = session.read_frame()?;
    if kind != KIND_ACK {
        return Err(NetworkError::Handshake("missing ack"));
    }
    let ack_sig = LatticeSignature::from_bytes(&payload)?;
    if !ch.pk.verify(&transcript, &ack_sig) {
        return Err(NetworkError::Handshake("server Dilithium auth failed"));
    }
    let score = verify_hardware_authenticity(&ch.attestation)?;
    let role = ch.role;
    Ok(info_from(ch.pk, role, ch.class, session.peer_addr()?, score))
}

fn responder_flow(
    session: &mut NoiseSession,
    local: &HandshakeConfig,
) -> Result<PeerInfo, NetworkError> {
    let (kind, payload) = session.read_frame()?;
    if kind != KIND_HELLO {
        let _ = session.write_frame(KIND_REJECT, &[1]);
        return Err(NetworkError::Handshake("expected hello"));
    }
    let hello = decode_hello(&payload)?;
    if let Err(e) = verify_attestation(&hello.attestation, &hello.pk, local.min_authenticity) {
        let _ = session.write_frame(KIND_REJECT, &[2]);
        return Err(e);
    }

    let mut server_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut server_nonce);
    session.write_frame(KIND_CHALLENGE, &encode_challenge(local, &server_nonce))?;

    let (kind, payload) = session.read_frame()?;
    if kind != KIND_AUTH {
        let _ = session.write_frame(KIND_REJECT, &[3]);
        return Err(NetworkError::Handshake("expected auth"));
    }
    let sig = LatticeSignature::from_bytes(&payload)?;
    let transcript = handshake_transcript(
        &hello.client_nonce,
        &server_nonce,
        &hello.pk.address(),
        &local.keys.public.address(),
        &session.handshake_hash,
    );
    if !hello.pk.verify(&transcript, &sig) {
        let _ = session.write_frame(KIND_REJECT, &[4]);
        return Err(NetworkError::Handshake("client Dilithium auth failed"));
    }
    let ack = local.keys.sign(&transcript)?;
    session.write_frame(KIND_ACK, &ack.to_bytes())?;
    let score = verify_hardware_authenticity(&hello.attestation)?;
    let role = hello.role;
    Ok(info_from(
        hello.pk,
        role,
        hello.class,
        session.peer_addr()?,
        score,
    ))
}

fn verify_attestation(
    att: &DeviceAttestation,
    pk: &LatticePublicKey,
    min_authenticity: u16,
) -> Result<(), NetworkError> {
    if att.miner != pk.address() {
        return Err(NetworkError::Handshake("attestation/key mismatch"));
    }
    let score = verify_hardware_authenticity(att)?;
    if score.authenticity < min_authenticity {
        return Err(NetworkError::Handshake("weak hardware score"));
    }
    Ok(())
}

fn handshake_transcript(
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    client_id: &Address,
    server_id: &Address,
    noise_hash: &[u8; 32],
) -> [u8; 32] {
    sha256_parts(&[
        b"p2p-hs-v2",
        client_nonce,
        server_nonce,
        client_id,
        server_id,
        noise_hash,
    ])
}

fn encode_hello(local: &HandshakeConfig, client_nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(local.role as u8);
    out.push(local.class as u8);
    crate::p2p::frame::put_bytes(&mut out, &local.keys.public.to_bytes());
    crate::p2p::frame::put_bytes(&mut out, &local.attestation.to_bytes());
    out.extend_from_slice(client_nonce);
    out
}

struct HelloMsg {
    role: PeerRole,
    class: DeviceClass,
    pk: LatticePublicKey,
    attestation: DeviceAttestation,
    client_nonce: [u8; 32],
}

fn decode_hello(bytes: &[u8]) -> Result<HelloMsg, NetworkError> {
    if bytes.len() < 2 {
        return Err(NetworkError::BadFrame);
    }
    let role = PeerRole::from_u8(bytes[0]).ok_or(NetworkError::BadFrame)?;
    let class = DeviceClass::from_u8(bytes[1]).ok_or(NetworkError::BadFrame)?;
    let mut off = 2;
    let pk = crate::p2p::frame::take_bytes(bytes, &mut off)?;
    let att = crate::p2p::frame::take_bytes(bytes, &mut off)?;
    if bytes.len() < off + 32 {
        return Err(NetworkError::BadFrame);
    }
    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&bytes[off..off + 32]);
    Ok(HelloMsg {
        role,
        class,
        pk: LatticePublicKey::from_bytes(&pk)?,
        attestation: DeviceAttestation::from_bytes(&att)
            .map_err(|_| NetworkError::BadFrame)?
            .0,
        client_nonce,
    })
}

fn encode_challenge(local: &HandshakeConfig, server_nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(local.role as u8);
    out.push(local.class as u8);
    crate::p2p::frame::put_bytes(&mut out, &local.keys.public.to_bytes());
    crate::p2p::frame::put_bytes(&mut out, &local.attestation.to_bytes());
    out.extend_from_slice(server_nonce);
    out
}

struct ChallengeMsg {
    role: PeerRole,
    class: DeviceClass,
    pk: LatticePublicKey,
    attestation: DeviceAttestation,
    server_nonce: [u8; 32],
}

fn decode_challenge(bytes: &[u8]) -> Result<ChallengeMsg, NetworkError> {
    let hello = decode_hello(bytes)?;
    Ok(ChallengeMsg {
        role: hello.role,
        class: hello.class,
        pk: hello.pk,
        attestation: hello.attestation,
        server_nonce: hello.client_nonce,
    })
}

fn info_from(
    pk: LatticePublicKey,
    role: PeerRole,
    class: DeviceClass,
    addr: std::net::SocketAddr,
    score: DeviceScore,
) -> PeerInfo {
    PeerInfo {
        peer: Peer {
            id: pk.address(),
            overlay_id: NodeOverlayId::from_pubkey(&pk),
            public_key: pk,
            addr,
            role,
            class,
            reputation: score.authenticity as i32,
            state: ConnectionState::Live,
            last_seen: std::time::Instant::now(),
        },
        score,
    }
}
