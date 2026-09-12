//! P2P errors. Fail closed: a malformed frame is treated as a bot.

use std::io;
use thiserror::Error;

use crate::anti_bot::SecurityError;
use crate::crypto::lattice::CryptoError;
use crate::dag::DagError;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("peer sent an invalid or oversized frame")]
    BadFrame,
    #[error("handshake rejected: {0}")]
    Handshake(&'static str),
    #[error("anti-bot: {0}")]
    AntiBot(#[from] SecurityError),
    #[error("lattice crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("unknown peer (no live TCP session) — UDP inventory dropped")]
    UnauthenticatedDatagram,
    #[error("routing table refused the contact (eclipse / subnet cap)")]
    RoutingDenied,
    #[error("payload hash does not match the advertised message id")]
    HashMismatch,
    #[error("dag: {0}")]
    Dag(#[from] DagError),
}

impl NetworkError {
    pub fn is_fatal_socket(&self) -> bool {
        matches!(
            self,
            NetworkError::Handshake(_)
                | NetworkError::AntiBot(_)
                | NetworkError::BadFrame
                | NetworkError::UnauthenticatedDatagram
        )
    }
}
