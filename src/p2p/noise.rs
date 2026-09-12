//! Noise XX over TCP. Existing NBCH frames travel inside the Noise payload
//! so gossip is not plaintext. Shared prologue is `kron-p2p-noise-xx-v1`.
//! Dilithium identity is bound afterwards by signing the handshake hash.

use std::io::{Read, Write};
use std::net::TcpStream;

use snow::{Builder, TransportState};

use crate::p2p::error::NetworkError;
use crate::p2p::frame::{MAGIC, MAX_FRAME, PROTO_VERSION};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"kron-p2p-noise-xx-v1";
/// Noise messages are capped at 65535 including the AEAD tag.
const NOISE_PLAIN_CHUNK: usize = 65_000;

pub struct NoiseSession {
    stream: TcpStream,
    transport: TransportState,
    pub handshake_hash: [u8; 32],
}

impl NoiseSession {
    pub fn handshake(mut stream: TcpStream, initiator: bool) -> Result<Self, NetworkError> {
        crate::p2p::frame::configure_socket(&mut stream)?;
        let params: snow::params::NoiseParams = PATTERN
            .parse()
            .map_err(|_| NetworkError::Handshake("noise params"))?;
        let builder = Builder::new(params);
        let kp = builder
            .generate_keypair()
            .map_err(|_| NetworkError::Handshake("noise keygen"))?;
        let mut hs = if initiator {
            builder
                .local_private_key(&kp.private)
                .prologue(PROLOGUE)
                .build_initiator()
        } else {
            builder
                .local_private_key(&kp.private)
                .prologue(PROLOGUE)
                .build_responder()
        }
        .map_err(|_| NetworkError::Handshake("noise build"))?;

        let mut buf = vec![0u8; 2048];
        if initiator {
            let n = hs
                .write_message(&[], &mut buf)
                .map_err(|_| NetworkError::Handshake("noise write e"))?;
            write_raw(&mut stream, &buf[..n])?;
            let incoming = read_raw(&mut stream)?;
            let _ = hs
                .read_message(&incoming, &mut buf)
                .map_err(|_| NetworkError::Handshake("noise read ees"))?;
            let n = hs
                .write_message(&[], &mut buf)
                .map_err(|_| NetworkError::Handshake("noise write s"))?;
            write_raw(&mut stream, &buf[..n])?;
        } else {
            let incoming = read_raw(&mut stream)?;
            let _ = hs
                .read_message(&incoming, &mut buf)
                .map_err(|_| NetworkError::Handshake("noise read e"))?;
            let n = hs
                .write_message(&[], &mut buf)
                .map_err(|_| NetworkError::Handshake("noise write ees"))?;
            write_raw(&mut stream, &buf[..n])?;
            let incoming = read_raw(&mut stream)?;
            let _ = hs
                .read_message(&incoming, &mut buf)
                .map_err(|_| NetworkError::Handshake("noise read s"))?;
        }

        let hh = hs.get_handshake_hash();
        let mut handshake_hash = [0u8; 32];
        let n = hh.len().min(32);
        handshake_hash[..n].copy_from_slice(&hh[..n]);
        let transport = hs
            .into_transport_mode()
            .map_err(|_| NetworkError::Handshake("noise transport"))?;
        Ok(Self {
            stream,
            transport,
            handshake_hash,
        })
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn set_read_timeout(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    pub fn write_frame(&mut self, kind: u8, payload: &[u8]) -> Result<(), NetworkError> {
        if payload.len() > MAX_FRAME as usize {
            return Err(NetworkError::BadFrame);
        }
        let mut inner = Vec::with_capacity(10 + payload.len());
        inner.extend_from_slice(MAGIC);
        inner.push(PROTO_VERSION);
        inner.push(kind);
        inner.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        inner.extend_from_slice(payload);
        self.write_plain(&inner)
    }

    pub fn read_frame(&mut self) -> Result<(u8, Vec<u8>), NetworkError> {
        let inner = self.read_plain()?;
        if inner.len() < 10 {
            return Err(NetworkError::BadFrame);
        }
        if inner[0..4] != MAGIC[..] || inner[4] != PROTO_VERSION {
            return Err(NetworkError::BadFrame);
        }
        let kind = inner[5];
        let len = u32::from_le_bytes(inner[6..10].try_into().unwrap()) as usize;
        if len > MAX_FRAME as usize || inner.len() != 10 + len {
            return Err(NetworkError::BadFrame);
        }
        Ok((kind, inner[10..].to_vec()))
    }

    fn write_plain(&mut self, plaintext: &[u8]) -> Result<(), NetworkError> {
        let chunks: Vec<&[u8]> = plaintext.chunks(NOISE_PLAIN_CHUNK).collect();
        let nchunks = chunks.len() as u32;
        write_raw(&mut self.stream, &nchunks.to_le_bytes())?;
        for chunk in chunks {
            let mut out = vec![0u8; chunk.len() + 16];
            let n = self
                .transport
                .write_message(chunk, &mut out)
                .map_err(|_| NetworkError::Handshake("noise encrypt"))?;
            write_raw(&mut self.stream, &out[..n])?;
        }
        self.stream.flush()?;
        Ok(())
    }

    fn read_plain(&mut self) -> Result<Vec<u8>, NetworkError> {
        let hdr = read_raw(&mut self.stream)?;
        if hdr.len() != 4 {
            return Err(NetworkError::BadFrame);
        }
        let nchunks = u32::from_le_bytes(hdr.try_into().unwrap()) as usize;
        if nchunks == 0 || nchunks > 16 {
            return Err(NetworkError::BadFrame);
        }
        let mut plain = Vec::new();
        for _ in 0..nchunks {
            let cipher = read_raw(&mut self.stream)?;
            let mut out = vec![0u8; cipher.len()];
            let n = self
                .transport
                .read_message(&cipher, &mut out)
                .map_err(|_| NetworkError::Handshake("noise decrypt"))?;
            plain.extend_from_slice(&out[..n]);
            if plain.len() > MAX_FRAME as usize + 10 {
                return Err(NetworkError::BadFrame);
            }
        }
        Ok(plain)
    }
}

fn write_raw(stream: &mut TcpStream, data: &[u8]) -> Result<(), NetworkError> {
    if data.len() > 70_000 {
        return Err(NetworkError::BadFrame);
    }
    stream.write_all(&(data.len() as u32).to_le_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn read_raw(stream: &mut TcpStream) -> Result<Vec<u8>, NetworkError> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let n = u32::from_le_bytes(hdr) as usize;
    if n > 70_000 {
        return Err(NetworkError::BadFrame);
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}
