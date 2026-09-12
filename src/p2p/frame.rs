//! Length-prefixed NBCH frames. Hard cap stops TCP/UDP memory bombs.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::p2p::error::NetworkError;

pub const MAGIC: &[u8; 4] = b"NBCH";
pub const PROTO_VERSION: u8 = 1;
/// Edge devices never accept a frame larger than this (256 KiB).
pub const MAX_FRAME: u32 = 256 * 1024;

pub const KIND_HELLO: u8 = 1;
pub const KIND_CHALLENGE: u8 = 2;
pub const KIND_AUTH: u8 = 3;
pub const KIND_ACK: u8 = 4;
pub const KIND_REJECT: u8 = 5;
pub const KIND_INV: u8 = 10;
pub const KIND_WANT: u8 = 11;
pub const KIND_PAYLOAD: u8 = 12;
pub const KIND_PING: u8 = 13;
pub const KIND_PONG: u8 = 14;
pub const KIND_FIND_NODE: u8 = 15;
pub const KIND_NEIGHBORS: u8 = 16;

pub fn configure_socket(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    Ok(())
}

pub fn write_frame(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<(), NetworkError> {
    if payload.len() > MAX_FRAME as usize {
        return Err(NetworkError::BadFrame);
    }
    let mut hdr = [0u8; 10];
    hdr[0..4].copy_from_slice(MAGIC);
    hdr[4] = PROTO_VERSION;
    hdr[5] = kind;
    hdr[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn read_frame(stream: &mut impl Read) -> Result<(u8, Vec<u8>), NetworkError> {
    let mut hdr = [0u8; 10];
    stream.read_exact(&mut hdr)?;
    if hdr[0..4] != MAGIC[..] || hdr[4] != PROTO_VERSION {
        return Err(NetworkError::BadFrame);
    }
    let kind = hdr[5];
    let len = u32::from_le_bytes(hdr[6..10].try_into().unwrap());
    if len > MAX_FRAME {
        return Err(NetworkError::BadFrame);
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

pub fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

pub fn take_bytes(data: &[u8], off: &mut usize) -> Result<Vec<u8>, NetworkError> {
    if data.len() < *off + 4 {
        return Err(NetworkError::BadFrame);
    }
    let n = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if data.len() < *off + n {
        return Err(NetworkError::BadFrame);
    }
    let slice = data[*off..*off + n].to_vec();
    *off += n;
    Ok(slice)
}
