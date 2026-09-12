//! Minimal Bech32 (BIP-173) encoder/decoder.
//!
//! Used only for the KRON display address (`kron1…`). Ledger keys stay
//! raw 32-byte [`crate::types::Address`] hashes. Integer polymod only;
//! no floating-point.

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e1d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Official human-readable part. Combined with the separator this yields `kron1`.
pub const HRP: &str = "kron";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Error {
    Empty,
    MixedCase,
    MissingSeparator,
    InvalidHrp,
    InvalidCharset,
    InvalidChecksum,
    InvalidPadding,
    InvalidPayloadLength,
}

impl std::fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty bech32 string"),
            Self::MixedCase => write!(f, "mixed-case bech32 is invalid"),
            Self::MissingSeparator => write!(f, "bech32 missing separator '1'"),
            Self::InvalidHrp => write!(f, "bech32 HRP must be 'kron'"),
            Self::InvalidCharset => write!(f, "bech32 character not in charset"),
            Self::InvalidChecksum => write!(f, "bech32 checksum mismatch"),
            Self::InvalidPadding => write!(f, "bech32 bit-conversion padding invalid"),
            Self::InvalidPayloadLength => write!(f, "bech32 payload is not 32 bytes"),
        }
    }
}

impl std::error::Error for Bech32Error {}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, gen) in GEN.iter().enumerate() {
            if ((b >> i) & 1) == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 31);
    }
    out
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = polymod(&values) ^ 1;
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

/// Convert `from`-bit groups to `to`-bit groups. All arithmetic is integer.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let max_v = (1u32 << to) - 1;
    for &value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max_v) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max_v) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max_v) != 0 {
        return None;
    }
    Some(out)
}

fn charset_index(c: u8) -> Option<u8> {
    CHARSET.iter().position(|&x| x == c).map(|i| i as u8)
}

/// Encode a 32-byte lattice address hash as `kron1…`.
pub fn encode_kron(payload: &[u8; 32]) -> String {
    let data = convert_bits(payload, 8, 5, true).expect("8-to-5 conversion of 32 bytes");
    let checksum = create_checksum(HRP, &data);
    let mut out = String::with_capacity(HRP.len() + 1 + data.len() + 6);
    out.push_str(HRP);
    out.push('1');
    for v in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[*v as usize] as char);
    }
    out
}

/// Decode a `kron1…` string back to the 32-byte payload.
pub fn decode_kron(s: &str) -> Result<[u8; 32], Bech32Error> {
    if s.is_empty() {
        return Err(Bech32Error::Empty);
    }
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = s.to_ascii_lowercase();
    let sep = lowered
        .rfind('1')
        .ok_or(Bech32Error::MissingSeparator)?;
    if sep == 0 || sep + 7 > lowered.len() {
        return Err(Bech32Error::InvalidHrp);
    }
    let hrp = &lowered[..sep];
    if hrp != HRP {
        return Err(Bech32Error::InvalidHrp);
    }
    let data_part = &lowered[sep + 1..];
    let mut data = Vec::with_capacity(data_part.len());
    for b in data_part.bytes() {
        let idx = charset_index(b).ok_or(Bech32Error::InvalidCharset)?;
        data.push(idx);
    }
    if !verify_checksum(HRP, &data) {
        return Err(Bech32Error::InvalidChecksum);
    }
    let payload5 = &data[..data.len() - 6];
    let bytes = convert_bits(payload5, 5, 8, false).ok_or(Bech32Error::InvalidPadding)?;
    if bytes.len() != 32 {
        return Err(Bech32Error::InvalidPayloadLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_starts_with_kron1_and_roundtrips() {
        let payload = [0xABu8; 32];
        let encoded = encode_kron(&payload);
        assert!(encoded.starts_with("kron1"));
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert_eq!(decode_kron(&encoded).unwrap(), payload);
        assert_eq!(decode_kron(&encoded.to_ascii_uppercase()).unwrap(), payload);
    }

    #[test]
    fn rejects_bad_checksum_and_mixed_case() {
        let encoded = encode_kron(&[0x11; 32]);
        let mut broken = encoded.clone();
        let last = broken.pop().unwrap();
        broken.push(if last == 'q' { 'p' } else { 'q' });
        assert_eq!(decode_kron(&broken), Err(Bech32Error::InvalidChecksum));

        let mixed = format!("Kron{}", &encoded[4..]);
        assert_eq!(decode_kron(&mixed), Err(Bech32Error::MixedCase));
        assert_eq!(decode_kron("bc1qqqq"), Err(Bech32Error::InvalidHrp));
    }
}
