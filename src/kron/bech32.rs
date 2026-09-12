//! Minimal Bech32 (BIP-173) encoder/decoder.
//!
//! Used only for the KRON display address (`kron1…`). Ledger keys stay
//! raw 32-byte [`crate::types::Address`] hashes. Integer polymod only;
//! no floating-point.

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// BIP-173 generator. The second coefficient is `0x26508e6d` (not `0x26508e1d`).
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Official human-readable part. Combined with the separator this yields `kron1`.
pub const HRP: &str = "kron";

/// Canonical `kron1…` length: `kron` + `1` + 52 five-bit groups + 6 checksum.
pub const KRON1_LEN: usize = 63;

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
            Self::MixedCase => write!(
                f,
                "mixed-case bech32 is invalid (BIP-173 requires all-lower or all-upper)"
            ),
            Self::MissingSeparator => write!(f, "bech32 missing separator '1'"),
            Self::InvalidHrp => write!(f, "bech32 HRP must be 'kron'"),
            Self::InvalidCharset => write!(f, "bech32 character not in charset"),
            Self::InvalidChecksum => write!(
                f,
                "bech32 checksum mismatch: a KRON address is {KRON1_LEN} characters; copy the full kron1 string as one line"
            ),
            Self::InvalidPadding => write!(f, "bech32 bit-conversion padding invalid"),
            Self::InvalidPayloadLength => write!(f, "bech32 payload is not 32 bytes"),
        }
    }
}

impl std::error::Error for Bech32Error {}

impl Bech32Error {
    /// CLI / menu text. Checksum failures always include length + paste hint.
    pub fn cli_message(self, cleaned: &str) -> String {
        match self {
            Self::InvalidChecksum => format!(
                "invalid KRON address: checksum failed (got {} characters, expected {KRON1_LEN}). Copy the full kron1 string as one line — Termux often wraps a long address onto a second line.",
                cleaned.len()
            ),
            Self::MixedCase => {
                "invalid KRON address: mixed-case is rejected (BIP-173). Use all-lowercase or all-uppercase.".into()
            }
            other => format!("invalid Bech32 KRON address '{cleaned}': {other}"),
        }
    }
}

/// Drop whitespace, newlines, and zero-width / bidi marks so a Termux-wrapped
/// paste (`kron1…` split across lines) becomes one string.
pub fn normalize_bech32_input(s: &str) -> String {
    s.chars().filter(|c| !is_ignorable_address_char(*c)).collect()
}

fn is_ignorable_address_char(c: char) -> bool {
    if c.is_whitespace() {
        return true;
    }
    matches!(
        c,
        '\u{00ad}' // soft hyphen
            | '\u{200b}' // zero-width space
            | '\u{200c}' // ZWNJ
            | '\u{200d}' // ZWJ
            | '\u{2060}' // word joiner
            | '\u{feff}' // BOM
            | '\u{200e}' // LRM
            | '\u{200f}' // RLM
            | '\u{202a}'..='\u{202e}' // bidi embeddings
            | '\u{2066}'..='\u{2069}' // bidi isolates
    )
}

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
    let max_acc = (1u32 << (from + to - 1)) - 1;
    for &value in data {
        let v = value as u32;
        if (v >> from) != 0 {
            return None;
        }
        acc = ((acc << from) | v) & max_acc;
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
    debug_assert_eq!(out.len(), KRON1_LEN);
    out
}

/// Decode a `kron1…` string back to the 32-byte payload.
pub fn decode_kron(s: &str) -> Result<[u8; 32], Bech32Error> {
    let s = normalize_bech32_input(s);
    if s.is_empty() {
        return Err(Bech32Error::Empty);
    }
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = s.to_ascii_lowercase();
    if lowered.len() > 90 {
        return Err(Bech32Error::InvalidChecksum);
    }
    let sep = lowered
        .rfind('1')
        .ok_or(Bech32Error::MissingSeparator)?;
    if sep == 0 {
        return Err(Bech32Error::InvalidHrp);
    }
    let hrp = &lowered[..sep];
    if hrp != HRP {
        return Err(Bech32Error::InvalidHrp);
    }
    let data_part = &lowered[sep + 1..];
    if data_part.len() < 6 {
        return Err(Bech32Error::InvalidChecksum);
    }
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
    fn bip173_empty_hrp_a_checksum() {
        let checksum = create_checksum("a", &[]);
        let mut s = String::from("a1");
        for v in checksum {
            s.push(CHARSET[v as usize] as char);
        }
        assert_eq!(s, "a12uel5l");
        assert_eq!(s.to_ascii_uppercase(), "A12UEL5L");
    }

    #[test]
    fn bip173_known_kron_payloads() {
        assert_eq!(
            encode_kron(&[0xAB; 32]),
            "kron14w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w4s6cn3gc"
        );
        assert_eq!(
            encode_kron(&[0; 32]),
            "kron1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq34pc3"
        );
        assert_eq!(encode_kron(&[0xAB; 32]).len(), KRON1_LEN);
    }

    #[test]
    fn encode_starts_with_kron1_and_roundtrips() {
        let payload = [0xABu8; 32];
        let encoded = encode_kron(&payload);
        assert!(encoded.starts_with("kron1"));
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert_eq!(encoded.len(), KRON1_LEN);
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
        assert!(decode_kron(&broken).unwrap_err().to_string().contains("63"));
        assert!(decode_kron(&broken)
            .unwrap_err()
            .to_string()
            .contains("one line"));

        let mixed = format!("Kron{}", &encoded[4..]);
        assert_eq!(decode_kron(&mixed), Err(Bech32Error::MixedCase));
        assert_eq!(decode_kron("bc1qqqq"), Err(Bech32Error::InvalidHrp));
    }

    #[test]
    fn joins_wrapped_and_zero_width_paste() {
        let payload = [0xCDu8; 32];
        let encoded = encode_kron(&payload);
        let mut wrapped = String::new();
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i % 20 == 0 {
                wrapped.push('\n');
            }
            wrapped.push(ch);
        }
        let with_zwsp = format!("\u{feff}{}\u{200b}", wrapped.replace('\n', " \n"));
        assert_eq!(decode_kron(&with_zwsp).unwrap(), payload);
    }

    #[test]
    fn truncated_address_is_checksum_error() {
        let encoded = encode_kron(&[0x22; 32]);
        let truncated = &encoded[..40];
        let err = decode_kron(truncated).unwrap_err();
        assert_eq!(err, Bech32Error::InvalidChecksum);
        let msg = err.cli_message(truncated);
        assert!(msg.contains("40"), "{msg}");
        assert!(msg.contains("63"), "{msg}");
        assert!(msg.contains("one line"), "{msg}");
    }
}
