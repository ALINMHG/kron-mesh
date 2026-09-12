//! Integer-only KRON amount parsing. Never uses `f32`/`f64`.

use new_blockchain::UNITS_PER_COIN;

/// Why a decimal string could not be converted into minor units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseAmountError {
    Empty,
    InvalidChars,
    TooManyDecimals,
    TooManySeparators,
    Overflow,
}

impl std::fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "amount is empty"),
            Self::InvalidChars => write!(f, "amount contains invalid characters"),
            Self::TooManyDecimals => write!(f, "maximum 6 decimal places"),
            Self::TooManySeparators => write!(f, "too many decimal separators"),
            Self::Overflow => write!(f, "amount exceeds u64"),
        }
    }
}

/// Parse a human KRON amount (`"1.5"` or `"1,5"`) into micro-KRON (`1_500_000`).
///
/// Accepts `.` or `,` as the decimal separator. Rejects a second separator
/// so `"1.500,00"` is not silently misread.
pub fn parse_kron_amount(input: &str) -> Result<u64, ParseAmountError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseAmountError::Empty);
    }

    let sep_count = s.chars().filter(|c| *c == '.' || *c == ',').count();
    if sep_count > 1 {
        return Err(ParseAmountError::TooManySeparators);
    }

    let normalized = s.replace(',', ".");
    let (whole_raw, frac_raw) = match normalized.split_once('.') {
        Some((w, f)) => (w, f),
        None => (normalized.as_str(), ""),
    };

    if whole_raw.is_empty() && frac_raw.is_empty() {
        return Err(ParseAmountError::Empty);
    }
    if !whole_raw.is_empty() && !whole_raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(ParseAmountError::InvalidChars);
    }
    if !frac_raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(ParseAmountError::InvalidChars);
    }
    if frac_raw.len() > 6 {
        return Err(ParseAmountError::TooManyDecimals);
    }

    let whole: u64 = if whole_raw.is_empty() {
        0
    } else {
        whole_raw
            .parse()
            .map_err(|_| ParseAmountError::Overflow)?
    };

    let mut frac_padded = frac_raw.to_string();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded
            .parse()
            .map_err(|_| ParseAmountError::Overflow)?
    };

    whole
        .checked_mul(UNITS_PER_COIN)
        .and_then(|w| w.checked_add(frac))
        .ok_or(ParseAmountError::Overflow)
}

/// Fixed 6-decimal display (`1500000` → `"1.500000"`).
pub fn format_kron_amount(micros: u64) -> String {
    let whole = micros / UNITS_PER_COIN;
    let frac = micros % UNITS_PER_COIN;
    format!("{whole}.{frac:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_and_a_half_kron() {
        assert_eq!(parse_kron_amount("1.5").unwrap(), 1_500_000);
        assert_eq!(parse_kron_amount("1,5").unwrap(), 1_500_000);
        assert_eq!(parse_kron_amount(" 1.500000 ").unwrap(), 1_500_000);
    }

    #[test]
    fn parse_whole_and_fractional_edges() {
        assert_eq!(parse_kron_amount("1").unwrap(), 1_000_000);
        assert_eq!(parse_kron_amount("0.001").unwrap(), 1_000);
        assert_eq!(parse_kron_amount(".5").unwrap(), 500_000);
        assert_eq!(parse_kron_amount("0.000001").unwrap(), 1);
        assert_eq!(format_kron_amount(1_500_000), "1.500000");
        assert_eq!(format_kron_amount(1_000), "0.001000");
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_kron_amount("").is_err());
        assert!(parse_kron_amount("1.2.3").is_err());
        assert!(parse_kron_amount("1.1234567").is_err());
        assert!(parse_kron_amount("abc").is_err());
        assert!(parse_kron_amount("1.5e2").is_err());
        assert_eq!(ParseAmountError::Empty.to_string(), "amount is empty");
        assert_eq!(
            ParseAmountError::TooManyDecimals.to_string(),
            "maximum 6 decimal places"
        );
    }
}
