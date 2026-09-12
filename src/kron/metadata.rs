//! Official KRON Network asset metadata.
//!
//! The icon is a canonical UTF-8 descriptor (plus a tiny SVG glyph). The
//! consensus-safe `icon_hash` is SHA-256 of that descriptor — never a PNG.

use crate::crypto::hash::sha256;
use crate::economics::UNITS_PER_COIN;
use crate::kron::{NETWORK_NAME, TICKER};

/// Canonical UTF-8 glyph description. `icon_hash` is SHA-256 of this exact
/// string so the digest is deterministic across platforms.
pub const KRON_ICON_DESCRIPTOR: &str = concat!(
    "KRON Network official icon v1\n",
    "motif: 3D letter K formed by intersecting lattice basis vectors\n",
    "style: minimalist cyberpunk geometric lattice\n",
    "background: matte black / dark metallic\n",
    "accent: electric neon blue\n",
    r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">"##,
    r##"<rect width="32" height="32" fill="#0a0a0c"/>"##,
    r##"<path d="M7 3 L16 16 L7 29" stroke="#00e5ff" stroke-width="2.2" fill="none"/>"##,
    r##"<path d="M16 16 L26 4" stroke="#00e5ff" stroke-width="2.2" fill="none"/>"##,
    r##"<path d="M16 16 L26 28" stroke="#00e5ff" stroke-width="2.2" fill="none"/>"##,
    r##"</svg>"##,
    "\n",
);

/// Visual presentation hints stored as metadata strings (not rendered here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KronVisualSpec {
    pub style: &'static str,
    pub background: &'static str,
    pub accent: &'static str,
    pub motif: &'static str,
}

/// On-chain / wallet-facing brand record for the native asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: &'static str,
    pub ticker: &'static str,
    pub decimals: u8,
    pub icon_hash: [u8; 32],
    pub visual: KronVisualSpec,
}

/// Official KRON brand metadata. Decimals match [`UNITS_PER_COIN`].
pub fn get_kron_metadata() -> AssetMetadata {
    let decimals = decimals_from_units(UNITS_PER_COIN);
    AssetMetadata {
        name: NETWORK_NAME,
        ticker: TICKER,
        decimals,
        icon_hash: sha256(KRON_ICON_DESCRIPTOR.as_bytes()),
        visual: KronVisualSpec {
            style: "minimalist cyberpunk geometric lattice",
            background: "matte black / dark metallic",
            accent: "electric neon blue",
            motif: "3D letter K formed by intersecting lattice basis vectors",
        },
    }
}

/// Integer log10 of the minor-unit scale (1_000_000 → 6). No floats.
fn decimals_from_units(units: u64) -> u8 {
    let mut n = units;
    let mut d = 0u8;
    while n >= 10 && n % 10 == 0 {
        n /= 10;
        d = d.saturating_add(1);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kron::SATOSHI_KRON;

    #[test]
    fn icon_hash_is_stable_and_decimals_match_scale() {
        let a = get_kron_metadata();
        let b = get_kron_metadata();
        assert_eq!(a.icon_hash, b.icon_hash);
        assert_eq!(a.decimals, 6);
        assert_eq!(SATOSHI_KRON, UNITS_PER_COIN);
        assert_eq!(a.visual.accent, "electric neon blue");
    }
}
