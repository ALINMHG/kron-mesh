//! BIP39 recovery phrases (24 words) mapped onto `LatticeKeyPair::from_seed`.
//!
//! The 32-byte BIP39 entropy *is* the seed passed to ML-DSA-44 keygen. The same
//! phrase always restores the same Dilithium keypair. No PBKDF2 truncation.

use bip39::Mnemonic;
use new_blockchain::crypto::lattice::LatticeKeyPair;
use new_blockchain::kron::KronKeypair;
use rand::RngCore;

/// Number of BIP39 words used for a new KRON wallet.
pub const WORD_COUNT: usize = 24;

/// Quiz prompts shown on the confirmation screen.
pub const QUIZ_LEN: usize = 4;

#[derive(Clone, Debug)]
pub struct RecoveryPhrase {
    mnemonic: Mnemonic,
    entropy: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhraseError {
    InvalidEntropy,
    #[allow(dead_code)]
    InvalidMnemonic,
}

impl std::fmt::Display for PhraseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEntropy => write!(f, "recovery entropy must be 32 bytes (24 words)"),
            Self::InvalidMnemonic => write!(f, "invalid recovery phrase"),
        }
    }
}

impl RecoveryPhrase {
    /// Fresh 24-word phrase from OS CSPRNG entropy.
    pub fn generate() -> Self {
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        Self::from_entropy(entropy).expect("32-byte entropy is valid BIP39")
    }

    pub fn from_entropy(entropy: [u8; 32]) -> Result<Self, PhraseError> {
        let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|_| PhraseError::InvalidEntropy)?;
        if mnemonic.word_count() != WORD_COUNT {
            return Err(PhraseError::InvalidEntropy);
        }
        Ok(Self { mnemonic, entropy })
    }

    #[allow(dead_code)]
    pub fn from_phrase(phrase: &str) -> Result<Self, PhraseError> {
        let mnemonic = Mnemonic::parse_normalized(phrase.trim())
            .map_err(|_| PhraseError::InvalidMnemonic)?;
        let raw = mnemonic.to_entropy();
        if raw.len() != 32 {
            return Err(PhraseError::InvalidMnemonic);
        }
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&raw);
        Ok(Self { mnemonic, entropy })
    }

    pub fn entropy(&self) -> [u8; 32] {
        self.entropy
    }

    pub fn words(&self) -> Vec<String> {
        self.mnemonic.words().map(str::to_string).collect()
    }

    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Dilithium keypair restored from BIP39 entropy via `LatticeKeyPair::from_seed`.
    pub fn keypair(&self) -> KronKeypair {
        KronKeypair::from_lattice(LatticeKeyPair::from_seed(self.entropy))
    }
}

/// Four distinct 0-based word indices for the confirmation quiz.
pub fn quiz_indices() -> [usize; QUIZ_LEN] {
    let mut chosen = [0usize; QUIZ_LEN];
    let mut used = [false; WORD_COUNT];
    let mut filled = 0;
    while filled < QUIZ_LEN {
        let i = (rand::random::<u8>() as usize) % WORD_COUNT;
        if used[i] {
            continue;
        }
        used[i] = true;
        chosen[filled] = i;
        filled += 1;
    }
    chosen.sort_unstable();
    chosen
}

pub fn words_match(expected: &str, typed: &str) -> bool {
    expected.eq_ignore_ascii_case(typed.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use new_blockchain::crypto::lattice::LatticeKeyPair;

    #[test]
    fn generates_twenty_four_english_words() {
        let phrase = RecoveryPhrase::generate();
        let words = phrase.words();
        assert_eq!(words.len(), WORD_COUNT);
        assert!(words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())));
        let again = RecoveryPhrase::from_entropy(phrase.entropy()).unwrap();
        assert_eq!(phrase.phrase(), again.phrase());
        assert_eq!(
            RecoveryPhrase::from_phrase(&phrase.phrase())
                .unwrap()
                .entropy(),
            phrase.entropy()
        );
    }

    #[test]
    fn entropy_restores_the_same_lattice_keypair() {
        let phrase = RecoveryPhrase::generate();
        let a = LatticeKeyPair::from_seed(phrase.entropy());
        let b = phrase.keypair();
        assert_eq!(a.public, *b.public_key());
        assert_eq!(a.secret, b.lattice().secret);
        let restored = RecoveryPhrase::from_phrase(&phrase.phrase()).unwrap();
        assert_eq!(
            LatticeKeyPair::from_seed(restored.entropy()).public,
            a.public
        );
    }

    #[test]
    fn quiz_picks_unique_sorted_indices() {
        for _ in 0..32 {
            let idx = quiz_indices();
            assert_eq!(idx.len(), QUIZ_LEN);
            for i in 1..idx.len() {
                assert!(idx[i] > idx[i - 1]);
                assert!(idx[i] < WORD_COUNT);
            }
        }
    }

    #[test]
    fn word_match_is_case_insensitive() {
        assert!(words_match("abandon", " Abandon "));
        assert!(!words_match("abandon", "ability"));
    }
}
