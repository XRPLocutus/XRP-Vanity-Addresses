// ============================================================================
//  XRPL Key Derivation & Seed Encoding
//
//  XRPL Ed25519 address derivation:
//    16-byte entropy
//      -> SHA-512(entropy) -> first 32 bytes = private key
//        -> Ed25519 Public Key (32 bytes)
//          -> [0xED] + pubkey (33 bytes)
//            -> SHA-256 -> RIPEMD-160 -> 20-byte Account ID
//              -> Base58Check (XRPL alphabet, 0x00 prefix) = r... address
// ============================================================================

use ed25519_dalek::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use std::sync::LazyLock;

/// XRPL uses its own Base58 alphabet (different from Bitcoin's).
/// Notably missing: 0, O, I, l (to avoid visual ambiguity).
pub const XRPL_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Pre-built Base58 alphabet -- avoids re-validating 58 chars on every iteration.
pub static XRPL_BS58_ALPHABET: LazyLock<bs58::Alphabet> =
    LazyLock::new(|| bs58::Alphabet::new(XRPL_ALPHABET).unwrap());

// ============================================================================
//  Key Derivation
// ============================================================================

/// Derives a 32-byte Ed25519 private key from 16-byte entropy using the
/// standard XRPL method: SHA-512(entropy), take first 32 bytes.
#[inline(always)]
pub fn entropy_to_private_key(entropy: &[u8; 16]) -> [u8; 32] {
    let hash = Sha512::digest(entropy);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key
}

/// Computes the 20-byte XRPL Account ID from an Ed25519 public key.
///
/// XRPL Ed25519 requires a 0xED prefix on the public key before hashing.
/// This is what makes XRPL Ed25519 addresses differ from raw Ed25519.
#[inline(always)]
pub fn pubkey_to_account_id(pubkey_bytes: &[u8; 32]) -> [u8; 20] {
    // Build 33-byte prefixed public key: [0xED] + pubkey
    let mut prefixed = [0u8; 33];
    prefixed[0] = 0xED;
    prefixed[1..33].copy_from_slice(pubkey_bytes);

    // SHA-256 -> RIPEMD-160
    let sha_result = Sha256::digest(&prefixed);
    let ripemd_result = Ripemd160::digest(sha_result);
    let mut account_id = [0u8; 20];
    account_id.copy_from_slice(&ripemd_result);
    account_id
}

/// Builds the full 25-byte Base58Check payload on the stack.
/// [0x00] + account_id (20 bytes) + checksum (4 bytes)
#[inline(always)]
pub fn build_payload(account_id: &[u8; 20]) -> [u8; 25] {
    let mut payload = [0u8; 25];
    payload[0] = 0x00;
    payload[1..21].copy_from_slice(account_id);

    let hash1 = Sha256::digest(&payload[..21]);
    let hash2 = Sha256::digest(hash1);
    payload[21..25].copy_from_slice(&hash2[..4]);
    payload
}

/// Full Base58Check encoding of a 25-byte payload into an XRPL address.
#[allow(dead_code)] // used in tests
pub fn encode_address(payload: &[u8; 25]) -> String {
    bs58::encode(payload)
        .with_alphabet(&*XRPL_BS58_ALPHABET)
        .into_string()
}

/// Generates an XRPL address from 16-byte entropy.
/// Returns (SigningKey, address_string).
#[allow(dead_code)] // used in tests
pub fn entropy_to_address(entropy: &[u8; 16]) -> (SigningKey, String) {
    let private_key = entropy_to_private_key(entropy);
    let signing_key = SigningKey::from_bytes(&private_key);
    let pubkey = signing_key.verifying_key().to_bytes();
    let account_id = pubkey_to_account_id(&pubkey);
    let payload = build_payload(&account_id);
    let address = encode_address(&payload);
    (signing_key, address)
}

// ============================================================================
//  Seed Encoding (sEd... format)
// ============================================================================

/// Encodes 16-byte entropy as an XRPL family seed in sEd... format.
///
/// This encodes the ENTROPY (not the derived private key), making the
/// seed importable into any XRPL wallet (XUMM/Xaman, etc.).
///
/// Format: Base58Check([0x01, 0xE1, 0x4B] + entropy_16 + checksum_4)
pub fn entropy_to_seed(entropy: &[u8; 16]) -> String {
    let mut payload = [0u8; 23]; // 3 prefix + 16 entropy + 4 checksum
    // Ed25519 family seed prefix
    payload[0] = 0x01;
    payload[1] = 0xE1;
    payload[2] = 0x4B;
    payload[3..19].copy_from_slice(entropy);

    // Checksum: double SHA-256, first 4 bytes
    let hash1 = Sha256::digest(&payload[..19]);
    let hash2 = Sha256::digest(hash1);
    payload[19..23].copy_from_slice(&hash2[..4]);

    bs58::encode(&payload)
        .with_alphabet(&*XRPL_BS58_ALPHABET)
        .into_string()
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_address_starts_with_r() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);
        let (_, addr) = entropy_to_address(&entropy);
        assert!(addr.starts_with('r'), "XRPL address must start with 'r': {}", addr);
    }

    #[test]
    fn test_address_length() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);
        let (_, addr) = entropy_to_address(&entropy);
        assert!(
            addr.len() >= 25 && addr.len() <= 35,
            "Address length {} out of expected range 25-35: {}",
            addr.len(),
            addr
        );
    }

    #[test]
    fn test_address_valid_characters() {
        let alphabet_str = std::str::from_utf8(XRPL_ALPHABET).unwrap();
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);
        let (_, addr) = entropy_to_address(&entropy);
        for ch in addr.chars() {
            assert!(
                alphabet_str.contains(ch),
                "Address contains invalid character '{}': {}",
                ch,
                addr
            );
        }
    }

    #[test]
    fn test_deterministic_address() {
        let entropy = [0x42u8; 16];
        let (_, addr1) = entropy_to_address(&entropy);
        let (_, addr2) = entropy_to_address(&entropy);
        assert_eq!(addr1, addr2, "Same entropy must produce same address");
    }

    #[test]
    fn test_different_entropy_different_addresses() {
        let entropy1 = [0x01u8; 16];
        let entropy2 = [0x02u8; 16];
        let (_, addr1) = entropy_to_address(&entropy1);
        let (_, addr2) = entropy_to_address(&entropy2);
        assert_ne!(addr1, addr2, "Different entropy should produce different addresses");
    }

    #[test]
    fn test_seed_format() {
        let entropy = [0x42u8; 16];
        let seed = entropy_to_seed(&entropy);
        assert!(
            seed.starts_with('s'),
            "Ed25519 seed must start with 's': {}",
            seed
        );
    }

    /// Verifies same 16-byte entropy deterministically produces
    /// the same address AND the same seed.
    #[test]
    fn test_seed_roundtrip() {
        let entropy = [0xABu8; 16];
        let (_, addr1) = entropy_to_address(&entropy);
        let seed1 = entropy_to_seed(&entropy);

        let (_, addr2) = entropy_to_address(&entropy);
        let seed2 = entropy_to_seed(&entropy);

        assert_eq!(addr1, addr2, "Address must be deterministic");
        assert_eq!(seed1, seed2, "Seed must be deterministic");
    }

    /// Verify that the 0xED prefix is actually used in address derivation.
    /// An address derived with the prefix must differ from one without.
    #[test]
    fn test_ed_prefix_matters() {
        let entropy = [0x55u8; 16];
        let private_key = entropy_to_private_key(&entropy);
        let signing_key = SigningKey::from_bytes(&private_key);
        let pubkey = signing_key.verifying_key().to_bytes();

        // Correct: with 0xED prefix
        let correct_id = pubkey_to_account_id(&pubkey);

        // Wrong: without prefix (raw pubkey hash)
        let wrong_sha = Sha256::digest(&pubkey);
        let wrong_ripemd = Ripemd160::digest(wrong_sha);
        let mut wrong_id = [0u8; 20];
        wrong_id.copy_from_slice(&wrong_ripemd);

        assert_ne!(
            correct_id, wrong_id,
            "0xED prefix must change the derived account ID"
        );
    }
}
