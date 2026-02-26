// ============================================================================
//  XRPL Vanity Wallet Address Generator v2.0
//
//  Security fixes over v1.0:
//    1. Correct XRPL key derivation: 16-byte entropy → SHA-512-Half → Ed25519
//    2. Correct seed encoding: sEd... encodes 16-byte entropy (importable)
//    3. Correct address derivation: 0xED prefix on pubkey before hashing
//
//  Performance optimizations:
//    - ChaCha20Rng instead of OsRng (~5x faster RNG)
//    - SHA-256/SHA-512 auto-vectorized via target-cpu=native
//    - Zero heap allocations in hot loop (stack buffers only)
//    - target-cpu=native via .cargo/config.toml
//
//  XRPL Ed25519 address derivation:
//    16-byte entropy
//      → SHA-512(entropy) → first 32 bytes = private key
//        → Ed25519 Public Key (32 bytes)
//          → [0xED] + pubkey (33 bytes)
//            → SHA-256 → RIPEMD-160 → 20-byte Account ID
//              → Base58Check (XRPL alphabet, 0x00 prefix) = r... address
// ============================================================================

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

/// XRPL uses its own Base58 alphabet (different from Bitcoin's).
/// Notably missing: 0, O, I, l (to avoid visual ambiguity).
const XRPL_ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Pre-built Base58 alphabet — avoids re-validating 58 chars on every iteration.
static XRPL_BS58_ALPHABET: LazyLock<bs58::Alphabet> = LazyLock::new(|| {
    bs58::Alphabet::new(XRPL_ALPHABET).unwrap()
});

#[derive(Parser, Debug)]
#[command(name = "xrpl-vanity")]
#[command(version)]
#[command(about = "High-performance XRPL vanity wallet address generator v2.0")]
#[command(long_about = "Generates Ed25519 keypairs across all CPU cores to find \
    XRPL addresses matching a desired prefix or suffix pattern.\n\n\
    Examples:\n  \
    xrpl-vanity --prefix Bob       Find rBob...\n  \
    xrpl-vanity --suffix XRP       Find r...XRP\n  \
    xrpl-vanity --prefix bob -i    Case-insensitive")]
struct Args {
    /// Desired prefix (after the leading 'r'), e.g. "Bob" to find rBob...
    #[arg(short, long, conflicts_with = "suffix")]
    prefix: Option<String>,

    /// Desired suffix, e.g. "XRP" to find r...XRP
    #[arg(short, long, conflicts_with = "prefix")]
    suffix: Option<String>,

    /// Number of threads (default: all CPU cores)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Case-insensitive matching
    #[arg(short = 'i', long, default_value_t = false)]
    case_insensitive: bool,

    /// Show progress every N million attempts
    #[arg(long, default_value_t = 10)]
    progress_every_million: u64,
}

// ============================================================================
//  XRPL Key Derivation (correct XRPL standard)
// ============================================================================

/// Derives a 32-byte Ed25519 private key from 16-byte entropy using the
/// standard XRPL method: SHA-512(entropy), take first 32 bytes.
#[inline(always)]
fn entropy_to_private_key(entropy: &[u8; 16]) -> [u8; 32] {
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
fn pubkey_to_account_id(pubkey_bytes: &[u8; 32]) -> [u8; 20] {
    // Build 33-byte prefixed public key: [0xED] + pubkey
    let mut prefixed = [0u8; 33];
    prefixed[0] = 0xED;
    prefixed[1..33].copy_from_slice(pubkey_bytes);

    // SHA-256 → RIPEMD-160
    let sha_result = Sha256::digest(&prefixed);
    let ripemd_result = Ripemd160::digest(sha_result);
    let mut account_id = [0u8; 20];
    account_id.copy_from_slice(&ripemd_result);
    account_id
}

/// Builds the full 25-byte Base58Check payload on the stack.
/// [0x00] + account_id (20 bytes) + checksum (4 bytes)
#[inline(always)]
fn build_payload(account_id: &[u8; 20]) -> [u8; 25] {
    let mut payload = [0u8; 25];
    payload[0] = 0x00;
    payload[1..21].copy_from_slice(account_id);

    let hash1 = Sha256::digest(&payload[..21]);
    let hash2 = Sha256::digest(hash1);
    payload[21..25].copy_from_slice(&hash2[..4]);
    payload
}

/// Full Base58Check encoding of a 25-byte payload into an XRPL address.
fn encode_address(payload: &[u8; 25]) -> String {
    bs58::encode(payload)
        .with_alphabet(&*XRPL_BS58_ALPHABET)
        .into_string()
}

/// Generates an XRPL address from 16-byte entropy.
/// Returns (SigningKey, address_string).
fn entropy_to_address(entropy: &[u8; 16]) -> (SigningKey, String) {
    let private_key = entropy_to_private_key(entropy);
    let signing_key = SigningKey::from_bytes(&private_key);
    let pubkey = signing_key.verifying_key().to_bytes();
    let account_id = pubkey_to_account_id(&pubkey);
    let payload = build_payload(&account_id);
    let address = encode_address(&payload);
    (signing_key, address)
}

// ============================================================================
//  XRPL Seed Encoding (sEd... format)
// ============================================================================

/// Encodes 16-byte entropy as an XRPL family seed in sEd... format.
///
/// This encodes the ENTROPY (not the derived private key), making the
/// seed importable into any XRPL wallet (XUMM/Xaman, etc.).
///
/// Format: Base58Check([0x01, 0xE1, 0x4B] + entropy_16 + checksum_4)
fn entropy_to_seed(entropy: &[u8; 16]) -> String {
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
//  Validation
// ============================================================================

/// Validates pattern characters against the XRPL Base58 alphabet.
/// Fix #4: case-insensitive mode now validates against lowercased alphabet.
fn validate_vanity_chars(pattern: &str, case_insensitive: bool) -> Result<(), String> {
    let alphabet_str = std::str::from_utf8(XRPL_ALPHABET).unwrap();

    for ch in pattern.chars() {
        let valid = if case_insensitive {
            alphabet_str
                .chars()
                .any(|a| a.to_lowercase().eq(ch.to_lowercase()))
        } else {
            alphabet_str.contains(ch)
        };

        if !valid {
            return Err(format!(
                "Character '{}' is not valid in the XRPL Base58 alphabet.\n\
                 Valid characters: {}",
                ch, alphabet_str
            ));
        }
    }
    Ok(())
}

// ============================================================================
//  Display helpers (Fix #6-#9: consistent box borders)
// ============================================================================

const BOX_WIDTH: usize = 84;

fn line(label: &str, value: &str) {
    let content = format!("  {}{}",
        format!("{:<18}", label),
        value
    );
    let pad = BOX_WIDTH.saturating_sub(content.len());
    println!("║{}{}║", content, " ".repeat(pad));
}

fn empty() {
    println!("║{}║", " ".repeat(BOX_WIDTH));
}

fn rule() {
    println!("╠{}╣", "═".repeat(BOX_WIDTH));
}

fn top() {
    println!("╔{}╗", "═".repeat(BOX_WIDTH));
}

fn bottom() {
    println!("╚{}╝", "═".repeat(BOX_WIDTH));
}

fn title(text: &str) {
    let pad = BOX_WIDTH.saturating_sub(text.len() + 2);
    println!("║  {}{}║", text, " ".repeat(pad));
}

// ============================================================================
//  Utility
// ============================================================================

fn estimate_attempts(pattern_len: usize) -> u64 {
    58u64.saturating_pow(pattern_len as u32)
}

fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0}ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} min", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hrs", seconds / 3600.0)
    } else {
        format!("{:.1} days", seconds / 86400.0)
    }
}

fn format_large_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

// ============================================================================
//  Main
// ============================================================================

fn main() {
    let args = Args::parse();

    // --- Validate input ---
    let (pattern, mode) = match (&args.prefix, &args.suffix) {
        (Some(p), None) => (p.clone(), "prefix"),
        (None, Some(s)) => (s.clone(), "suffix"),
        _ => {
            eprintln!("❌ Please specify either --prefix or --suffix.");
            eprintln!("   Example: xrpl-vanity --prefix Bob");
            eprintln!("   Example: xrpl-vanity --suffix XRP");
            std::process::exit(1);
        }
    };

    // Fix #4: validate even in case-insensitive mode
    if let Err(e) = validate_vanity_chars(&pattern, args.case_insensitive) {
        eprintln!("❌ {}", e);
        std::process::exit(1);
    }

    // --- Configure thread pool ---
    let threads = args.threads.unwrap_or_else(num_cpus::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();

    let avg_attempts = estimate_attempts(pattern.len());

    // --- Print banner (Fix #6-#9: consistent box borders) ---
    println!();
    top();
    title("XRPL Vanity Wallet Generator v2.0");
    rule();
    line("Mode:", &format!("{} \"{}\"", mode, pattern));
    line("Case-insensitive:", if args.case_insensitive { "Yes" } else { "No" });
    line("Threads:", &threads.to_string());
    line("Avg. attempts:", &format!("~{}", format_large_number(avg_attempts)));
    bottom();
    println!();

    // --- Shared state ---
    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let progress_interval = args.progress_every_million * 1_000_000;

    // Fix #10: print initial "Searching..." on stderr for in-place overwrite
    eprint!("🔍 Searching...");

    // Pre-compute match data for the hot loop (avoid per-iteration overhead)
    let pattern_bytes = pattern.as_bytes();
    let is_prefix = mode == "prefix";
    let case_insensitive = args.case_insensitive;

    // --- Parallel search across all threads ---
    let result: Option<([u8; 16], SigningKey, String)> =
        (0..threads).into_par_iter().find_map_any(|_| {
            // Optimization: ChaCha20Rng seeded once from OsRng per thread (~5x faster)
            let mut rng = ChaCha20Rng::from_entropy();
            let mut entropy = [0u8; 16];
            let mut local_count: u64 = 0;
            let mut addr_buf = [0u8; 50]; // stack buffer for Base58 (max ~35 chars)

            loop {
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                // Generate 16-byte random entropy
                rng.fill_bytes(&mut entropy);

                // Derive private key: SHA-512-Half (Fix #1)
                let private_key = entropy_to_private_key(&entropy);
                let signing_key = SigningKey::from_bytes(&private_key);
                let pubkey = signing_key.verifying_key().to_bytes();

                // Derive address with 0xED prefix (Fix #3)
                let account_id = pubkey_to_account_id(&pubkey);
                let payload = build_payload(&account_id);

                // Encode to stack buffer (zero heap allocation)
                let addr_len = bs58::encode(&payload)
                    .with_alphabet(&*XRPL_BS58_ALPHABET)
                    .onto(&mut addr_buf[..])
                    .unwrap();
                let addr = &addr_buf[..addr_len];

                local_count += 1;

                // Progress reporting — bitmask instead of modulo (Fix #10)
                if local_count & 0xFFFF == 0 {
                    let total = counter.fetch_add(65_536, Ordering::Relaxed) + 65_536;
                    if total % progress_interval < 65_536 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let rate = total as f64 / elapsed;
                        let eta_secs = (avg_attempts as f64 - total as f64) / rate;
                        eprint!(
                            "\r🔍 {} attempts | {}/s | est. remaining: {}          ",
                            format_large_number(total),
                            format_large_number(rate as u64),
                            if eta_secs > 0.0 {
                                format_duration(eta_secs)
                            } else {
                                "any moment!".to_string()
                            }
                        );
                    }
                }

                // Check match (byte-level comparison, no heap allocation)
                let matches = if is_prefix {
                    if case_insensitive {
                        addr.len() > pattern_bytes.len()
                            && addr[1..1 + pattern_bytes.len()]
                                .eq_ignore_ascii_case(pattern_bytes)
                    } else {
                        addr[1..].starts_with(pattern_bytes)
                    }
                } else if case_insensitive {
                    addr.len() >= pattern_bytes.len()
                        && addr[addr.len() - pattern_bytes.len()..]
                            .eq_ignore_ascii_case(pattern_bytes)
                } else {
                    addr.ends_with(pattern_bytes)
                };

                if matches {
                    found.store(true, Ordering::Relaxed);
                    counter.fetch_add(local_count & 0xFFFF, Ordering::Relaxed);
                    let addr_string = std::str::from_utf8(addr).unwrap().to_string();
                    return Some((entropy, signing_key, addr_string));
                }
            }
        });

    // --- Display results (Fix #6-#9: consistent box, wide enough for hex) ---
    let elapsed = start.elapsed();
    let total_attempts = counter.load(Ordering::Relaxed);

    // Clear the progress line
    eprint!("\r{}\r", " ".repeat(90));
    println!();

    match result {
        Some((entropy, signing_key, address)) => {
            // Fix #2: encode the 16-byte entropy, not the 32-byte key
            let seed = entropy_to_seed(&entropy);
            let secret_hex = hex::encode(signing_key.to_bytes());

            top();
            title("FOUND!");
            rule();
            empty();
            line("Address:", &address);
            line("Secret (hex):", &secret_hex);
            line("Seed:", &seed);
            empty();
            rule();
            line("Attempts:", &format_large_number(total_attempts));
            line("Duration:", &format!("{:.2?}", elapsed));
            line(
                "Speed:",
                &format!(
                    "{}/sec",
                    format_large_number(
                        (total_attempts as f64 / elapsed.as_secs_f64()) as u64
                    )
                ),
            );
            rule();
            empty();
            title("IMPORTANT: Store your secret key / seed securely!");
            title("Anyone with the seed controls the wallet.");
            title("Clear this terminal after noting it down.");
            empty();
            bottom();
        }
        None => {
            println!("❌ Search was interrupted (this should not happen).");
        }
    }
}

// ============================================================================
//  Tests (Fix #12, #13)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Fix #12: Verifies same 16-byte entropy deterministically produces
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

    #[test]
    fn test_validate_chars_valid() {
        assert!(validate_vanity_chars("Bob", false).is_ok());
        assert!(validate_vanity_chars("XRP", false).is_ok());
        assert!(validate_vanity_chars("r3", false).is_ok());
    }

    #[test]
    fn test_validate_chars_invalid() {
        assert!(validate_vanity_chars("O", false).is_err());
        assert!(validate_vanity_chars("0", false).is_err());
        assert!(validate_vanity_chars("I", false).is_err());
        assert!(validate_vanity_chars("l", false).is_err());
    }

    /// Fix #4: case-insensitive validation must also reject invalid chars.
    #[test]
    fn test_validate_chars_case_insensitive() {
        assert!(validate_vanity_chars("bob", true).is_ok());
        assert!(validate_vanity_chars("O", true).is_ok()); // O matches o in alphabet
        assert!(validate_vanity_chars("0", true).is_err()); // 0 has no match
    }

    #[test]
    fn test_estimate_attempts() {
        assert_eq!(estimate_attempts(1), 58);
        assert_eq!(estimate_attempts(2), 3364);
        assert_eq!(estimate_attempts(3), 195112);
    }

    #[test]
    fn test_format_large_number() {
        assert_eq!(format_large_number(500), "500");
        assert_eq!(format_large_number(1_500), "1.5K");
        assert_eq!(format_large_number(2_500_000), "2.50M");
        assert_eq!(format_large_number(3_000_000_000), "3.00B");
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
