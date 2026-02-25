// ============================================================================
//  XRPL Vanity Wallet Address Generator
//
//  Generates Ed25519 keypairs at high speed across all CPU cores to find
//  XRPL addresses matching a desired prefix or suffix pattern.
//
//  Address derivation:
//    Random Seed (16 bytes)
//      → SHA-512-Half → Ed25519 Private Key (32 bytes)
//        → Ed25519 Public Key (prefixed with 0xED, 33 bytes)
//          → SHA-256 (32 bytes)
//            → RIPEMD-160 (20 bytes) = Account ID
//              → Base58Check (XRPL alphabet, 0x00 prefix) = r... address
// ============================================================================

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rayon::prelude::*;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// XRPL uses its own Base58 alphabet (different from Bitcoin's).
/// Notably missing: 0, O, I, l (to avoid visual ambiguity).
const XRPL_ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

#[derive(Parser, Debug)]
#[command(name = "xrpl-vanity")]
#[command(version)]
#[command(about = "⚡ High-performance XRPL vanity wallet address generator")]
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

/// Derives an XRPL classic address (r...) from an Ed25519 signing key.
///
/// Process:
///   1. Extract the 32-byte Ed25519 public key, prefix with 0xED
///   2. SHA-256 hash of prefixed public key → 32 bytes
///   3. RIPEMD-160 hash → 20 bytes (Account ID)
///   4. Prepend type prefix byte 0x00
///   5. Append checksum (first 4 bytes of double SHA-256)
///   6. Base58 encode with XRPL alphabet
fn keypair_to_address(signing_key: &SigningKey) -> String {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    // Step 1: Prefix public key with 0xED (XRPL Ed25519 convention)
    let mut prefixed_pubkey = [0u8; 33];
    prefixed_pubkey[0] = 0xED;
    prefixed_pubkey[1..].copy_from_slice(&pubkey_bytes);

    // Step 2: SHA-256 of the prefixed public key
    let sha_result = Sha256::digest(prefixed_pubkey);

    // Step 3: RIPEMD-160 of the SHA-256 hash
    let account_id = Ripemd160::digest(sha_result);

    // Step 4: Prepend the account type prefix (0x00 for classic addresses)
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00u8);
    payload.extend_from_slice(&account_id);

    // Step 5: Checksum = first 4 bytes of SHA-256(SHA-256(payload))
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(hash1);
    payload.extend_from_slice(&hash2[..4]);

    // Step 6: Base58 encode using the XRPL-specific alphabet
    bs58::encode(&payload)
        .with_alphabet(&bs58::Alphabet::new(XRPL_ALPHABET).unwrap())
        .into_string()
}

/// Encodes 16-byte seed entropy as an XRPL family seed (sEd...).
///
/// This is the portable secret format that can be imported into XRPL wallets.
/// Uses prefix bytes [0x01, 0xE1, 0x4B] for Ed25519 seeds.
fn entropy_to_seed(entropy: &[u8; 16]) -> String {
    // Ed25519 family seed prefix
    let mut payload = Vec::with_capacity(23);
    payload.push(0x01);
    payload.push(0xE1);
    payload.push(0x4B);
    payload.extend_from_slice(entropy);

    // Checksum = first 4 bytes of SHA-256(SHA-256(payload))
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(hash1);
    payload.extend_from_slice(&hash2[..4]);

    bs58::encode(&payload)
        .with_alphabet(&bs58::Alphabet::new(XRPL_ALPHABET).unwrap())
        .into_string()
}

/// Derives an Ed25519 signing key from 16-byte seed entropy.
///
/// Uses XRPL's standard derivation: SHA-512(entropy), take first 32 bytes.
fn derive_signing_key(entropy: &[u8; 16]) -> SigningKey {
    let hash = Sha512::digest(entropy);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash[..32]);
    SigningKey::from_bytes(&key_bytes)
}

/// Validates that all characters in the pattern exist in the XRPL Base58 alphabet.
fn validate_vanity_chars(pattern: &str) -> Result<(), String> {
    let alphabet_str = std::str::from_utf8(XRPL_ALPHABET).unwrap();
    for ch in pattern.chars() {
        if !alphabet_str.contains(ch) {
            return Err(format!(
                "Character '{}' is not valid in the XRPL Base58 alphabet.\n\
                 Valid characters: {}",
                ch, alphabet_str
            ));
        }
    }
    Ok(())
}

/// Returns the expected average number of attempts for a pattern of given length.
/// Each Base58 character has a 1/58 probability, so the expectation is 58^length.
fn estimate_attempts(pattern_len: usize) -> u64 {
    58u64.saturating_pow(pattern_len as u32)
}

/// Formats a duration in seconds to a human-readable string.
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

/// Formats a large number with human-readable suffixes (K, M, B).
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

    if args.case_insensitive {
        // Validate against lowercased alphabet so invalid chars are still caught
        let alphabet_lower = std::str::from_utf8(XRPL_ALPHABET)
            .unwrap()
            .to_lowercase();
        for ch in pattern.to_lowercase().chars() {
            if !alphabet_lower.contains(ch) {
                eprintln!(
                    "❌ Character '{}' cannot appear in XRPL Base58 addresses.\n   \
                     Valid characters: {}",
                    ch,
                    std::str::from_utf8(XRPL_ALPHABET).unwrap()
                );
                std::process::exit(1);
            }
        }
    } else if let Err(e) = validate_vanity_chars(&pattern) {
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

    // --- Print banner ---
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║     ⚡ XRPL Vanity Wallet Generator                ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "║  Mode:            {:<35}║",
        format!("{} \"{}\"", mode, pattern)
    );
    println!(
        "║  Case-insensitive: {:<34}║",
        if args.case_insensitive { "Yes" } else { "No" }
    );
    println!("║  Threads:         {:<35}║", threads);
    println!(
        "║  Avg. attempts:   {:<35}║",
        format!("~{}", format_large_number(avg_attempts))
    );
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("🔍 Searching...");
    println!();

    // --- Shared state for cross-thread coordination ---
    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let progress_interval = args.progress_every_million * 1_000_000;

    // --- Parallel search across all threads ---
    let result = (0..threads).into_par_iter().find_map_any(|_| {
        let mut rng = rand::rngs::OsRng;
        let mut local_count: u64 = 0;

        loop {
            // Check if another thread already found a match
            if found.load(Ordering::Relaxed) {
                return None;
            }

            // Generate a random 16-byte seed and derive the keypair
            let mut entropy = [0u8; 16];
            rng.fill_bytes(&mut entropy);
            let key = derive_signing_key(&entropy);
            let addr = keypair_to_address(&key);
            local_count += 1;

            // Periodically report progress
            if local_count % 50_000 == 0 {
                let total = counter.fetch_add(50_000, Ordering::Relaxed) + 50_000;
                if total % progress_interval < 50_000 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = total as f64 / elapsed;
                    let eta_secs = (avg_attempts as f64 - total as f64) / rate;
                    eprint!(
                        "\r   {}M attempts | {:.0}K/s | est. remaining: {}    ",
                        total / 1_000_000,
                        rate / 1000.0,
                        if eta_secs > 0.0 {
                            format_duration(eta_secs)
                        } else {
                            "any moment!".to_string()
                        }
                    );
                }
            }

            // Check if the address matches the desired pattern
            let matches = match mode {
                "prefix" => {
                    // XRPL addresses always start with 'r'; check after it
                    if args.case_insensitive {
                        addr[1..].to_lowercase().starts_with(&pattern.to_lowercase())
                    } else {
                        addr[1..].starts_with(&pattern)
                    }
                }
                "suffix" => {
                    if args.case_insensitive {
                        addr.to_lowercase().ends_with(&pattern.to_lowercase())
                    } else {
                        addr.ends_with(&pattern)
                    }
                }
                _ => unreachable!(),
            };

            if matches {
                found.store(true, Ordering::Relaxed);
                counter.fetch_add(local_count % 50_000, Ordering::Relaxed);
                return Some((entropy, key, addr));
            }
        }
    });

    // --- Display results ---
    let elapsed = start.elapsed();
    let total_attempts = counter.load(Ordering::Relaxed);

    println!();
    println!();

    match result {
        Some((entropy, signing_key, address)) => {
            let seed = entropy_to_seed(&entropy);
            let secret_hex = hex::encode(signing_key.to_bytes());

            println!("╔══════════════════════════════════════════════════════╗");
            println!("║  ✅ FOUND!                                          ║");
            println!("╠══════════════════════════════════════════════════════╣");
            println!("║                                                      ║");
            println!("  Address:      {}", address);
            println!("  Secret (hex): {}", secret_hex);
            println!("  Seed:         {}", seed);
            println!("║                                                      ║");
            println!("╠══════════════════════════════════════════════════════╣");
            println!(
                "  Attempts:     {}",
                format_large_number(total_attempts)
            );
            println!("  Duration:     {:.2?}", elapsed);
            println!(
                "  Speed:        {:.0}K addr/sec",
                total_attempts as f64 / elapsed.as_secs_f64() / 1000.0
            );
            println!("╚══════════════════════════════════════════════════════╝");
            println!();
            println!("⚠️  IMPORTANT: Store your secret key / seed securely!");
            println!("    Anyone with the secret key controls the wallet.");
            println!("    Clear this terminal after noting it down.");
        }
        None => {
            println!("❌ Search was interrupted (this should not happen).");
        }
    }
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_starts_with_r() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr = keypair_to_address(&key);
        assert!(addr.starts_with('r'), "XRPL address must start with 'r'");
    }

    #[test]
    fn test_address_length() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr = keypair_to_address(&key);
        // XRPL classic addresses are 25-35 characters
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
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr = keypair_to_address(&key);
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
        // Same signing key must always produce the same address
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr1 = keypair_to_address(&key);
        let addr2 = keypair_to_address(&key);
        assert_eq!(addr1, addr2, "Same key must produce same address");
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let key1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let key2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr1 = keypair_to_address(&key1);
        let addr2 = keypair_to_address(&key2);
        assert_ne!(addr1, addr2, "Different keys should produce different addresses");
    }

    #[test]
    fn test_seed_format() {
        let mut entropy = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let seed = entropy_to_seed(&entropy);
        assert!(
            seed.starts_with('s'),
            "Ed25519 seed must start with 's': {}",
            seed
        );
    }

    #[test]
    fn test_seed_roundtrip() {
        // Same seed entropy must always derive the same address
        let mut entropy = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let key1 = derive_signing_key(&entropy);
        let key2 = derive_signing_key(&entropy);
        let addr1 = keypair_to_address(&key1);
        let addr2 = keypair_to_address(&key2);
        assert_eq!(addr1, addr2, "Same seed must produce same address");
    }

    #[test]
    fn test_validate_chars_valid() {
        assert!(validate_vanity_chars("Bob").is_ok());
        assert!(validate_vanity_chars("XRP").is_ok());
        assert!(validate_vanity_chars("r3").is_ok());
    }

    #[test]
    fn test_validate_chars_invalid() {
        assert!(validate_vanity_chars("O").is_err()); // O not in XRPL alphabet
        assert!(validate_vanity_chars("0").is_err()); // 0 not in XRPL alphabet
        assert!(validate_vanity_chars("I").is_err()); // I not in XRPL alphabet
        assert!(validate_vanity_chars("l").is_err()); // l not in XRPL alphabet
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
}
