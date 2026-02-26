// ============================================================================
//  XRPL Vanity Wallet Address Generator v2.0
// ============================================================================

mod crypto;
mod display;
mod validation;

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crypto::{
    build_payload, entropy_to_private_key, entropy_to_seed, pubkey_to_account_id,
    XRPL_BS58_ALPHABET,
};
use display::{
    bottom, empty, estimate_attempts, format_duration, format_large_number, line, rule, title, top,
};
use validation::validate_vanity_chars;

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

    // --- Print banner ---
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

    eprint!("🔍 Searching...");

    // Pre-compute match data for the hot loop
    let pattern_bytes = pattern.as_bytes();
    let is_prefix = mode == "prefix";
    let case_insensitive = args.case_insensitive;

    // --- Parallel search across all threads ---
    let result: Option<([u8; 16], SigningKey, String)> =
        (0..threads).into_par_iter().find_map_any(|_| {
            // ChaCha20Rng seeded once from OsRng per thread (~5x faster)
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

                // Derive private key: SHA-512-Half
                let private_key = entropy_to_private_key(&entropy);
                let signing_key = SigningKey::from_bytes(&private_key);
                let pubkey = signing_key.verifying_key().to_bytes();

                // Derive address with 0xED prefix
                let account_id = pubkey_to_account_id(&pubkey);
                let payload = build_payload(&account_id);

                // Encode to stack buffer (zero heap allocation)
                let addr_len = bs58::encode(&payload)
                    .with_alphabet(&*XRPL_BS58_ALPHABET)
                    .onto(&mut addr_buf[..])
                    .unwrap();
                let addr = &addr_buf[..addr_len];

                local_count += 1;

                // Progress reporting -- bitmask instead of modulo
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

    // --- Display results ---
    let elapsed = start.elapsed();
    let total_attempts = counter.load(Ordering::Relaxed);

    // Clear the progress line
    eprint!("\r{}\r", " ".repeat(90));
    println!();

    match result {
        Some((entropy, signing_key, address)) => {
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
