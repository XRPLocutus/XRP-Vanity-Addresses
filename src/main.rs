// ============================================================================
//  XRPL Vanity Wallet Address Generator v2.0
// ============================================================================

mod crypto;
mod display;
mod validation;

use anyhow::{bail, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    XRPL addresses matching a desired pattern.\n\n\
    Examples:\n  \
    xrpl-vanity --prefix Bob               Find rBob...\n  \
    xrpl-vanity --suffix XRP               Find r...XRP\n  \
    xrpl-vanity --prefix Bob --suffix XRP   Find rBob...XRP\n  \
    xrpl-vanity --contains Ninja            Find r...Ninja...\n  \
    xrpl-vanity --prefix bob -i             Case-insensitive\n  \
    xrpl-vanity --prefix X --count 5        Find 5 matches")]
struct Args {
    /// Desired prefix (after the leading 'r'), e.g. "Bob" to find rBob...
    #[arg(short, long)]
    prefix: Option<String>,

    /// Desired suffix, e.g. "XRP" to find r...XRP
    #[arg(short, long)]
    suffix: Option<String>,

    /// Desired substring anywhere in the address
    #[arg(short = 'c', long)]
    contains: Option<String>,

    /// Number of matching addresses to find
    #[arg(short = 'n', long, default_value_t = 1)]
    count: usize,

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

fn main() -> Result<()> {
    let args = Args::parse();

    // --- Validate input ---
    if args.prefix.is_none() && args.suffix.is_none() && args.contains.is_none() {
        bail!(
            "Please specify at least one of --prefix, --suffix, or --contains.\n\
             Example: xrpl-vanity --prefix Bob\n\
             Example: xrpl-vanity --suffix XRP\n\
             Example: xrpl-vanity --contains Ninja"
        );
    }

    let ci = args.case_insensitive;
    for pattern in [&args.prefix, &args.suffix, &args.contains]
        .into_iter()
        .flatten()
    {
        if let Err(e) = validate_vanity_chars(pattern, ci) {
            bail!("{}", e);
        }
    }

    // --- Configure thread pool ---
    let threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // --- Difficulty estimate ---
    let total_pattern_len = args.prefix.as_ref().map_or(0, |p| p.len())
        + args.suffix.as_ref().map_or(0, |s| s.len())
        + args.contains.as_ref().map_or(0, |c| c.len());
    let avg_attempts = estimate_attempts(total_pattern_len);

    // --- Describe mode ---
    let mode_desc = {
        let mut parts = Vec::new();
        if let Some(ref p) = args.prefix {
            parts.push(format!("prefix \"{}\"", p));
        }
        if let Some(ref s) = args.suffix {
            parts.push(format!("suffix \"{}\"", s));
        }
        if let Some(ref c) = args.contains {
            parts.push(format!("contains \"{}\"", c));
        }
        parts.join(" + ")
    };

    // --- Print banner ---
    println!();
    top();
    title("XRPL Vanity Wallet Generator v2.0");
    rule();
    line("Mode:", &mode_desc);
    line(
        "Case-insensitive:",
        if ci { "Yes" } else { "No" },
    );
    line("Threads:", &threads.to_string());
    if args.count > 1 {
        line("Find:", &format!("{} addresses", args.count));
    }
    line(
        "Avg. attempts:",
        &format!("~{} per match", format_large_number(avg_attempts)),
    );
    bottom();
    println!();

    // --- Shared state ---
    let done = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let results: Arc<Mutex<Vec<([u8; 16], String)>>> = Arc::new(Mutex::new(Vec::new()));
    let target = args.count;
    let start = Instant::now();
    let progress_interval = args.progress_every_million * 1_000_000;

    // --- Ctrl+C handler ---
    let done_ctrlc = done.clone();
    let interrupted_ctrlc = interrupted.clone();
    ctrlc::set_handler(move || {
        interrupted_ctrlc.store(true, Ordering::Relaxed);
        done_ctrlc.store(true, Ordering::Relaxed);
    })?;

    eprint!("\u{1f50d} Searching...");

    // Pre-compute match data for the hot loop
    let prefix_bytes: &[u8] = args.prefix.as_ref().map_or(&[], |p| p.as_bytes());
    let suffix_bytes: &[u8] = args.suffix.as_ref().map_or(&[], |s| s.as_bytes());
    let contains_bytes: &[u8] = args.contains.as_ref().map_or(&[], |c| c.as_bytes());

    // --- Parallel search across all threads ---
    (0..threads).into_par_iter().for_each(|_| {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = [0u8; 16];
        let mut local_count: u64 = 0;
        let mut addr_buf = [0u8; 50];

        loop {
            // Check done flag every 256 iterations
            if local_count & 0xFF == 0 && local_count > 0 && done.load(Ordering::Relaxed) {
                break;
            }

            rng.fill_bytes(&mut entropy);

            let private_key = entropy_to_private_key(&entropy);
            let signing_key = SigningKey::from_bytes(&private_key);
            let pubkey = signing_key.verifying_key().to_bytes();
            let account_id = pubkey_to_account_id(&pubkey);
            let payload = build_payload(&account_id);

            // Encode to stack buffer (zero heap allocation)
            let addr_len = bs58::encode(&payload)
                .with_alphabet(&*XRPL_BS58_ALPHABET)
                .onto(&mut addr_buf[..])
                .unwrap(); // infallible: 50-byte buffer always fits 25-byte payload
            let addr = &addr_buf[..addr_len];

            local_count += 1;

            // Progress reporting every 65536 iterations
            if local_count & 0xFFFF == 0 {
                let total = counter.fetch_add(65_536, Ordering::Relaxed) + 65_536;
                if total % progress_interval < 65_536 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = total as f64 / elapsed;
                    let eta_secs =
                        (avg_attempts as f64 * target as f64 - total as f64) / rate;
                    eprint!(
                        "\r\u{1f50d} {} attempts | {}/s | est. remaining: {}          ",
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

            // Check all match conditions (short-circuits on first failure)
            let prefix_ok = prefix_bytes.is_empty()
                || if ci {
                    addr.len() > prefix_bytes.len()
                        && addr[1..1 + prefix_bytes.len()].eq_ignore_ascii_case(prefix_bytes)
                } else {
                    addr[1..].starts_with(prefix_bytes)
                };

            if !prefix_ok {
                continue;
            }

            let suffix_ok = suffix_bytes.is_empty()
                || if ci {
                    addr.len() >= suffix_bytes.len()
                        && addr[addr.len() - suffix_bytes.len()..]
                            .eq_ignore_ascii_case(suffix_bytes)
                } else {
                    addr.ends_with(suffix_bytes)
                };

            if !suffix_ok {
                continue;
            }

            let contains_ok = contains_bytes.is_empty()
                || if ci {
                    addr.windows(contains_bytes.len())
                        .any(|w| w.eq_ignore_ascii_case(contains_bytes))
                } else {
                    addr.windows(contains_bytes.len())
                        .any(|w| w == contains_bytes)
                };

            if !contains_ok {
                continue;
            }

            // Match found -- store result
            let addr_string = std::str::from_utf8(addr).unwrap().to_string();
            let mut results_guard = results.lock().unwrap();
            if results_guard.len() < target {
                results_guard.push((entropy, addr_string));
                if results_guard.len() >= target {
                    done.store(true, Ordering::Relaxed);
                }
            }
            drop(results_guard);

            if done.load(Ordering::Relaxed) {
                break;
            }
        }

        // Flush remaining local iterations to global counter
        counter.fetch_add(local_count & 0xFFFF, Ordering::Relaxed);
    });

    // --- Display results ---
    let elapsed = start.elapsed();
    let total_attempts = counter.load(Ordering::Relaxed);
    let results = results.lock().unwrap();
    let was_interrupted = interrupted.load(Ordering::Relaxed);

    // Clear the progress line
    eprint!("\r{}\r", " ".repeat(90));
    println!();

    if results.is_empty() {
        if was_interrupted {
            println!("Search interrupted. No matches found.");
        } else {
            println!("No matches found (this should not happen).");
        }
    } else {
        top();
        if was_interrupted && results.len() < target {
            title(&format!(
                "INTERRUPTED -- found {} of {} requested",
                results.len(),
                target
            ));
        } else if results.len() == 1 {
            title("FOUND!");
        } else {
            title(&format!("FOUND {} MATCHES!", results.len()));
        }
        rule();

        for (i, (entropy, address)) in results.iter().enumerate() {
            let private_key = entropy_to_private_key(entropy);
            let signing_key = SigningKey::from_bytes(&private_key);
            let seed = entropy_to_seed(entropy);
            let secret_hex = hex::encode(signing_key.to_bytes());

            if results.len() > 1 {
                empty();
                title(&format!("#{}", i + 1));
            }
            empty();
            line("Address:", address);
            line("Secret (hex):", &secret_hex);
            line("Seed:", &seed);

            if i < results.len() - 1 {
                empty();
                rule();
            }
        }

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

    Ok(())
}
