# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-02-27

### Performance
- **Hardware acceleration** – `target-cpu=native` enables SHA-NI intrinsics for SHA-256/SHA-512 (called 4x per iteration) and AVX2 SIMD for Ed25519 scalar multiplication via `curve25519_dalek_backend=simd`
- **Batch RNG generation** – pre-generates 4096 bytes (256 entropies) per RNG call instead of 16 bytes, ~256x fewer RNG calls in the hot loop
- **Reduced atomic contention** – progress counter updated every 262,144 iterations (was 65,536); done-flag checked every 1,024 (was 256)

## [2.2.1] - 2026-02-27

### Security
- **Secret zeroization** – all private keys, entropy, seeds, and hex-encoded secrets are wrapped in `zeroize::Zeroizing` and wiped from memory on drop
- **Entropy source validation** – startup sanity check bails if the OS CSPRNG returns all zeros
- **`--clear` flag** – clears the screen and terminal scrollback after the user has noted down their keys
- **Mutex poisoning safety** – result lock uses `unwrap_or_else` to recover gracefully instead of panicking

### Added
- `--clear` flag — press Enter after noting your keys to clear screen and scrollback buffer
- `zeroize` dependency for secure memory wiping
- Windows x64 release binary attached to GitHub release

## [2.1.0] - 2026-02-26

### Added
- `--contains` (`-c`) flag — match a substring anywhere in the address
- `--count` (`-n`) flag — find multiple matching addresses in one run
- Combined filters — `--prefix`, `--suffix`, and `--contains` can now be used together freely
- Graceful Ctrl+C handling — displays partial results when interrupted

### Changed
- `--prefix` and `--suffix` are no longer mutually exclusive; combine them for patterns like `rBob...XRP`
- Replaced `num_cpus` crate with `std::thread::available_parallelism()` (one fewer dependency)
- Search loop uses `for_each` with shared result collection instead of `find_map_any`
- Done-flag check reduced from every iteration to every 256 iterations (less atomic contention)
- `main()` returns `Result<()>` via `anyhow` instead of calling `process::exit`

### Code Quality
- Split `main.rs` into modules: `crypto.rs`, `validation.rs`, `display.rs`

## [2.0.0] - 2026-02-26

### Security Fixes
- Fixed key derivation — changed from raw 32-byte random to standard XRPL path: 16-byte seed entropy → SHA-512-Half → 32-byte private key
- Fixed seed encoding — sEd... output now encodes the 16-byte entropy (not the 32-byte key), making it importable by any XRPL wallet
- Fixed address derivation — added missing 0xED prefix to the public key before hashing, so generated addresses match what the XRPL ledger computes
- Fixed case-insensitive validation — `-i` flag no longer skips pattern validation; invalid characters are now caught against the lowercased alphabet

### Performance
- ChaCha20Rng replaces OsRng for ~5x faster random number generation
- Hardware-accelerated SHA-256 via `sha2` asm feature
- Moved target-cpu=native to `.cargo/config.toml` as a proper rustc flag (eliminates build warning)
- Zero heap allocations in the hot loop (stack buffers only)

### Display
- Consistent box borders — all content lines properly enclosed in ║...║
- Wider box (84 chars) — fits the full 64-char hex secret without overflow
- Structured sections — credentials, stats, and warning separated by ╠═══╣ dividers
- Warning displayed inside the box — no more dangling text after the frame
- Progress on stderr — overwrites "Searching..." in place; uses format_large_number for consistency

### Tests
- Added test_seed_roundtrip — verifies same 16-byte entropy deterministically produces the same address
- Added test_ed_prefix_matters — verifies 0xED prefix affects address derivation
- Added test_validate_chars_case_insensitive — verifies -i flag still catches invalid chars
- Updated test_seed_format — uses new entropy_to_seed API

## [1.0.0] - 2026-02-25

### Added
- Initial release
- Ed25519 keypair generation with XRPL address derivation
- Prefix and suffix vanity matching
- Case-insensitive search mode (`-i`)
- Multithreaded search using all CPU cores via Rayon
- Live progress display with speed and ETA
- XRPL family seed output (`sEd...` format)
- Hex secret key output
- Input validation against XRPL Base58 alphabet
- Configurable thread count
- Comprehensive test suite
