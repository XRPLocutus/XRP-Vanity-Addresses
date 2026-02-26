# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
