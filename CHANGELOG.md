# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Optimized release profile (LTO, native CPU target)
- Comprehensive test suite
