# Security Policy

## Cryptographic Design

This tool generates XRPL wallets using:

- **Ed25519** key generation via the `ed25519-dalek` crate
- **OsRng** (operating system cryptographic random number generator) for seed generation
- **SHA-256** and **RIPEMD-160** for address derivation
- **Base58Check** encoding with the XRPL-specific alphabet

All cryptographic operations use well-audited Rust crates from the RustCrypto project.

## Security Considerations

### This tool does NOT:
- Connect to the internet
- Send any data anywhere
- Log or store generated keys (beyond printing to the terminal)
- Use any custom or weakened cryptography

### Users should:
- **Always build from source** — do not trust pre-compiled binaries from unknown sources
- **Run offline** — disconnect from the internet while generating keys for maximum safety
- **Clear terminal history** after noting down the secret key
- **Never use online vanity generators** — they may retain your private key
- **Verify the code** — review `src/main.rs` before running; it's a single, readable file

## Reporting Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead:

1. Email: **XRPLocutus@protonmail.com**
2. Include a description of the vulnerability
3. Include steps to reproduce if possible

I will respond within 48 hours and work on a fix.

## Dependencies

All dependencies are from well-known, audited sources:

| Crate | Purpose | Maintainer |
|-------|---------|------------|
| `ed25519-dalek` | Ed25519 signatures | dalek-cryptography |
| `sha2` | SHA-256 hashing | RustCrypto |
| `ripemd` | RIPEMD-160 hashing | RustCrypto |
| `rand` | Cryptographic RNG | rust-random |
| `bs58` | Base58 encoding | Rust community |
| `rayon` | Parallel iteration | rayon-rs |
| `clap` | CLI argument parsing | clap-rs |

Run `cargo audit` to check for known vulnerabilities in dependencies.
