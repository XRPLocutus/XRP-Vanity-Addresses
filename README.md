# ⚡ XRPL Vanity Address Generator v2.0

A high-performance vanity wallet address generator for the XRP Ledger (XRPL). Generates Ed25519 keypairs at maximum speed using all available CPU cores to find addresses matching a desired prefix or suffix.

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green)

## Features

- 🚀 **Blazing fast** – ChaCha20 RNG, hardware-accelerated SHA-256, zero heap allocations in hot loop
- 🧵 **Multithreaded** – automatically uses all CPU cores via [Rayon](https://github.com/rayon-rs/rayon)
- 🔐 **Correct XRPL derivation** – standard 16-byte entropy → SHA-512-Half → Ed25519 path
- 🔑 **Importable seeds** – sEd... output works directly in XUMM/Xaman, Ledger, and all XRPL wallets
- 🎯 **Prefix & suffix matching** – find `rYourName...` or `r...XRP`
- 🔡 **Case-insensitive mode** – match regardless of capitalization
- 📊 **Live progress** – real-time speed and ETA display
- 🔒 **Fully offline** – no network connection needed, keys never leave your machine
- 🪟 **Cross-platform** – works on Windows, Linux, and macOS

## v2.0 Changes

### Security Fixes
- **Correct key derivation** – uses the standard XRPL path: 16-byte entropy → SHA-512-Half → 32-byte Ed25519 private key
- **Correct seed encoding** – sEd... output encodes the 16-byte entropy (not the raw key), making it importable by any XRPL wallet
- **Correct address derivation** – 0xED prefix on public key before hashing, matching ledger behavior
- **Case-insensitive validation** – `-i` flag no longer skips character validation

### Performance
- **ChaCha20Rng** replaces OsRng (~5x faster random number generation)
- **Hardware-accelerated SHA-256** via `sha2` asm feature
- **target-cpu=native** via `.cargo/config.toml` (enables AVX2/AVX-512 on supported CPUs)
- **Zero heap allocations** in the hot loop (all stack buffers)

### Display
- **Consistent box borders** – all content properly enclosed
- **Wider output box** (84 chars) – fits full 64-char hex secrets without overflow
- **Progress on stderr** – overwrites in place, no scrolling

## Performance

Typical speeds on modern hardware (release build):

| CPU | Threads | Speed |
|-----|---------|-------|
| Ryzen 9 7950X | 32 | ~3.5M addr/s |
| Core i9-13900K | 32 | ~3.0M addr/s |
| Ryzen 7 5800X | 16 | ~1.8M addr/s |
| Apple M2 Pro | 12 | ~1.5M addr/s |

### Estimated Search Times (at 2M addr/s)

| Prefix Length | Avg. Attempts | Est. Time |
|---------------|---------------|-----------|
| 1 char | ~58 | instant |
| 2 chars | ~3,364 | instant |
| 3 chars | ~195K | < 1 sec |
| 4 chars | ~11M | ~6 sec |
| 5 chars | ~656M | ~5 min |
| 6 chars | ~38B | ~5 hrs |
| 7+ chars | ~2T+ | days |

> Each additional character multiplies the search space by ~58x (XRPL Base58 alphabet size).

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or later
- A C/C++ linker:
  - **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **"Desktop development with C++"** workload
  - **Linux**: `build-essential` (`sudo apt install build-essential`)
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)

### Build

```bash
git clone https://github.com/XRPLocutus/xrpl-vanity.git
cd xrpl-vanity
cargo build --release
```

The compiled binary will be at `target/release/xrpl-vanity` (or `xrpl-vanity.exe` on Windows).

> ⚠️ **Always use `--release`!** Debug builds are ~20x slower.

### Usage

```bash
# Find an address starting with rBob...
xrpl-vanity --prefix Bob

# Find an address ending with ...XRP
xrpl-vanity --suffix XRP

# Case-insensitive search
xrpl-vanity --prefix bob -i

# Limit to 8 threads
xrpl-vanity --prefix Cool --threads 8

# Show progress every 5 million attempts
xrpl-vanity --prefix Hello --progress-every-million 5
```

### Example Output

```
╔════════════════════════════════════════════════════════════════════════════════════════╗
║  ⚡ XRPL Vanity Wallet Generator v2.0                                                ║
╠════════════════════════════════════════════════════════════════════════════════════════╣
║  Mode:              prefix "Bob"                                                      ║
║  Case-insensitive:  No                                                                ║
║  Threads:           16                                                                ║
║  Avg. attempts:     ~195.1K                                                           ║
╚════════════════════════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════════════════════════╗
║  ✅ FOUND!                                                                            ║
╠════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║  Address:          rBobK8q2F7TVr4pn9jLcE6MxB8a7VfJqHN                                 ║
║  Secret (hex):     a3f182...full 64 chars...b72e                                       ║
║  Seed:             sEdV...                                                             ║
║                                                                                        ║
╠════════════════════════════════════════════════════════════════════════════════════════╣
║  Attempts:         83.2K                                                               ║
║  Duration:         0.05s                                                               ║
║  Speed:            1.66M/sec                                                           ║
╠════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║  ⚠️  IMPORTANT: Store your secret key / seed securely!                                 ║
║     Anyone with the seed controls the wallet.                                          ║
║     Clear this terminal after noting it down.                                          ║
║                                                                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--prefix <PATTERN>` | `-p` | Desired prefix after the leading `r` |
| `--suffix <PATTERN>` | `-s` | Desired suffix at the end of the address |
| `--case-insensitive` | `-i` | Match regardless of upper/lower case |
| `--threads <N>` | `-t` | Number of threads (default: all CPU cores) |
| `--progress-every-million <N>` | | Progress update interval in millions (default: 10) |
| `--help` | `-h` | Show help |

## Valid Characters

XRPL addresses use a custom Base58 alphabet. Only these characters are valid in vanity patterns:

```
r p s h n a f 3 9 w B U D N E G H J K L M 4 P Q R S T 7 V W X Y Z
2 b c d e C g 6 5 j k m 8 o F q i 1 t u v A x y z
```

Notably absent: `0` (zero), `O` (uppercase o), `I` (uppercase i), `l` (lowercase L) — excluded to prevent visual confusion.

## How It Works

XRPL Ed25519 key derivation follows the standard ledger path:

1. **Generate** 16 bytes of random entropy using ChaCha20Rng (seeded from OS CSPRNG)
2. **Derive** the private key: `SHA-512(entropy)` → first 32 bytes
3. **Compute** the Ed25519 public key (32 bytes)
4. **Prefix** the public key with `0xED` (33 bytes) — XRPL Ed25519 marker
5. **Hash**: `SHA-256` → `RIPEMD-160` → 20-byte Account ID
6. **Encode** with Base58Check (XRPL alphabet, `0x00` prefix) → `r...` address
7. **Check** if the address matches the desired pattern
8. **Repeat** across all CPU cores until a match is found

```
Random Entropy (16 bytes)
  → SHA-512 → first 32 bytes = Ed25519 Private Key
    → Ed25519 Public Key (32 bytes)
      → [0xED] + pubkey (33 bytes)
        → SHA-256 (32 bytes)
          → RIPEMD-160 (20 bytes) = Account ID
            → Base58Check → rXXXXXXXX... (classic address)
```

The generated `sEd...` seed encodes the original 16-byte entropy and can be imported directly into XUMM/Xaman, Ledger, or any XRPL-compatible wallet.

## Security

### Is a vanity address less secure?

**No.** The entropy is generated from a cryptographically secure random source — identical to any standard wallet. The vanity generator simply discards keys whose addresses don't match your pattern. The key you keep is just as random and secure as any other.

### Best practices

- **Generate offline** — this tool requires no network connection
- **Never use online vanity generators** — they may retain your private key
- **Clear your terminal** after noting down the secret key
- **Store the secret key securely** — anyone with access to it controls the wallet
- **Verify the full address** when transacting, not just the vanity portion

## Activating Your Wallet

A newly generated XRPL address must be funded with the [base reserve](https://xrpl.org/reserves.html) (currently 10 XRP) before it becomes active on the ledger. Send XRP from an existing wallet to your new vanity address to activate it.

## Building from Source

### Release build (slow compilation, fast execution)

```bash
cargo build --release
./target/release/xrpl-vanity --prefix Test
```

### Run tests

```bash
cargo test
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `rustc` not found | Open a new terminal after installing Rust, or add `~/.cargo/bin` to PATH |
| Linker errors on Windows | Install VS Build Tools with "Desktop development with C++" workload |
| Linker errors on Linux | `sudo apt install build-essential` |
| Very slow performance | Make sure you're using `--release` flag |
| Invalid character error | Check the [valid characters](#valid-characters) section |
| Low thread count | Use `--threads` to manually set core count |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This software is provided as-is, without warranty of any kind. The authors are not responsible for any loss of funds resulting from the use of this software. Always verify generated keys independently before storing significant value.
