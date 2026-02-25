# ⚡ XRPL Vanity Address Generator

A high-performance vanity wallet address generator for the XRP Ledger (XRPL). Generates Ed25519 keypairs at maximum speed using all available CPU cores to find addresses matching a desired prefix or suffix.

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green)

## Features

- 🚀 **Blazing fast** – optimized release build with LTO, native CPU instructions
- 🧵 **Multithreaded** – automatically uses all CPU cores via [Rayon](https://github.com/rayon-rs/rayon)
- 🔐 **Ed25519 keypairs** – faster key generation than secp256k1
- 🎯 **Prefix & suffix matching** – find `rYourName...` or `r...XRP`
- 🔡 **Case-insensitive mode** – match regardless of capitalization
- 📊 **Live progress** – real-time speed and ETA display
- 🔒 **Fully offline** – no network connection needed, keys never leave your machine
- 🪟 **Cross-platform** – works on Windows, Linux, and macOS

## Performance

Typical speeds on modern hardware (release build):

| CPU | Threads | Speed |
|-----|---------|-------|
| Ryzen 9 7950X | 32 | ~2.5M addr/s |
| Core i9-13900K | 32 | ~2.2M addr/s |
| Ryzen 7 5800X | 16 | ~1.2M addr/s |
| Apple M2 Pro | 12 | ~1.0M addr/s |

### Estimated Search Times (at 1M addr/s)

| Prefix Length | Avg. Attempts | Est. Time |
|---------------|---------------|-----------|
| 1 char | ~58 | instant |
| 2 chars | ~3,364 | instant |
| 3 chars | ~195K | < 1 sec |
| 4 chars | ~11M | ~11 sec |
| 5 chars | ~656M | ~11 min |
| 6 chars | ~38B | ~10 hrs |
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
╔══════════════════════════════════════════════════════╗
║     ⚡ XRPL Vanity Wallet Generator                ║
╠══════════════════════════════════════════════════════╣
║  Mode:            prefix "Bob"                       ║
║  Case-insensitive: No                                ║
║  Threads:         16                                 ║
║  Avg. attempts:   ~195.1k                            ║
╚══════════════════════════════════════════════════════╝

🔍 Searching...

╔══════════════════════════════════════════════════════╗
║  ✅ FOUND!                                          ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
  Address:      rBobK8q2F7TVr4pn9jLcE6MxB8a7VfJqHN
  Secret (hex): a3f1...b72e
  Seed:         sEdV...
║                                                      ║
╠══════════════════════════════════════════════════════╣
  Attempts:     83.2k
  Duration:     0.14s
  Speed:        594k addr/sec
╚══════════════════════════════════════════════════════╝

⚠️  IMPORTANT: Store your secret key / seed securely!
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

1. **Generate** a random 32-byte seed using the OS cryptographic RNG (`OsRng`)
2. **Derive** an Ed25519 keypair from the seed
3. **Hash** the public key: `SHA-256` → `RIPEMD-160` → 20-byte Account ID
4. **Encode** with Base58Check (XRPL alphabet, `0x00` prefix) → `r...` address
5. **Check** if the address matches the desired pattern
6. **Repeat** across all CPU cores until a match is found

```
Random Seed (32 bytes)
  → Ed25519 Public Key (32 bytes)
    → SHA-256 (32 bytes)
      → RIPEMD-160 (20 bytes) = Account ID
        → Base58Check Encoding → rXXXXXXXX... (classic address)
```

## Security

### Is a vanity address less secure?

**No.** The private key is generated from a full 32-byte cryptographically secure random seed — identical to any standard wallet. The vanity generator simply discards keys whose addresses don't match your pattern. The key you keep is just as random and secure as any other.

### Best practices

- **Generate offline** — this tool requires no network connection
- **Never use online vanity generators** — they may retain your private key
- **Clear your terminal** after noting down the secret key
- **Store the secret key securely** — anyone with access to it controls the wallet
- **Verify the full address** when transacting, not just the vanity portion

## Activating Your Wallet

A newly generated XRPL address must be funded with the [base reserve](https://xrpl.org/reserves.html) (currently 10 XRP) before it becomes active on the ledger. Send XRP from an existing wallet to your new vanity address to activate it.

## Building from Source

### Development build (fast compilation, slow execution)

```bash
cargo build
cargo run -- --prefix Test
```

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
| Invalid character error | Check the [valid characters](#valid-characters) section — XRPL uses a custom Base58 alphabet |
| Low thread count | Use `--threads` to manually set core count |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This software is provided as-is, without warranty of any kind. The authors are not responsible for any loss of funds resulting from the use of this software. Always verify generated keys independently before storing significant value.
