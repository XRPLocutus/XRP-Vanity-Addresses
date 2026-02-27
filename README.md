# ⚡ XRPL Vanity Address Generator

A high-performance vanity wallet address generator for the XRP Ledger (XRPL). Generates Ed25519 keypairs at maximum speed to find addresses matching a desired prefix, suffix, or substring.

![CUDA](https://img.shields.io/badge/CUDA-13.x-76B900?logo=nvidia)
![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)

## Two Versions

| | **v3.0 — GPU (CUDA)** | **v2.3 — CPU (Rust)** |
|---|---|---|
| **Speed** | ~27M addr/s (RTX 5090) | ~3.5M addr/s (Ryzen 9 7950X) |
| **Speedup** | **~8x faster** than CPU | Baseline |
| **Requires** | NVIDIA GPU + CUDA Toolkit | Rust toolchain only |
| **Platform** | Windows, Linux | Windows, Linux, macOS |
| **Location** | [`gpu/`](gpu/) | Project root (`Cargo.toml`) |

## Features

- 🚀 **GPU-accelerated** – entire Ed25519 derivation pipeline runs on CUDA (v3.0)
- 🧵 **CPU multithreaded** – uses all CPU cores via Rayon (v2.3 fallback)
- 🔐 **Correct XRPL derivation** – standard 16-byte entropy → SHA-512-Half → Ed25519 path
- 🔑 **Importable seeds** – sEd... output works directly in XUMM/Xaman, Ledger, and all XRPL wallets
- 🎯 **Prefix, suffix & contains** – find `rYourName...`, `r...XRP`, or `r...Ninja...`
- 🔢 **Multiple results** – `--count N` finds N matching addresses in one run
- 🔡 **Case-insensitive mode** – match regardless of capitalization
- 📊 **Live progress** – real-time speed and ETA display
- ⛔ **Graceful Ctrl+C** – interrupt anytime and see partial results
- 🔒 **Fully offline** – no network connection needed, keys never leave your machine
- 🖥️ **`--clear` flag** – clears screen and scrollback after you note down your keys
- ✅ **Self-verified** – GPU results are verified against CPU reference (KAT) on startup

## Performance

### GPU (v3.0)

| GPU | Speed |
|-----|-------|
| RTX 5090 | ~27M addr/s |
| RTX 4090 | ~15M addr/s (estimated) |
| RTX 3090 | ~8M addr/s (estimated) |

### CPU (v2.3)

| CPU | Threads | Speed |
|-----|---------|-------|
| Ryzen 9 7950X | 32 | ~3.5M addr/s |
| Core i9-13900K | 32 | ~3.0M addr/s |
| Ryzen 7 5800X | 16 | ~1.8M addr/s |
| Apple M2 Pro | 12 | ~1.5M addr/s |

### Estimated Search Times

| Prefix Length | Avg. Attempts | GPU (~27M/s) | CPU (~2M/s) |
|---------------|---------------|--------------|-------------|
| 1 char | ~58 | instant | instant |
| 2 chars | ~3.4K | instant | instant |
| 3 chars | ~195K | instant | < 1 sec |
| 4 chars | ~11M | < 1 sec | ~6 sec |
| 5 chars | ~656M | ~24 sec | ~5 min |
| 6 chars | ~38B | ~23 min | ~5 hrs |
| 7+ chars | ~2T+ | ~21 hrs | days |

> Each additional character multiplies the search space by ~58x (XRPL Base58 alphabet size).

---

## Quick Start — GPU (v3.0)

### Prerequisites

- **NVIDIA GPU** (Compute Capability 8.6+: RTX 3000 series or newer)
- [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) 12.x or 13.x
- [CMake](https://cmake.org/) 3.20+
- **Windows**: Visual Studio 2022 with C++ workload
- **Linux**: GCC/G++ and `build-essential`

### Build

```bash
git clone https://github.com/XRPLocutus/XRP-Vanity-Addresses.git
cd XRP-Vanity-Addresses/gpu
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

The binary will be at `gpu/build/Release/xrpl-vanity-gpu.exe` (Windows) or `gpu/build/xrpl-vanity-gpu` (Linux).

### Usage

```bash
# Find an address starting with rBob...
xrpl-vanity-gpu -p Bob

# Find an address ending with ...XRP
xrpl-vanity-gpu -s XRP

# Find an address containing "Ninja" anywhere
xrpl-vanity-gpu -c Ninja

# Case-insensitive search
xrpl-vanity-gpu -p bob -i

# Find 5 matching addresses
xrpl-vanity-gpu -p X -n 5

# Use a specific GPU
xrpl-vanity-gpu -p Cool --gpu-id 0

# Auto-clear screen after noting down keys
xrpl-vanity-gpu -p Bob --clear
```

### Example Output

```
╔════════════════════════════════════════════════════════════════════════════════════╗
║  XRPL Vanity Address Generator v3.0 (GPU)                                        ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  Pattern:          Bob (prefix)                                                   ║
║  Case-sensitive:   Yes                                                            ║
║  Target:           1 address                                                      ║
║  Avg. attempts:    ~195.1K per match                                              ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  GPU:              NVIDIA GeForce RTX 5090 (170 SMs, CC 12.0)                     ║
║  Grid:             170 blocks x 256 threads (43.5K concurrent)                    ║
║  Self-test:        OK                                                             ║
╚════════════════════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════════════════════╗
║  FOUND!                                                                           ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  Address:          rBobK8q2F7TVr4pn9jLcE6MxB8a7VfJqHN                             ║
║  Seed:             sEdV...                                                        ║
║  Secret (hex):     a3f182...64 hex chars...b72e                                   ║
║                                                                                   ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  Attempts:         83.2K                                                          ║
║  Duration:         3ms                                                            ║
║  Speed:            27.44M/sec                                                     ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                   ║
║  IMPORTANT: Save your seed/secret securely!                                       ║
║  Anyone with the seed controls the wallet.                                        ║
║                                                                                   ║
╚════════════════════════════════════════════════════════════════════════════════════╝
```

### GPU Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--prefix <PATTERN>` | `-p` | Desired prefix after the leading `r` |
| `--suffix <PATTERN>` | `-s` | Desired suffix at the end of the address |
| `--contains <PATTERN>` | `-c` | Desired substring anywhere in the address |
| `--count <N>` | `-n` | Number of matching addresses to find (default: 1) |
| `--case-insensitive` | `-i` | Match regardless of upper/lower case |
| `--gpu-id <ID>` | | Use a specific GPU (default: 0) |
| `--gpu-grid <BLOCKS>` | | Grid blocks (default: auto = SM count) |
| `--gpu-threads <N>` | | Threads per block (default: 256) |
| `--clear` | | Clear screen and scrollback after displaying results |
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |

---

## Quick Start — CPU (v2.3)

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or later
- A C/C++ linker:
  - **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **"Desktop development with C++"** workload
  - **Linux**: `build-essential` (`sudo apt install build-essential`)
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)

### Build

```bash
git clone https://github.com/XRPLocutus/XRP-Vanity-Addresses.git
cd XRP-Vanity-Addresses
cargo build --release
```

The binary will be at `target/release/xrpl-vanity` (or `xrpl-vanity.exe` on Windows).

> ⚠️ **Always use `--release`!** Debug builds are ~20x slower.

### Usage

```bash
# Find an address starting with rBob...
xrpl-vanity --prefix Bob

# Find an address ending with ...XRP
xrpl-vanity --suffix XRP

# Find an address containing "Ninja" anywhere
xrpl-vanity --contains Ninja

# Combine prefix and suffix: rBob...XRP
xrpl-vanity --prefix Bob --suffix XRP

# Case-insensitive search
xrpl-vanity --prefix bob -i

# Find 5 matching addresses
xrpl-vanity --prefix X --count 5

# Limit to 8 threads
xrpl-vanity --prefix Cool --threads 8

# Auto-clear screen after noting down keys
xrpl-vanity --prefix Bob --clear
```

### CPU Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--prefix <PATTERN>` | `-p` | Desired prefix after the leading `r` |
| `--suffix <PATTERN>` | `-s` | Desired suffix at the end of the address |
| `--contains <PATTERN>` | `-c` | Desired substring anywhere in the address |
| `--count <N>` | `-n` | Number of matching addresses to find (default: 1) |
| `--case-insensitive` | `-i` | Match regardless of upper/lower case |
| `--threads <N>` | `-t` | Number of threads (default: all CPU cores) |
| `--progress-every-million <N>` | | Progress update interval in millions (default: 10) |
| `--clear` | | Clear screen and scrollback after displaying results |
| `--help` | `-h` | Show help |

`--prefix`, `--suffix`, and `--contains` can be freely combined. At least one must be specified.

## Valid Characters

XRPL addresses use a custom Base58 alphabet. Only these characters are valid in vanity patterns:

```
r p s h n a f 3 9 w B U D N E G H J K L M 4 P Q R S T 7 V W X Y Z
2 b c d e C g 6 5 j k m 8 o F q i 1 t u v A x y z
```

Notably absent: `0` (zero), `O` (uppercase o), `I` (uppercase i), `l` (lowercase L) — excluded to prevent visual confusion.

## Valid Characters

XRPL addresses use a custom Base58 alphabet. Only these characters are valid in vanity patterns:

```
r p s h n a f 3 9 w B U D N E G H J K L M 4 P Q R S T 7 V W X Y Z
2 b c d e C g 6 5 j k m 8 o F q i 1 t u v A x y z
```

Notably absent: `0` (zero), `O` (uppercase o), `I` (uppercase i), `l` (lowercase L) — excluded to prevent visual confusion.

## How It Works

XRPL Ed25519 key derivation follows the standard ledger path:

1. **Generate** 16 bytes of random entropy (OS CSPRNG → Philox PRNG on GPU, ChaCha20 on CPU)
2. **Derive** the private key: `SHA-512(entropy)` → first 32 bytes, clamped for Ed25519
3. **Compute** the Ed25519 public key via scalar multiplication (radix-16 windowed on GPU)
4. **Prefix** the public key with `0xED` (33 bytes) — XRPL Ed25519 marker
5. **Hash**: `SHA-256` → `RIPEMD-160` → 20-byte Account ID
6. **Encode** with Base58Check (XRPL alphabet, `0x00` prefix) → `r...` address
7. **Check** if the address matches the desired pattern
8. **Repeat** until the requested number of matches is found

```
Random Entropy (16 bytes)
  → SHA-512 → first 32 bytes = Ed25519 Private Key
    → Ed25519 Public Key (32 bytes)
      → [0xED] + pubkey (33 bytes)
        → SHA-256 (32 bytes)
          → RIPEMD-160 (20 bytes) = Account ID
            → Base58Check → rXXXXXXXX... (classic address)
```

The GPU version runs the entire pipeline (SHA-512, Ed25519, SHA-256, RIPEMD-160, Base58Check) on the GPU. Each CUDA thread processes multiple derivations per kernel launch. A CPU reference implementation verifies every GPU match before displaying it.

The generated `sEd...` seed encodes the original 16-byte entropy and can be imported directly into XUMM/Xaman, Ledger, or any XRPL-compatible wallet.

## Security

### Is a vanity address less secure?

**No.** The entropy is generated from a cryptographically secure random source — identical to any standard wallet. The vanity generator simply discards keys whose addresses don't match your pattern. The key you keep is just as random and secure as any other.

### Memory safety

- **GPU (v3.0)**: The CSPRNG seed is zeroed from host memory after upload. GPU results are CPU-verified before display.
- **CPU (v2.3)**: All secret material is wrapped in [`zeroize::Zeroizing`](https://crates.io/crates/zeroize) and wiped from memory on drop.

Use `--clear` to wipe the terminal scrollback after noting down your keys.

### Best practices

- **Generate offline** — this tool requires no network connection
- **Never use online vanity generators** — they may retain your private key
- **Use `--clear`** to wipe the screen and scrollback after noting down the secret key
- **Store the secret key securely** — anyone with access to it controls the wallet
- **Verify the full address** when transacting, not just the vanity portion

## Activating Your Wallet

A newly generated XRPL address must be funded with the [base reserve](https://xrpl.org/reserves.html) (currently 10 XRP) before it becomes active on the ledger. Send XRP from an existing wallet to your new vanity address to activate it.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| CUDA not found | Install [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) and ensure `nvcc` is on PATH |
| GPU not detected | Check NVIDIA drivers and `nvidia-smi` output |
| `rustc` not found | Open a new terminal after installing Rust, or add `~/.cargo/bin` to PATH |
| Linker errors on Windows | Install VS Build Tools / VS 2022 with "Desktop development with C++" workload |
| Linker errors on Linux | `sudo apt install build-essential` |
| Very slow CPU performance | Make sure you're using `--release` flag |
| Invalid character error | Check the [valid characters](#valid-characters) section |
| Box-drawing characters garbled | Ensure your terminal supports UTF-8 (Windows Terminal recommended) |

## Version History

### v3.0 — GPU Acceleration (CUDA)
- **Full GPU pipeline** – SHA-512, Ed25519, SHA-256, RIPEMD-160, Base58Check all on GPU
- **Radix-16 windowed scalar mult** – precomputed basepoint table, zero warp divergence
- **Philox PRNG** – counter-based CSPRNG seeded from OS entropy
- **CPU verification** – every GPU match is verified against a CPU reference
- **~8x faster** than the CPU version on modern NVIDIA GPUs

### v2.3 — CPU Performance
- Batch RNG, SHA-NI acceleration, reduced atomic contention

### v2.2 — Security Hardening
- Secret zeroization via `zeroize`, `--clear` flag, entropy validation

### v2.0 — Correctness
- Correct XRPL Ed25519 key derivation, seed encoding, and address derivation

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This software is provided as-is, without warranty of any kind. The authors are not responsible for any loss of funds resulting from the use of this software. Always verify generated keys independently before storing significant value.
