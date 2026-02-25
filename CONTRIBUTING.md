# Contributing to XRPL Vanity Generator

Thank you for your interest in contributing! Here's how you can help.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/XRPLocutus/xrpl-vanity.git`
3. Create a feature branch: `git checkout -b feature/my-improvement`
4. Make your changes
5. Run tests: `cargo test`
6. Commit: `git commit -m "Add my improvement"`
7. Push: `git push origin feature/my-improvement`
8. Open a Pull Request

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run tests
cargo test

# Run with optimizations
cargo run --release -- --prefix Test
```

## Code Style

- Follow standard Rust conventions (`cargo fmt` to auto-format)
- Run `cargo clippy` and address all warnings
- Add tests for new functionality
- Comment non-obvious logic

## Ideas for Contributions

- **Performance improvements** — faster hashing, SIMD optimizations, early rejection
- **GPU support** — CUDA/OpenCL kernel for Ed25519 + SHA-256 + RIPEMD-160
- **Regex matching** — allow flexible pattern matching beyond prefix/suffix
- **Output formats** — JSON export, QR code generation
- **Benchmarks** — `cargo bench` with criterion

## Reporting Issues

- Use GitHub Issues
- Include your OS, Rust version (`rustc --version`), and CPU model
- For performance issues, include your `--release` build speed

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
