#pragma once
#include <cstdint>

// CPU Ed25519 scalar multiplication (ref10-style, public domain)
// Used for CPU-side verification of GPU results.

// Derive Ed25519 public key from a 32-byte private key (already SHA-512-Half'd).
// Applies standard clamping: scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;
void cpu_ed25519_derive_pubkey(const uint8_t private_key[32], uint8_t public_key[32]);
