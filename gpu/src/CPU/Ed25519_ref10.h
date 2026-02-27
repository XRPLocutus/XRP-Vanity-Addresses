#pragma once
#include <cstdint>

// CPU Ed25519 scalar multiplication (ref10-style, public domain)
// Used for CPU-side verification of GPU results and basepoint table generation.

// Derive Ed25519 public key from a 32-byte private key (already SHA-512-Half'd).
// Applies standard clamping: scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;
void cpu_ed25519_derive_pubkey(const uint8_t private_key[32], uint8_t public_key[32]);

// Precomputed basepoint table: 32 groups of 8 entries.
// Each entry is (y+x, y-x, 2*d*x*y) in 5x51-bit limb representation.
// Total: 32 * 8 * 3 * 5 = 3840 uint64_t values.
struct cpu_ge25519_precomp {
    uint64_t ypx[5];
    uint64_t ymx[5];
    uint64_t xy2d[5];
};

// Compute the full basepoint table on CPU.
// out must point to 32*8 = 256 entries.
void cpu_ed25519_compute_basepoint_table(cpu_ge25519_precomp out[32][8]);
