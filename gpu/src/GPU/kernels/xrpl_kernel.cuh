#pragma once
#include "Philox.cuh"
#include "SHA512.cuh"
#include "SHA256.cuh"
#include "RIPEMD160.cuh"
#include "Ed25519.cuh"
#include "Base58.cuh"

// Number of iterations each thread processes per kernel launch
#define ITERATIONS_PER_THREAD 64

// ─────────────────────────────────────────────────────────────
// Search parameters (uploaded from host)
// ─────────────────────────────────────────────────────────────

struct SearchParams {
    char     pattern[32];      // Search pattern (null-terminated)
    int      pattern_len;      // Length of pattern
    int      pattern_type;     // 0=prefix, 1=suffix, 2=contains
    int      case_insensitive; // 1=case-insensitive matching
};

// ─────────────────────────────────────────────────────────────
// Result structure (written to global memory on match)
// ─────────────────────────────────────────────────────────────

struct GPUResult {
    uint8_t  entropy[16];      // 16-byte entropy (seed input)
    uint8_t  private_key[32];  // SHA-512-Half result
    uint8_t  public_key[32];   // Ed25519 compressed point
    uint8_t  account_id[20];   // RIPEMD-160 hash
    char     address[36];      // Full Base58Check address
};

// ─────────────────────────────────────────────────────────────
// Full XRPL vanity address search kernel
// ─────────────────────────────────────────────────────────────

__global__ void xrpl_vanity_kernel(
    const uint32_t* __restrict__ host_seed,     // 8 x uint32_t CSPRNG seed
    const SearchParams* __restrict__ params,     // Search parameters
    uint64_t start_iteration,                    // Starting iteration counter
    // Outputs:
    GPUResult* __restrict__ results,             // Array of result slots
    int* __restrict__ found_count,               // Atomic counter of found results
    int max_results,                             // Maximum results to collect
    uint64_t* __restrict__ total_checked         // Global progress counter
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t grid_size = gridDim.x * blockDim.x;

    // Load search params into registers
    int pat_len  = params->pattern_len;
    int pat_type = params->pattern_type;
    int pat_ci   = params->case_insensitive;

    for (int batch = 0; batch < ITERATIONS_PER_THREAD; batch++) {
        // Check if we've found enough results
        if (*found_count >= max_results) return;

        uint64_t iter = start_iteration + uint64_t(batch) * grid_size + tid;

        // ──── Step 1: Generate 16-byte entropy ────
        uint8_t entropy[16];
        generate_entropy(host_seed, blockIdx.x, threadIdx.x, iter, entropy);

        // ──── Step 2: SHA-512-Half → 32-byte private key ────
        uint8_t private_key[32];
        sha512_half(entropy, 16, private_key);

        // ──── Step 3: Ed25519 scalar multiply → public key ────
        uint8_t public_key[32];
        ed25519_derive_pubkey(private_key, public_key);

        // ──── Step 4: 0xED prefix + pubkey → SHA-256 → RIPEMD-160 ────
        uint8_t prefixed[33];
        prefixed[0] = 0xED;
        for (int i = 0; i < 32; i++) prefixed[i+1] = public_key[i];

        uint8_t sha_out[32];
        sha256(prefixed, 33, sha_out);

        uint8_t account_id[20];
        ripemd160(sha_out, 32, account_id);

        // ──── Step 5: Build Base58Check payload ────
        uint8_t payload[25];
        payload[0] = 0x00; // XRPL account type prefix
        for (int i = 0; i < 20; i++) payload[i+1] = account_id[i];

        // Double SHA-256 checksum
        sha256(payload, 21, sha_out);
        uint8_t sha_out2[32];
        sha256(sha_out, 32, sha_out2);
        payload[21] = sha_out2[0];
        payload[22] = sha_out2[1];
        payload[23] = sha_out2[2];
        payload[24] = sha_out2[3];

        // ──── Step 6: Pattern match ────
        if (check_pattern_match(payload, params->pattern, pat_len, pat_type, pat_ci)) {
            // Found a match! Atomically claim a result slot
            int slot = atomicAdd(found_count, 1);
            if (slot < max_results) {
                // Write result to global memory
                for (int i = 0; i < 16; i++) results[slot].entropy[i] = entropy[i];
                for (int i = 0; i < 32; i++) results[slot].private_key[i] = private_key[i];
                for (int i = 0; i < 32; i++) results[slot].public_key[i] = public_key[i];
                for (int i = 0; i < 20; i++) results[slot].account_id[i] = account_id[i];
                base58check_encode(payload, results[slot].address);
            }
        }
    }

    // Update global progress counter (one atomic per thread, not per iteration)
    atomicAdd(total_checked, uint64_t(ITERATIONS_PER_THREAD));
}

// ─────────────────────────────────────────────────────────────
// Single-derivation kernel (for KAT validation)
// ─────────────────────────────────────────────────────────────

__global__ void xrpl_derive_single(
    const uint8_t* __restrict__ entropy_in,      // 16 bytes
    GPUResult* __restrict__ result
) {
    // Only thread 0 runs
    if (threadIdx.x != 0 || blockIdx.x != 0) return;

    uint8_t entropy[16];
    for (int i = 0; i < 16; i++) entropy[i] = entropy_in[i];

    // Step 2: SHA-512-Half
    uint8_t private_key[32];
    sha512_half(entropy, 16, private_key);

    // Step 3: Ed25519
    uint8_t public_key[32];
    ed25519_derive_pubkey(private_key, public_key);

    // Step 4: SHA-256 + RIPEMD-160
    uint8_t prefixed[33];
    prefixed[0] = 0xED;
    for (int i = 0; i < 32; i++) prefixed[i+1] = public_key[i];

    uint8_t sha_out[32];
    sha256(prefixed, 33, sha_out);

    uint8_t account_id[20];
    ripemd160(sha_out, 32, account_id);

    // Step 5: Base58Check
    uint8_t payload[25];
    payload[0] = 0x00;
    for (int i = 0; i < 20; i++) payload[i+1] = account_id[i];
    sha256(payload, 21, sha_out);
    uint8_t sha_out2[32];
    sha256(sha_out, 32, sha_out2);
    payload[21] = sha_out2[0];
    payload[22] = sha_out2[1];
    payload[23] = sha_out2[2];
    payload[24] = sha_out2[3];

    // Write result
    for (int i = 0; i < 16; i++) result->entropy[i] = entropy[i];
    for (int i = 0; i < 32; i++) result->private_key[i] = private_key[i];
    for (int i = 0; i < 32; i++) result->public_key[i] = public_key[i];
    for (int i = 0; i < 20; i++) result->account_id[i] = account_id[i];
    base58check_encode(payload, result->address);
}
