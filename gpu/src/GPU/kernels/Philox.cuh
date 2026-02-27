#pragma once
#include <cstdint>

// Philox-4x32-10: Counter-based CSPRNG (NVIDIA cuRAND standard)
// Each (key, counter) pair produces a unique 128-bit output.
// GPU-friendly: no state, no memory, pure arithmetic.

__device__ __forceinline__
void philox_round(uint32_t* ctr, const uint32_t* key) {
    // Philox S-box constants
    constexpr uint32_t PHILOX_M0 = 0xD2511F53u;
    constexpr uint32_t PHILOX_M1 = 0xCD9E8D57u;

    uint32_t hi0, lo0, hi1, lo1;

    lo0 = ctr[0] * PHILOX_M0;
    hi0 = __umulhi(ctr[0], PHILOX_M0);

    lo1 = ctr[2] * PHILOX_M1;
    hi1 = __umulhi(ctr[2], PHILOX_M1);

    ctr[0] = hi1 ^ ctr[1] ^ key[0];
    ctr[1] = lo1;
    ctr[2] = hi0 ^ ctr[3] ^ key[1];
    ctr[3] = lo0;
}

__device__ __forceinline__
void philox4x32_10(uint32_t ctr[4], uint32_t key[2]) {
    // Weyl sequence bump constants
    constexpr uint32_t PHILOX_W0 = 0x9E3779B9u;
    constexpr uint32_t PHILOX_W1 = 0xBB67AE85u;

    // 10 rounds of Philox
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key); key[0] += PHILOX_W0; key[1] += PHILOX_W1;
    philox_round(ctr, key);
}

// Generate 16 bytes of entropy for a specific thread and iteration
// Uses all 256 bits of the host seed (8 x uint32_t)
__device__ __forceinline__
void generate_entropy(
    const uint32_t* host_seed,
    uint32_t block_id, uint32_t thread_id,
    uint64_t iteration, uint8_t entropy[16]
) {
    uint32_t ctr[4] = {
        thread_id   ^ host_seed[2],
        block_id    ^ host_seed[3],
        static_cast<uint32_t>(iteration)       ^ host_seed[4],
        static_cast<uint32_t>(iteration >> 32)  ^ host_seed[5]
    };
    uint32_t key[2] = {
        host_seed[0] ^ host_seed[6],
        host_seed[1] ^ host_seed[7]
    };
    philox4x32_10(ctr, key);
    reinterpret_cast<uint32_t*>(entropy)[0] = ctr[0];
    reinterpret_cast<uint32_t*>(entropy)[1] = ctr[1];
    reinterpret_cast<uint32_t*>(entropy)[2] = ctr[2];
    reinterpret_cast<uint32_t*>(entropy)[3] = ctr[3];
}
