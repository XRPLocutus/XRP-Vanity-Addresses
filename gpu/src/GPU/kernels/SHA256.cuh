#pragma once
#include <cstdint>

// SHA-256 device implementation for CUDA
// Processes messages up to 64 bytes (single block after padding)
// Used for: address hashing (33-byte input), checksum (21/32-byte input)

namespace sha256_impl {

__device__ __constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__
uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__
uint32_t Sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

__device__ __forceinline__
uint32_t Sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

__device__ __forceinline__
uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }

__device__ __forceinline__
uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

__device__ __forceinline__
uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

__device__ __forceinline__
void store_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}

} // namespace sha256_impl

// SHA-256 for messages up to 55 bytes (fits in single 64-byte block after padding)
__device__ void sha256(const uint8_t* msg, int len, uint8_t digest[32]) {
    using namespace sha256_impl;

    // Pad message into a single 64-byte block
    uint8_t block[64];
    for (int i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    for (int i = len + 1; i < 56; i++) block[i] = 0;
    // Length in bits (big-endian 64-bit) — len <= 55, so high word is 0
    block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
    uint32_t bitlen = uint32_t(len) << 3;
    store_be32(block + 60, bitlen);

    // Parse block into 16 words
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = load_be32(block + i * 4);

    // Extend to 64 words
    for (int i = 16; i < 64; i++)
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];

    // Initial hash values
    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    // 64 rounds
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    // Final hash
    store_be32(digest +  0, a + 0x6a09e667);
    store_be32(digest +  4, b + 0xbb67ae85);
    store_be32(digest +  8, c + 0x3c6ef372);
    store_be32(digest + 12, d + 0xa54ff53a);
    store_be32(digest + 16, e + 0x510e527f);
    store_be32(digest + 20, f + 0x9b05688c);
    store_be32(digest + 24, g + 0x1f83d9ab);
    store_be32(digest + 28, h + 0x5be0cd19);
}
