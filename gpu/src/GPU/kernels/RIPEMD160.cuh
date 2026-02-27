#pragma once
#include <cstdint>

// RIPEMD-160 device implementation for CUDA
// Input: 32-byte SHA-256 hash → Output: 20-byte Account ID

namespace ripemd160_impl {

__device__ __forceinline__
uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__
uint32_t load_le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

__device__ __forceinline__
void store_le32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

// Boolean functions
__device__ __forceinline__ uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
__device__ __forceinline__ uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
__device__ __forceinline__ uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
__device__ __forceinline__ uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
__device__ __forceinline__ uint32_t J(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

// Left-line message selection
__device__ __constant__ int RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};

// Right-line message selection
__device__ __constant__ int RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};

// Left-line shift amounts
__device__ __constant__ int SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};

// Right-line shift amounts
__device__ __constant__ int SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

} // namespace ripemd160_impl

// RIPEMD-160 for messages up to 55 bytes (single 64-byte block)
__device__ void ripemd160(const uint8_t* msg, int len, uint8_t digest[20]) {
    using namespace ripemd160_impl;

    // Pad into 64-byte block (little-endian length)
    uint8_t block[64];
    for (int i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    for (int i = len + 1; i < 56; i++) block[i] = 0;
    uint32_t bitlen = uint32_t(len) << 3;
    store_le32(block + 56, bitlen);
    block[60] = 0; block[61] = 0; block[62] = 0; block[63] = 0;

    // Parse 16 words (little-endian)
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
        X[i] = load_le32(block + i * 4);

    // Initial values
    uint32_t al = 0x67452301, bl = 0xefcdab89, cl = 0x98badcfe;
    uint32_t dl = 0x10325476, el = 0xc3d2e1f0;
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;

    // Round constants: left line
    const uint32_t KL[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
    // Round constants: right line
    const uint32_t KR[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

    // 80 rounds
    for (int j = 0; j < 80; j++) {
        int round = j / 16;
        uint32_t fl, fr;

        switch (round) {
            case 0: fl = F(bl, cl, dl); fr = J(br, cr, dr); break;
            case 1: fl = G(bl, cl, dl); fr = I(br, cr, dr); break;
            case 2: fl = H(bl, cl, dl); fr = H(br, cr, dr); break;
            case 3: fl = I(bl, cl, dl); fr = G(br, cr, dr); break;
            case 4: fl = J(bl, cl, dl); fr = F(br, cr, dr); break;
            default: fl = fr = 0; break;
        }

        uint32_t tl = rotl32(al + fl + X[RL[j]] + KL[round], SL[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = tl;

        uint32_t tr = rotl32(ar + fr + X[RR[j]] + KR[round], SR[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = tr;
    }

    // Final addition (cyclic shift of h-values per RIPEMD-160 spec)
    uint32_t h0 = 0xefcdab89 + cl + dr;   // h0' = h1 + CL + DR
    uint32_t h1 = 0x98badcfe + dl + er;    // h1' = h2 + DL + ER
    uint32_t h2 = 0x10325476 + el + ar;    // h2' = h3 + EL + AR
    uint32_t h3 = 0xc3d2e1f0 + al + br;   // h3' = h4 + AL + BR
    uint32_t h4 = 0x67452301 + bl + cr;    // h4' = h0 + BL + CR

    // Store as little-endian bytes
    store_le32(digest +  0, h0);
    store_le32(digest +  4, h1);
    store_le32(digest +  8, h2);
    store_le32(digest + 12, h3);
    store_le32(digest + 16, h4);
}
