#pragma once
#include <cstdint>

// Curve25519 field arithmetic: GF(2^255 - 19)
// 5x51-bit limb representation (ref10 style)
// Each limb fits in a uint64_t with headroom for lazy reduction

// Field element: 5 limbs of up to 51 bits each
// Value = v[0] + v[1]*2^51 + v[2]*2^102 + v[3]*2^153 + v[4]*2^204
struct fe25519 {
    uint64_t v[5];
};

// 128-bit product helper using PTX inline assembly
struct uint128_t {
    uint64_t lo, hi;
};

__device__ __forceinline__
uint128_t mul64(uint64_t a, uint64_t b) {
    uint128_t r;
    r.lo = a * b;
    r.hi = __umul64hi(a, b);
    return r;
}

__device__ __forceinline__
void add128(uint128_t& acc, uint128_t val) {
    uint64_t old_lo = acc.lo;
    acc.lo += val.lo;
    acc.hi += val.hi + (acc.lo < old_lo ? 1ULL : 0ULL);
}

__device__ __forceinline__
void add128_u64(uint128_t& acc, uint64_t val) {
    uint64_t old_lo = acc.lo;
    acc.lo += val;
    acc.hi += (acc.lo < old_lo ? 1ULL : 0ULL);
}

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

static constexpr uint64_t MASK51 = (1ULL << 51) - 1;

// ─────────────────────────────────────────────────────────────
// Load / Store
// ─────────────────────────────────────────────────────────────

__device__ __forceinline__
void fe25519_to_bytes(uint8_t s[32], const fe25519* f) {
    // First, fully reduce
    fe25519 t = *f;
    // Carry propagation
    for (int i = 0; i < 4; i++) {
        t.v[i+1] += t.v[i] >> 51;
        t.v[i] &= MASK51;
    }
    t.v[0] += (t.v[4] >> 51) * 19;
    t.v[4] &= MASK51;
    // Second pass
    for (int i = 0; i < 4; i++) {
        t.v[i+1] += t.v[i] >> 51;
        t.v[i] &= MASK51;
    }
    t.v[0] += (t.v[4] >> 51) * 19;
    t.v[4] &= MASK51;

    // Reduce mod p: if t >= p, subtract p
    // p = 2^255 - 19
    uint64_t m = (t.v[0] >= 0x7FFFFFFFFFFED) ? 1 : 0;
    for (int i = 1; i < 4; i++)
        m &= (t.v[i] == MASK51) ? 1 : 0;
    m &= (t.v[4] >= 0x7FFFFFFFFFFFF) ? 1 : 0;

    if (m) {
        t.v[0] -= 0x7FFFFFFFFFFED;
        t.v[1] -= MASK51;
        t.v[2] -= MASK51;
        t.v[3] -= MASK51;
        t.v[4] -= 0x7FFFFFFFFFFFF;
    }

    // Reconstruct 256-bit number and write as 32 bytes little-endian
    uint64_t w0 = t.v[0] | (t.v[1] << 51);
    uint64_t w1 = (t.v[1] >> 13) | (t.v[2] << 38);
    uint64_t w2 = (t.v[2] >> 26) | (t.v[3] << 25);
    uint64_t w3 = (t.v[3] >> 39) | (t.v[4] << 12);

    for (int i = 0; i < 8; i++) {
        s[i]    = uint8_t(w0 >> (i * 8));
        s[i+8]  = uint8_t(w1 >> (i * 8));
        s[i+16] = uint8_t(w2 >> (i * 8));
        s[i+24] = uint8_t(w3 >> (i * 8));
    }
}

// ─────────────────────────────────────────────────────────────
// Arithmetic
// ─────────────────────────────────────────────────────────────

__device__ __forceinline__
void fe25519_add(fe25519* r, const fe25519* a, const fe25519* b) {
    for (int i = 0; i < 5; i++)
        r->v[i] = a->v[i] + b->v[i];
}

__device__ __forceinline__
void fe25519_sub(fe25519* r, const fe25519* a, const fe25519* b) {
    // Add 2*p to avoid underflow before subtracting
    // 2*p limbs: [0xFFFFFFFFFFFDA, MASK51*2, MASK51*2, MASK51*2, MASK51*2]
    // Actually we add a multiple that ensures each limb stays positive
    r->v[0] = (a->v[0] + 0xFFFFFFFFFFFDAULL) - b->v[0];
    r->v[1] = (a->v[1] + 0xFFFFFFFFFFFFEULL) - b->v[1];
    r->v[2] = (a->v[2] + 0xFFFFFFFFFFFFEULL) - b->v[2];
    r->v[3] = (a->v[3] + 0xFFFFFFFFFFFFEULL) - b->v[3];
    r->v[4] = (a->v[4] + 0xFFFFFFFFFFFFEULL) - b->v[4];
}

// Carry-reduce after add/sub
__device__ __forceinline__
void fe25519_carry(fe25519* r) {
    for (int i = 0; i < 4; i++) {
        r->v[i+1] += r->v[i] >> 51;
        r->v[i] &= MASK51;
    }
    r->v[0] += (r->v[4] >> 51) * 19;
    r->v[4] &= MASK51;
}

// Multiplication: r = a * b mod p
// Uses 25 partial products with lazy reduction
__device__ void fe25519_mul(fe25519* r, const fe25519* a, const fe25519* b) {
    const uint64_t* av = a->v;
    const uint64_t* bv = b->v;

    // Precompute b[i]*19 for reduction (since 2^255 ≡ 19 mod p)
    uint64_t b1_19 = bv[1] * 19;
    uint64_t b2_19 = bv[2] * 19;
    uint64_t b3_19 = bv[3] * 19;
    uint64_t b4_19 = bv[4] * 19;

    // Accumulate 128-bit products for each output limb
    // r[0] = a0*b0 + a1*b4_19 + a2*b3_19 + a3*b2_19 + a4*b1_19
    uint128_t t0 = mul64(av[0], bv[0]);
    add128(t0, mul64(av[1], b4_19));
    add128(t0, mul64(av[2], b3_19));
    add128(t0, mul64(av[3], b2_19));
    add128(t0, mul64(av[4], b1_19));

    // r[1] = a0*b1 + a1*b0 + a2*b4_19 + a3*b3_19 + a4*b2_19
    uint128_t t1 = mul64(av[0], bv[1]);
    add128(t1, mul64(av[1], bv[0]));
    add128(t1, mul64(av[2], b4_19));
    add128(t1, mul64(av[3], b3_19));
    add128(t1, mul64(av[4], b2_19));

    // r[2] = a0*b2 + a1*b1 + a2*b0 + a3*b4_19 + a4*b3_19
    uint128_t t2 = mul64(av[0], bv[2]);
    add128(t2, mul64(av[1], bv[1]));
    add128(t2, mul64(av[2], bv[0]));
    add128(t2, mul64(av[3], b4_19));
    add128(t2, mul64(av[4], b3_19));

    // r[3] = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*b4_19
    uint128_t t3 = mul64(av[0], bv[3]);
    add128(t3, mul64(av[1], bv[2]));
    add128(t3, mul64(av[2], bv[1]));
    add128(t3, mul64(av[3], bv[0]));
    add128(t3, mul64(av[4], b4_19));

    // r[4] = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
    uint128_t t4 = mul64(av[0], bv[4]);
    add128(t4, mul64(av[1], bv[3]));
    add128(t4, mul64(av[2], bv[2]));
    add128(t4, mul64(av[3], bv[1]));
    add128(t4, mul64(av[4], bv[0]));

    // Carry propagation (from 128-bit accumulators to 51-bit limbs)
    // Must add carry to the FULL 128-bit accumulator, not just the low 64 bits,
    // because t.lo + c can overflow 64 bits.
    r->v[0] = t0.lo & MASK51;
    uint64_t c = (t0.lo >> 51) | (t0.hi << 13);

    add128_u64(t1, c);
    r->v[1] = t1.lo & MASK51;
    c = (t1.lo >> 51) | (t1.hi << 13);

    add128_u64(t2, c);
    r->v[2] = t2.lo & MASK51;
    c = (t2.lo >> 51) | (t2.hi << 13);

    add128_u64(t3, c);
    r->v[3] = t3.lo & MASK51;
    c = (t3.lo >> 51) | (t3.hi << 13);

    add128_u64(t4, c);
    r->v[4] = t4.lo & MASK51;
    c = (t4.lo >> 51) | (t4.hi << 13);

    // Final reduction: c * 19 back into limb 0
    r->v[0] += c * 19;
    // One more carry from limb 0 to limb 1
    r->v[1] += r->v[0] >> 51;
    r->v[0] &= MASK51;
}

// Squaring: r = a^2 mod p (optimized: 15 unique products instead of 25)
__device__ void fe25519_sq(fe25519* r, const fe25519* a) {
    const uint64_t* av = a->v;

    uint64_t a0_2 = av[0] * 2;
    uint64_t a1_2 = av[1] * 2;

    uint64_t a3_38 = av[3] * 38;
    uint64_t a4_19 = av[4] * 19;
    uint64_t a4_38 = a4_19 * 2;

    // t0 = a0*a0 + a1*a4_38 + a2*a3_38
    uint128_t t0 = mul64(av[0], av[0]);
    add128(t0, mul64(av[1], a4_38));
    add128(t0, mul64(av[2], a3_38));

    // t1 = a0_2*a1 + a2*a4_38 + a3*a3_19 (a3*a3_19 = a3^2 * 19)
    uint128_t t1 = mul64(a0_2, av[1]);
    add128(t1, mul64(av[2], a4_38));
    add128(t1, mul64(av[3], av[3] * 19));

    // t2 = a0_2*a2 + a1*a1 + a3*a4_38
    uint128_t t2 = mul64(a0_2, av[2]);
    add128(t2, mul64(av[1], av[1]));
    add128(t2, mul64(av[3], a4_38));

    // t3 = a0_2*a3 + a1_2*a2 + a4*a4_19
    uint128_t t3 = mul64(a0_2, av[3]);
    add128(t3, mul64(a1_2, av[2]));
    add128(t3, mul64(av[4], a4_19));

    // t4 = a0_2*a4 + a1_2*a3 + a2*a2
    uint128_t t4 = mul64(a0_2, av[4]);
    add128(t4, mul64(a1_2, av[3]));
    add128(t4, mul64(av[2], av[2]));

    // Carry propagation (must use full 128-bit add for carry, same as mul)
    r->v[0] = t0.lo & MASK51;
    uint64_t c = (t0.lo >> 51) | (t0.hi << 13);

    add128_u64(t1, c);
    r->v[1] = t1.lo & MASK51;
    c = (t1.lo >> 51) | (t1.hi << 13);

    add128_u64(t2, c);
    r->v[2] = t2.lo & MASK51;
    c = (t2.lo >> 51) | (t2.hi << 13);

    add128_u64(t3, c);
    r->v[3] = t3.lo & MASK51;
    c = (t3.lo >> 51) | (t3.hi << 13);

    add128_u64(t4, c);
    r->v[4] = t4.lo & MASK51;
    c = (t4.lo >> 51) | (t4.hi << 13);

    r->v[0] += c * 19;
    r->v[1] += r->v[0] >> 51;
    r->v[0] &= MASK51;
}

// r = a^2 repeated n times
__device__ __forceinline__
void fe25519_sq_n(fe25519* r, const fe25519* a, int n) {
    fe25519_sq(r, a);
    for (int i = 1; i < n; i++)
        fe25519_sq(r, r);
}

// Negate: r = -a mod p = (2p - a)
__device__ __forceinline__
void fe25519_neg(fe25519* r, const fe25519* a) {
    fe25519 zero = {};
    fe25519_sub(r, &zero, a);
}

// Copy
__device__ __forceinline__
void fe25519_copy(fe25519* r, const fe25519* a) {
    for (int i = 0; i < 5; i++)
        r->v[i] = a->v[i];
}

// Set to 0
__device__ __forceinline__
void fe25519_zero(fe25519* r) {
    for (int i = 0; i < 5; i++)
        r->v[i] = 0;
}

// Set to 1
__device__ __forceinline__
void fe25519_one(fe25519* r) {
    r->v[0] = 1;
    for (int i = 1; i < 5; i++)
        r->v[i] = 0;
}

// Conditional swap: swap a and b if flag != 0, constant-time
__device__ __forceinline__
void fe25519_cswap(fe25519* a, fe25519* b, uint64_t flag) {
    uint64_t mask = ~(flag - 1); // 0 or 0xFFFF...
    for (int i = 0; i < 5; i++) {
        uint64_t x = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= x;
        b->v[i] ^= x;
    }
}

// Conditional move: r = (flag) ? a : r, constant-time
__device__ __forceinline__
void fe25519_cmov(fe25519* r, const fe25519* a, uint64_t flag) {
    uint64_t mask = ~(flag - 1);
    for (int i = 0; i < 5; i++) {
        r->v[i] ^= mask & (r->v[i] ^ a->v[i]);
    }
}

// Inversion: r = a^(-1) mod p = a^(p-2)
// Using Fermat's little theorem with an addition chain for p-2
__device__ void fe25519_inv(fe25519* r, const fe25519* a) {
    fe25519 t0, t1, t2, t3;

    fe25519_sq(&t0, a);           // t0 = a^2
    fe25519_sq_n(&t1, &t0, 2);   // t1 = a^8
    fe25519_mul(&t1, a, &t1);    // t1 = a^9
    fe25519_mul(&t0, &t0, &t1);  // t0 = a^11
    fe25519_sq(&t2, &t0);         // t2 = a^22
    fe25519_mul(&t1, &t1, &t2);  // t1 = a^(2^5 - 1) = a^31

    fe25519_sq_n(&t2, &t1, 5);
    fe25519_mul(&t1, &t2, &t1);  // t1 = a^(2^10 - 1)

    fe25519_sq_n(&t2, &t1, 10);
    fe25519_mul(&t2, &t2, &t1);  // t2 = a^(2^20 - 1)

    fe25519_sq_n(&t3, &t2, 20);
    fe25519_mul(&t2, &t3, &t2);  // t2 = a^(2^40 - 1)

    fe25519_sq_n(&t2, &t2, 10);
    fe25519_mul(&t1, &t2, &t1);  // t1 = a^(2^50 - 1)

    fe25519_sq_n(&t2, &t1, 50);
    fe25519_mul(&t2, &t2, &t1);  // t2 = a^(2^100 - 1)

    fe25519_sq_n(&t3, &t2, 100);
    fe25519_mul(&t2, &t3, &t2);  // t2 = a^(2^200 - 1)

    fe25519_sq_n(&t2, &t2, 50);
    fe25519_mul(&t1, &t2, &t1);  // t1 = a^(2^250 - 1)

    fe25519_sq_n(&t1, &t1, 5);
    fe25519_mul(r, &t1, &t0);    // r = a^(2^255 - 21) = a^(p-2)
}

