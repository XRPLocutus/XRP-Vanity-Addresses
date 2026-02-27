#pragma once
#include "Curve25519.cuh"

// Ed25519 on the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
// d = -121665/121666 mod p

// ─────────────────────────────────────────────────────────────
// Point representations
// ─────────────────────────────────────────────────────────────

// Extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, X*Y=Z*T
struct ge25519_p3 {
    fe25519 X, Y, Z, T;
};

// Completed coordinates (X:Y:Z:T) — intermediate form for add/double
struct ge25519_p1p1 {
    fe25519 X, Y, Z, T;
};

// Projective (X:Y:Z) without T coordinate
struct ge25519_p2 {
    fe25519 X, Y, Z;
};

// Precomputed point for addition: (y+x, y-x, 2*d*x*y)
struct ge25519_precomp {
    fe25519 ypx;  // y + x
    fe25519 ymx;  // y - x
    fe25519 xy2d; // 2 * d * x * y
};

// Cached point: (Y+X, Y-X, Z, T2d) for readdition
struct ge25519_cached {
    fe25519 YpX, YmX, Z, T2d;
};

// ─────────────────────────────────────────────────────────────
// Curve constant d = -121665/121666 mod p (5x51-bit limbs)
// ─────────────────────────────────────────────────────────────

__device__ __constant__ fe25519 ED25519_D = {{
    929955233495203ULL,
    466365720129213ULL,
    1662059464998953ULL,
    2033849074728123ULL,
    1442794654840575ULL
}};

__device__ __constant__ fe25519 ED25519_D2 = {{
    1859910466990425ULL,
    932731440258426ULL,
    1072319116312658ULL,
    1815898335770999ULL,
    633789495995903ULL
}};

// Precomputed basepoint table in constant memory
// 32 entries for 4-bit windowed scalar multiplication
// (This covers bits in groups of 4 with 64 doublings)
// Using 8 tables of 8 entries for a radix-16 approach
__device__ __constant__ ge25519_precomp BASEPOINT_TABLE[32][8];
// This will be initialized at startup from CPU-computed values

// ─────────────────────────────────────────────────────────────
// Point operations
// ─────────────────────────────────────────────────────────────

// Set to neutral element (0, 1, 1, 0)
__device__ __forceinline__
void ge25519_set_neutral(ge25519_p3* r) {
    fe25519_zero(&r->X);
    fe25519_one(&r->Y);
    fe25519_one(&r->Z);
    fe25519_zero(&r->T);
}

// p1p1 → p3 conversion: normalize
__device__ __forceinline__
void ge25519_p1p1_to_p3(ge25519_p3* r, const ge25519_p1p1* p) {
    fe25519_mul(&r->X, &p->X, &p->T);
    fe25519_mul(&r->Y, &p->Y, &p->Z);
    fe25519_mul(&r->Z, &p->Z, &p->T);
    fe25519_mul(&r->T, &p->X, &p->Y);
}

// p1p1 → p2 conversion
__device__ __forceinline__
void ge25519_p1p1_to_p2(ge25519_p2* r, const ge25519_p1p1* p) {
    fe25519_mul(&r->X, &p->X, &p->T);
    fe25519_mul(&r->Y, &p->Y, &p->Z);
    fe25519_mul(&r->Z, &p->Z, &p->T);
}

// p3 → cached conversion (for readdition)
__device__ __forceinline__
void ge25519_p3_to_cached(ge25519_cached* r, const ge25519_p3* p) {
    fe25519_add(&r->YpX, &p->Y, &p->X);
    fe25519_sub(&r->YmX, &p->Y, &p->X);
    fe25519_copy(&r->Z, &p->Z);
    fe25519_mul(&r->T2d, &p->T, &ED25519_D2);
}

// Point doubling: p1p1 = 2 * p2
// Formula from: https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
__device__ void ge25519_double(ge25519_p1p1* r, const ge25519_p2* p) {
    fe25519 a, b, c, d;

    fe25519_sq(&a, &p->X);            // A = X^2
    fe25519_sq(&b, &p->Y);            // B = Y^2
    fe25519_sq(&c, &p->Z);            // C = Z^2
    fe25519_add(&c, &c, &c);          // C = 2*Z^2
    fe25519_neg(&d, &a);              // D = -A (for twisted: a=-1)

    fe25519_add(&r->X, &p->X, &p->Y); // E = (X+Y)^2 - A - B
    fe25519_sq(&r->X, &r->X);
    fe25519_sub(&r->X, &r->X, &a);
    fe25519_sub(&r->X, &r->X, &b);    // r->X = E

    fe25519_add(&r->Z, &d, &b);       // r->Z = G = D + B
    fe25519_sub(&r->T, &r->Z, &c);    // r->T = F = G - C
    fe25519_sub(&r->Y, &d, &b);       // r->Y = H = D - B
    // p1p1 = (E, H, G, F) → p1p1_to_p3 produces (E*F, H*G, G*F, E*H)
}

// Point addition: r = p + q (p3 + cached → p1p1)
__device__ void ge25519_add_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q) {
    fe25519 a, b;

    fe25519_add(&r->X, &p->Y, &p->X);   // A = Y1 + X1
    fe25519_sub(&r->Y, &p->Y, &p->X);   // B = Y1 - X1
    fe25519_mul(&a, &r->X, &q->YpX);    // C = A * (Y2+X2)
    fe25519_mul(&b, &r->Y, &q->YmX);    // D = B * (Y2-X2)
    fe25519_mul(&r->T, &p->T, &q->T2d); // E = T1 * 2*d*T2
    fe25519_mul(&r->Z, &p->Z, &q->Z);   // F = Z1 * Z2
    fe25519_add(&r->Z, &r->Z, &r->Z);   // F = 2 * Z1 * Z2

    fe25519_sub(&r->X, &a, &b);          // r->X = E = C - D
    fe25519_add(&r->Y, &a, &b);          // r->Y = H = C + D
    fe25519_add(&a, &r->Z, &r->T);       // a = G = F + E
    fe25519_sub(&b, &r->Z, &r->T);       // b = F' = F - E (named H in EFD)

    fe25519_copy(&r->Z, &a);             // r->Z = G
    fe25519_copy(&r->T, &b);             // r->T = F'
    // p1p1 = (E, H, G, F') → p1p1_to_p3 produces (E*F', H*G, G*F', E*H)
}

// Subtraction: r = p - q (p3 + cached → p1p1)
// Same as add_cached but with negated q: swap YpX/YmX and swap +/- for T2d term
__device__ void ge25519_sub_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q) {
    fe25519 a, b;

    fe25519_add(&r->X, &p->Y, &p->X);
    fe25519_sub(&r->Y, &p->Y, &p->X);
    fe25519_mul(&a, &r->X, &q->YmX);    // Swap YpX/YmX for negation
    fe25519_mul(&b, &r->Y, &q->YpX);
    fe25519_mul(&r->T, &p->T, &q->T2d);
    fe25519_mul(&r->Z, &p->Z, &q->Z);
    fe25519_add(&r->Z, &r->Z, &r->Z);

    fe25519_sub(&r->X, &a, &b);          // r->X = E
    fe25519_add(&r->Y, &a, &b);          // r->Y = H
    fe25519_sub(&a, &r->Z, &r->T);       // a = F (swapped from add: D - C instead of D + C)
    fe25519_add(&b, &r->Z, &r->T);       // b = G (swapped from add: D + C instead of D - C)

    fe25519_copy(&r->Z, &b);             // r->Z = G
    fe25519_copy(&r->T, &a);             // r->T = F
    // p1p1 = (E, H, G, F) → p1p1_to_p3 produces (E*F, H*G, G*F, E*H)
}

// Addition with precomputed point (for basepoint table)
__device__ void ge25519_add_precomp(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_precomp* q) {
    fe25519 a, b, c;

    fe25519_add(&a, &p->Y, &p->X);       // A = Y1 + X1
    fe25519_sub(&b, &p->Y, &p->X);       // B = Y1 - X1
    fe25519_mul(&a, &a, &q->ypx);        // C = A * (y+x)
    fe25519_mul(&b, &b, &q->ymx);        // D = B * (y-x)
    fe25519_mul(&c, &p->T, &q->xy2d);    // E = T1 * 2*d*x*y

    fe25519_add(&r->Z, &p->Z, &p->Z);    // F = 2 * Z1

    fe25519_sub(&r->X, &a, &b);          // X3 = C - D
    fe25519_add(&r->Y, &a, &b);          // Y3 = C + D
    fe25519_add(&r->T, &r->Z, &c);       // G = F + E
    fe25519_sub(&r->Z, &r->Z, &c);       // H = F - E (stored in Z for p1p1)

    // p1p1_to_p3 computes: p3.X = p1p1.X * p1p1.T, p3.Y = p1p1.Y * p1p1.Z
    // ref10 requires: X3 = (C-D)*H, Y3 = (C+D)*G
    // We stored G in T-slot and H in Z-slot, so swap them.
    fe25519 tmp;
    fe25519_copy(&tmp, &r->Z);
    fe25519_copy(&r->Z, &r->T);
    fe25519_copy(&r->T, &tmp);
}

// Subtraction with precomputed point
__device__ void ge25519_sub_precomp(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_precomp* q) {
    fe25519 a, b, c;

    fe25519_add(&a, &p->Y, &p->X);
    fe25519_sub(&b, &p->Y, &p->X);
    fe25519_mul(&a, &a, &q->ymx);        // Swapped for negation
    fe25519_mul(&b, &b, &q->ypx);
    fe25519_mul(&c, &p->T, &q->xy2d);

    fe25519_add(&r->Z, &p->Z, &p->Z);

    fe25519_sub(&r->X, &a, &b);
    fe25519_add(&r->Y, &a, &b);
    fe25519_sub(&r->T, &r->Z, &c);       // Negated
    fe25519_add(&r->Z, &r->Z, &c);

    // Swap Z↔T for p1p1 convention (same as ge25519_add_precomp)
    fe25519 tmp;
    fe25519_copy(&tmp, &r->Z);
    fe25519_copy(&r->Z, &r->T);
    fe25519_copy(&r->T, &tmp);
}

// ─────────────────────────────────────────────────────────────
// Pack/Unpack (compressed Edwards point encoding)
// ─────────────────────────────────────────────────────────────

// Pack p3 → 32-byte compressed point
__device__ void ge25519_pack(uint8_t out[32], const ge25519_p3* p) {
    fe25519 recip, x, y;

    fe25519_inv(&recip, &p->Z);
    fe25519_mul(&x, &p->X, &recip);
    fe25519_mul(&y, &p->Y, &recip);

    fe25519_to_bytes(out, &y);

    // Set high bit of last byte to sign of x
    uint8_t x_bytes[32];
    fe25519_to_bytes(x_bytes, &x);
    out[31] |= (x_bytes[0] & 1) << 7;
}

// ─────────────────────────────────────────────────────────────
// Scalar multiplication (fixed-base, windowed)
// ─────────────────────────────────────────────────────────────

// Select from precomputed table
// Not constant-time — for vanity generation the scalar is not secret.
__device__ __forceinline__
void ge25519_select_precomp(ge25519_precomp* r, int pos, int b) {
    int bneg = (b < 0) ? 1 : 0;
    int babs = b - (((-bneg) & b) * 2);

    fe25519_one(&r->ypx);
    fe25519_one(&r->ymx);
    fe25519_zero(&r->xy2d);

    if (babs > 0 && babs <= 8) {
        *r = BASEPOINT_TABLE[pos][babs - 1];
    }

    if (bneg) {
        fe25519 tmp;
        fe25519_copy(&tmp, &r->ypx);
        fe25519_copy(&r->ypx, &r->ymx);
        fe25519_copy(&r->ymx, &tmp);
        fe25519_neg(&r->xy2d, &r->xy2d);
    }
}

// Ed25519 basepoint B (5x51-bit limbs)
__device__ __constant__ fe25519 ED25519_BX = {{
    1738742601995546ULL, 1146398526822698ULL,
    2070867633025821ULL, 562264141797630ULL, 587772402128613ULL
}};
__device__ __constant__ fe25519 ED25519_BY = {{
    1801439850948184ULL, 1351079888211148ULL,
    450359962737049ULL, 900719925474099ULL, 1801439850948198ULL
}};

// Simple double-and-add scalar multiplication: result = scalar * B
// No precomputed table — uses basepoint directly.
__device__ void ed25519_scalarmult_base(ge25519_p3* result, const uint8_t scalar[32]) {
    // Set up basepoint
    ge25519_p3 base;
    fe25519_copy(&base.X, &ED25519_BX);
    fe25519_copy(&base.Y, &ED25519_BY);
    fe25519_one(&base.Z);
    fe25519_mul(&base.T, &ED25519_BX, &ED25519_BY);

    ge25519_set_neutral(result);

    ge25519_cached bc;
    ge25519_p3_to_cached(&bc, &base);

    for (int i = 255; i >= 0; i--) {
        // Double
        ge25519_p2 p2;
        p2.X = result->X; p2.Y = result->Y; p2.Z = result->Z;
        ge25519_p1p1 r_p1p1;
        ge25519_double(&r_p1p1, &p2);
        ge25519_p1p1_to_p3(result, &r_p1p1);

        // If bit is set, add basepoint
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        if ((scalar[byte_idx] >> bit_idx) & 1) {
            ge25519_add_cached(&r_p1p1, result, &bc);
            ge25519_p1p1_to_p3(result, &r_p1p1);
        }
    }
}

// Ed25519: clamp scalar and multiply
// scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;
__device__ void ed25519_derive_pubkey(const uint8_t private_key[32], uint8_t public_key[32]) {
    // Clamp the scalar (standard Ed25519 clamping)
    uint8_t scalar[32];
    for (int i = 0; i < 32; i++) scalar[i] = private_key[i];
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    ge25519_p3 point;
    ed25519_scalarmult_base(&point, scalar);
    ge25519_pack(public_key, &point);
}
