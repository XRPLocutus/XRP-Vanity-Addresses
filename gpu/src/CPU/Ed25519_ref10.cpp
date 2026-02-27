#include "Ed25519_ref10.h"
#include <cstring>

// ═══════════════════════════════════════════════════════════════
// CPU Ed25519 ref10-style implementation (public domain)
// 5x51-bit limb representation, matching the GPU Curve25519.cuh layout.
// ═══════════════════════════════════════════════════════════════

using u64 = uint64_t;

#ifdef _MSC_VER
#include <intrin.h>
// MSVC doesn't have __int128, use _umul128 intrinsic
struct u128 {
    u64 lo, hi;
    u128() : lo(0), hi(0) {}
    u128(u64 v) : lo(v), hi(0) {}
    u128& operator+=(const u128& o) {
        u64 old_lo = lo;
        lo += o.lo;
        hi += o.hi + (lo < old_lo ? 1 : 0);
        return *this;
    }
    u128& operator+=(u64 v) {
        u64 old_lo = lo;
        lo += v;
        hi += (lo < old_lo ? 1 : 0);
        return *this;
    }
    u128 operator>>(int n) const {
        if (n == 0) return *this;
        u128 r;
        if (n < 64) { r.lo = (lo >> n) | (hi << (64 - n)); r.hi = hi >> n; }
        else { r.lo = hi >> (n - 64); r.hi = 0; }
        return r;
    }
    explicit operator u64() const { return lo; }
    u64 operator&(u64 mask) const { return lo & mask; }
};
static inline u128 mul128(u64 a, u64 b) {
    u128 r;
    r.lo = _umul128(a, b, &r.hi);
    return r;
}
#define MUL128(a, b) mul128(a, b)
#else
using u128 = unsigned __int128;
#define MUL128(a, b) ((u128)(a) * (u128)(b))
#endif

static constexpr u64 MASK51 = (1ULL << 51) - 1;

// ─────────────────────────────────────────────────────────────
// Field element (5x51-bit limbs)
// ─────────────────────────────────────────────────────────────

struct fe { u64 v[5]; };

static void fe_zero(fe* r) { for (int i = 0; i < 5; i++) r->v[i] = 0; }
static void fe_one(fe* r) { r->v[0] = 1; for (int i = 1; i < 5; i++) r->v[i] = 0; }
static void fe_copy(fe* r, const fe* a) { for (int i = 0; i < 5; i++) r->v[i] = a->v[i]; }

static void fe_add(fe* r, const fe* a, const fe* b) {
    for (int i = 0; i < 5; i++) r->v[i] = a->v[i] + b->v[i];
}

static void fe_sub(fe* r, const fe* a, const fe* b) {
    r->v[0] = (a->v[0] + 0xFFFFFFFFFFFDAULL) - b->v[0];
    r->v[1] = (a->v[1] + 0xFFFFFFFFFFFFEULL) - b->v[1];
    r->v[2] = (a->v[2] + 0xFFFFFFFFFFFFEULL) - b->v[2];
    r->v[3] = (a->v[3] + 0xFFFFFFFFFFFFEULL) - b->v[3];
    r->v[4] = (a->v[4] + 0xFFFFFFFFFFFFEULL) - b->v[4];
}

static void fe_carry(fe* r) {
    for (int i = 0; i < 4; i++) { r->v[i+1] += r->v[i] >> 51; r->v[i] &= MASK51; }
    r->v[0] += (r->v[4] >> 51) * 19; r->v[4] &= MASK51;
}

static void fe_mul(fe* r, const fe* a, const fe* b) {
    const u64* av = a->v;
    const u64* bv = b->v;
    u64 b1_19 = bv[1]*19, b2_19 = bv[2]*19, b3_19 = bv[3]*19, b4_19 = bv[4]*19;

    u128 t0 = MUL128(av[0],bv[0]); t0 += MUL128(av[1],b4_19); t0 += MUL128(av[2],b3_19); t0 += MUL128(av[3],b2_19); t0 += MUL128(av[4],b1_19);
    u128 t1 = MUL128(av[0],bv[1]); t1 += MUL128(av[1],bv[0]);  t1 += MUL128(av[2],b4_19); t1 += MUL128(av[3],b3_19); t1 += MUL128(av[4],b2_19);
    u128 t2 = MUL128(av[0],bv[2]); t2 += MUL128(av[1],bv[1]);  t2 += MUL128(av[2],bv[0]);  t2 += MUL128(av[3],b4_19); t2 += MUL128(av[4],b3_19);
    u128 t3 = MUL128(av[0],bv[3]); t3 += MUL128(av[1],bv[2]);  t3 += MUL128(av[2],bv[1]);  t3 += MUL128(av[3],bv[0]);  t3 += MUL128(av[4],b4_19);
    u128 t4 = MUL128(av[0],bv[4]); t4 += MUL128(av[1],bv[3]);  t4 += MUL128(av[2],bv[2]);  t4 += MUL128(av[3],bv[1]);  t4 += MUL128(av[4],bv[0]);

    r->v[0] = (u64)t0 & MASK51; u64 c = (u64)(t0 >> 51);
    t1 += c; r->v[1] = (u64)t1 & MASK51; c = (u64)(t1 >> 51);
    t2 += c; r->v[2] = (u64)t2 & MASK51; c = (u64)(t2 >> 51);
    t3 += c; r->v[3] = (u64)t3 & MASK51; c = (u64)(t3 >> 51);
    t4 += c; r->v[4] = (u64)t4 & MASK51; c = (u64)(t4 >> 51);
    r->v[0] += c * 19; r->v[1] += r->v[0] >> 51; r->v[0] &= MASK51;
}

static void fe_sq(fe* r, const fe* a) {
    const u64* av = a->v;
    u64 a0_2 = av[0]*2, a1_2 = av[1]*2;
    u64 a3_38 = av[3]*38, a4_19 = av[4]*19, a4_38 = a4_19*2;

    u128 t0 = MUL128(av[0],av[0]); t0 += MUL128(av[1],a4_38); t0 += MUL128(av[2],a3_38);
    u128 t1 = MUL128(a0_2,av[1]);  t1 += MUL128(av[2],a4_38); t1 += MUL128(av[3],av[3]*19);
    u128 t2 = MUL128(a0_2,av[2]);  t2 += MUL128(av[1],av[1]); t2 += MUL128(av[3],a4_38);
    u128 t3 = MUL128(a0_2,av[3]);  t3 += MUL128(a1_2,av[2]);  t3 += MUL128(av[4],a4_19);
    u128 t4 = MUL128(a0_2,av[4]);  t4 += MUL128(a1_2,av[3]);  t4 += MUL128(av[2],av[2]);

    r->v[0] = (u64)t0 & MASK51; u64 c = (u64)(t0 >> 51);
    t1 += c; r->v[1] = (u64)t1 & MASK51; c = (u64)(t1 >> 51);
    t2 += c; r->v[2] = (u64)t2 & MASK51; c = (u64)(t2 >> 51);
    t3 += c; r->v[3] = (u64)t3 & MASK51; c = (u64)(t3 >> 51);
    t4 += c; r->v[4] = (u64)t4 & MASK51; c = (u64)(t4 >> 51);
    r->v[0] += c * 19; r->v[1] += r->v[0] >> 51; r->v[0] &= MASK51;
}

static void fe_sq_n(fe* r, const fe* a, int n) {
    fe_sq(r, a); for (int i = 1; i < n; i++) fe_sq(r, r);
}

static void fe_neg(fe* r, const fe* a) { fe z; fe_zero(&z); fe_sub(r, &z, a); }

static void fe_inv(fe* r, const fe* a) {
    fe t0, t1, t2, t3;
    fe_sq(&t0, a); fe_sq_n(&t1, &t0, 2); fe_mul(&t1, a, &t1);
    fe_mul(&t0, &t0, &t1); fe_sq(&t2, &t0); fe_mul(&t1, &t1, &t2);
    fe_sq_n(&t2, &t1, 5); fe_mul(&t1, &t2, &t1);
    fe_sq_n(&t2, &t1, 10); fe_mul(&t2, &t2, &t1);
    fe_sq_n(&t3, &t2, 20); fe_mul(&t2, &t3, &t2);
    fe_sq_n(&t2, &t2, 10); fe_mul(&t1, &t2, &t1);
    fe_sq_n(&t2, &t1, 50); fe_mul(&t2, &t2, &t1);
    fe_sq_n(&t3, &t2, 100); fe_mul(&t2, &t3, &t2);
    fe_sq_n(&t2, &t2, 50); fe_mul(&t1, &t2, &t1);
    fe_sq_n(&t1, &t1, 5); fe_mul(r, &t1, &t0);
}

static void fe_from_bytes(fe* r, const uint8_t s[32]) {
    u64 w0=0, w1=0, w2=0, w3=0;
    for (int i = 0; i < 8; i++) {
        w0 |= (u64)s[i]    << (i*8);
        w1 |= (u64)s[i+8]  << (i*8);
        w2 |= (u64)s[i+16] << (i*8);
        w3 |= (u64)s[i+24] << (i*8);
    }
    r->v[0] = w0 & MASK51;
    r->v[1] = ((w0 >> 51) | (w1 << 13)) & MASK51;
    r->v[2] = ((w1 >> 38) | (w2 << 26)) & MASK51;
    r->v[3] = ((w2 >> 25) | (w3 << 39)) & MASK51;
    r->v[4] = (w3 >> 12) & MASK51;
}

static void fe_to_bytes(uint8_t s[32], const fe* f) {
    fe t = *f;
    for (int i = 0; i < 4; i++) { t.v[i+1] += t.v[i] >> 51; t.v[i] &= MASK51; }
    t.v[0] += (t.v[4] >> 51) * 19; t.v[4] &= MASK51;
    for (int i = 0; i < 4; i++) { t.v[i+1] += t.v[i] >> 51; t.v[i] &= MASK51; }
    t.v[0] += (t.v[4] >> 51) * 19; t.v[4] &= MASK51;

    u64 m = (t.v[0] >= 0x7FFFFFFFFFFEDULL) ? 1 : 0;
    for (int i = 1; i < 4; i++) m &= (t.v[i] == MASK51) ? 1 : 0;
    m &= (t.v[4] >= 0x7FFFFFFFFFFFFULL) ? 1 : 0;
    if (m) { t.v[0] -= 0x7FFFFFFFFFFEDULL; t.v[1] -= MASK51; t.v[2] -= MASK51; t.v[3] -= MASK51; t.v[4] -= 0x7FFFFFFFFFFFFULL; }

    u64 r0 = t.v[0] | (t.v[1] << 51);
    u64 r1 = (t.v[1] >> 13) | (t.v[2] << 38);
    u64 r2 = (t.v[2] >> 26) | (t.v[3] << 25);
    u64 r3 = (t.v[3] >> 39) | (t.v[4] << 12);
    for (int i = 0; i < 8; i++) {
        s[i]    = (uint8_t)(r0 >> (i*8));
        s[i+8]  = (uint8_t)(r1 >> (i*8));
        s[i+16] = (uint8_t)(r2 >> (i*8));
        s[i+24] = (uint8_t)(r3 >> (i*8));
    }
}

// ─────────────────────────────────────────────────────────────
// Point types
// ─────────────────────────────────────────────────────────────

struct ge_p3  { fe X, Y, Z, T; };
struct ge_p1p1 { fe X, Y, Z, T; };
struct ge_p2  { fe X, Y, Z; };
struct ge_precomp { fe ypx, ymx, xy2d; };
struct ge_cached { fe YpX, YmX, Z, T2d; };

// d = -121665/121666 mod p
static const fe ED_D = {{ 929955233495203ULL, 466365720129213ULL, 1662059464998953ULL, 2033849074728123ULL, 1442794654840575ULL }};
static const fe ED_D2 = {{ 1859910466990425ULL, 932731440258426ULL, 1072319116312658ULL, 1815898335770999ULL, 633789495995903ULL }};

// Ed25519 basepoint B
static const fe B_X = {{ 1738742601995546ULL, 1146398526822698ULL, 2070867633025821ULL, 562264141797630ULL, 587772402128613ULL }};
static const fe B_Y = {{ 1801439850948184ULL, 1351079888211148ULL, 450359962737049ULL, 900719925474099ULL, 1801439850948198ULL }};

// ─────────────────────────────────────────────────────────────
// Point operations
// ─────────────────────────────────────────────────────────────

static void ge_set_neutral(ge_p3* r) {
    fe_zero(&r->X); fe_one(&r->Y); fe_one(&r->Z); fe_zero(&r->T);
}

static void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p) {
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
    fe_mul(&r->T, &p->X, &p->Y);
}

static void ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p) {
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
}

static void ge_p3_to_cached(ge_cached* r, const ge_p3* p) {
    fe_add(&r->YpX, &p->Y, &p->X);
    fe_sub(&r->YmX, &p->Y, &p->X);
    fe_copy(&r->Z, &p->Z);
    fe_mul(&r->T2d, &p->T, &ED_D2);
}

static void ge_double(ge_p1p1* r, const ge_p2* p) {
    fe a, b, c, d;
    fe_sq(&a, &p->X);                  // A = X^2
    fe_sq(&b, &p->Y);                  // B = Y^2
    fe_sq(&c, &p->Z); fe_add(&c, &c, &c); // C = 2*Z^2
    fe_neg(&d, &a);                    // D = -A (twisted: a=-1)

    fe_add(&r->X, &p->X, &p->Y);      // E = (X+Y)^2 - A - B
    fe_sq(&r->X, &r->X);
    fe_sub(&r->X, &r->X, &a);
    fe_sub(&r->X, &r->X, &b);         // r->X = E

    fe_add(&r->Z, &d, &b);            // r->Z = G = D+B
    fe_sub(&r->T, &r->Z, &c);         // r->T = F = G-C
    fe_sub(&r->Y, &d, &b);            // r->Y = H = D-B
    // p1p1 = (E, H, G, F) → p1p1_to_p3 produces (E*F, H*G, G*F, E*H)
}

static void ge_add_cached(ge_p1p1* r, const ge_p3* p, const ge_cached* q) {
    fe a, b;
    fe_add(&r->X, &p->Y, &p->X);       // Y1+X1
    fe_sub(&r->Y, &p->Y, &p->X);       // Y1-X1
    fe_mul(&a, &r->X, &q->YpX);        // a = (Y1+X1)*(Y2+X2)
    fe_mul(&b, &r->Y, &q->YmX);        // b = (Y1-X1)*(Y2-X2)
    fe_mul(&r->T, &p->T, &q->T2d);     // C = T1*2d*T2
    fe_mul(&r->Z, &p->Z, &q->Z);       // D_half = Z1*Z2
    fe_add(&r->Z, &r->Z, &r->Z);       // D = 2*Z1*Z2

    fe_sub(&r->X, &a, &b);             // r->X = E = a-b
    fe_add(&r->Y, &a, &b);             // r->Y = H = a+b
    fe_add(&a, &r->Z, &r->T);          // a = G = D+C
    fe_sub(&b, &r->Z, &r->T);          // b = F = D-C

    fe_copy(&r->Z, &a);                // r->Z = G
    fe_copy(&r->T, &b);                // r->T = F
    // p1p1 = (E, H, G, F) → p1p1_to_p3 produces (E*F, H*G, G*F, E*H)
}

static void ge_add_precomp(ge_p1p1* r, const ge_p3* p, const ge_precomp* q) {
    fe a, b, c;
    fe_add(&a, &p->Y, &p->X);
    fe_sub(&b, &p->Y, &p->X);
    fe_mul(&a, &a, &q->ypx);
    fe_mul(&b, &b, &q->ymx);
    fe_mul(&c, &p->T, &q->xy2d);
    fe_add(&r->Z, &p->Z, &p->Z);

    fe_sub(&r->X, &a, &b);
    fe_add(&r->Y, &a, &b);
    fe_add(&r->T, &r->Z, &c);
    fe_sub(&r->Z, &r->Z, &c);

    // Swap Z↔T for p1p1 convention
    fe tmp; fe_copy(&tmp, &r->Z); fe_copy(&r->Z, &r->T); fe_copy(&r->T, &tmp);
}

static void ge_pack(uint8_t out[32], const ge_p3* p) {
    fe recip, x, y;
    fe_inv(&recip, &p->Z);
    fe_mul(&x, &p->X, &recip);
    fe_mul(&y, &p->Y, &recip);
    fe_to_bytes(out, &y);
    uint8_t xb[32]; fe_to_bytes(xb, &x);
    out[31] |= (xb[0] & 1) << 7;
}

// ─────────────────────────────────────────────────────────────
// Scalar multiplication (double-and-add, no precomp table needed)
// ─────────────────────────────────────────────────────────────

static void ge_scalarmult_base_simple(ge_p3* result, const uint8_t scalar[32]) {
    // Set basepoint
    ge_p3 base;
    fe_copy(&base.X, &B_X);
    fe_copy(&base.Y, &B_Y);
    fe_one(&base.Z);
    fe_mul(&base.T, &B_X, &B_Y);

    ge_set_neutral(result);
    ge_cached bc;
    ge_p3_to_cached(&bc, &base);

    for (int i = 255; i >= 0; i--) {
        // Double
        ge_p2 p2; p2.X = result->X; p2.Y = result->Y; p2.Z = result->Z;
        ge_p1p1 p1p1;
        ge_double(&p1p1, &p2);
        ge_p1p1_to_p3(result, &p1p1);

        // If bit is set, add base
        int byte = i / 8;
        int bit = i % 8;
        if ((scalar[byte] >> bit) & 1) {
            ge_add_cached(&p1p1, result, &bc);
            ge_p1p1_to_p3(result, &p1p1);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────

void cpu_ed25519_derive_pubkey(const uint8_t private_key[32], uint8_t public_key[32]) {
    uint8_t scalar[32];
    memcpy(scalar, private_key, 32);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    ge_p3 point;
    ge_scalarmult_base_simple(&point, scalar);
    ge_pack(public_key, &point);
}

void cpu_ed25519_compute_basepoint_table(cpu_ge25519_precomp out[32][8]) {
    // Basepoint
    ge_p3 base;
    fe_copy(&base.X, &B_X);
    fe_copy(&base.Y, &B_Y);
    fe_one(&base.Z);
    fe_mul(&base.T, &B_X, &B_Y);

    // For each group i (0..31), we need multiples of B * 16^i
    // group_base = B * 16^i
    // Entries: 1*group_base, 2*group_base, ..., 8*group_base
    ge_p3 group_base;
    fe_copy(&group_base.X, &base.X);
    fe_copy(&group_base.Y, &base.Y);
    fe_copy(&group_base.Z, &base.Z);
    fe_copy(&group_base.T, &base.T);

    for (int i = 0; i < 32; i++) {
        // Compute 1*group_base through 8*group_base
        ge_p3 current;
        fe_copy(&current.X, &group_base.X);
        fe_copy(&current.Y, &group_base.Y);
        fe_copy(&current.Z, &group_base.Z);
        fe_copy(&current.T, &group_base.T);

        for (int j = 0; j < 8; j++) {
            // Normalize: convert to affine (Z=1) for the precomp table
            fe recip, x, y;
            fe_inv(&recip, &current.Z);
            fe_mul(&x, &current.X, &recip);
            fe_mul(&y, &current.Y, &recip);

            // precomp = (y+x, y-x, 2*d*x*y)
            fe ypx, ymx, xy2d, xy;
            fe_add(&ypx, &y, &x);
            fe_carry(&ypx);  // reduce to canonical 51-bit limbs
            fe_sub(&ymx, &y, &x);
            fe_carry(&ymx);  // reduce to canonical 51-bit limbs
            fe_mul(&xy, &x, &y);
            fe_mul(&xy2d, &xy, &ED_D2);

            // Copy limbs to output
            for (int k = 0; k < 5; k++) {
                out[i][j].ypx[k]  = ypx.v[k];
                out[i][j].ymx[k]  = ymx.v[k];
                out[i][j].xy2d[k] = xy2d.v[k];
            }

            // current += group_base
            if (j < 7) {
                ge_cached gc;
                ge_p3_to_cached(&gc, &group_base);
                ge_p1p1 p1p1;
                ge_add_cached(&p1p1, &current, &gc);
                ge_p1p1_to_p3(&current, &p1p1);
            }
        }

        // group_base *= 256 (double 8 times)
        // Each group covers 8 bits (2 radix-16 digits) of the scalar.
        // TABLE[j] = multiples of B * 256^j, used by the ref10 two-pass algorithm.
        for (int d = 0; d < 8; d++) {
            ge_p2 p2; p2.X = group_base.X; p2.Y = group_base.Y; p2.Z = group_base.Z;
            ge_p1p1 p1p1;
            ge_double(&p1p1, &p2);
            ge_p1p1_to_p3(&group_base, &p1p1);
        }
    }
}
