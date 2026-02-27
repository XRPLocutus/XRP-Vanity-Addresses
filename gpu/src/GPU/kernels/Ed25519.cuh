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

// Precomputed point: (Y+X, Y-X, 2*d*X*Y) — assumes Z=1
// Used for windowed scalar multiplication with fixed basepoint.
struct ge25519_precomp {
    fe25519 ypx;    // y + x
    fe25519 ymx;    // y - x
    fe25519 xy2d;   // 2 * d * x * y
};

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

// Point addition with precomputed point: r = p + q (p3 + precomp → p1p1)
// Same as add_cached but q.Z is implicitly 1, saving one fe_mul.
__device__ void ge25519_add_precomp(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_precomp* q) {
    fe25519 a, b, c;

    fe25519_add(&a, &p->Y, &p->X);     // a = Y1 + X1
    fe25519_sub(&b, &p->Y, &p->X);     // b = Y1 - X1
    fe25519_mul(&a, &a, &q->ypx);      // a = (Y1+X1) * (Y2+X2)
    fe25519_mul(&b, &b, &q->ymx);      // b = (Y1-X1) * (Y2-X2)
    fe25519_mul(&c, &p->T, &q->xy2d);  // c = T1 * 2*d*T2
    fe25519_add(&r->Z, &p->Z, &p->Z);  // r.Z = 2*Z1 (Z2=1, no multiply!)

    fe25519_sub(&r->X, &a, &b);        // E = a - b
    fe25519_add(&r->Y, &a, &b);        // H = a + b
    fe25519_add(&r->T, &r->Z, &c);     // G = 2*Z1 + c
    fe25519_sub(&r->Z, &r->Z, &c);     // F = 2*Z1 - c

    // Swap Z↔T for p1p1 convention (same reason as in ge25519_double)
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
// Precomputed basepoint table for windowed scalar multiplication
// BP_TABLE[i] = i * B in precomp form (y+x, y-x, 2*d*x*y)
// 16 entries for 4-bit (radix-16) windowed method.
// Computed from the Ed25519 basepoint, verified with Python.
// ─────────────────────────────────────────────────────────────

__device__ __constant__ ge25519_precomp BP_TABLE[16] = {
    // [0] = neutral (0 * B): x=0, y=1 → ypx=1, ymx=1, xy2d=0
    {{{1, 0, 0, 0, 0}},
     {{1, 0, 0, 0, 0}},
     {{0, 0, 0, 0, 0}}},

    // [1] = 1 * B
    {{{1288382639258501ULL, 245678601348599ULL, 269427782077623ULL, 1462984067271730ULL, 137412439391563ULL}},
     {{62697248952638ULL, 204681361388450ULL, 631292143396476ULL, 338455783676468ULL, 1213667448819585ULL}},
     {{301289933810280ULL, 1259582250014073ULL, 1422107436869536ULL, 796239922652654ULL, 1953934009299142ULL}}},

    // [2] = 2 * B
    {{{1380971894829527ULL, 790832306631236ULL, 2067202295274102ULL, 1995808275510000ULL, 1566530869037010ULL}},
     {{463307831301544ULL, 432984605774163ULL, 1610641361907204ULL, 750899048855000ULL, 1894842303421586ULL}},
     {{748439484463711ULL, 1033211726465151ULL, 1396005112841647ULL, 1611506220286469ULL, 1972177495910992ULL}}},

    // [3] = 3 * B
    {{{1601611775252272ULL, 1720807796594148ULL, 1132070835939856ULL, 1260455018889551ULL, 2147779492816911ULL}},
     {{316559037616741ULL, 2177824224946892ULL, 1459442586438991ULL, 1461528397712656ULL, 751590696113597ULL}},
     {{1850748884277385ULL, 1200145853858453ULL, 1068094770532492ULL, 672251375690438ULL, 1586055907191707ULL}}},

    // [4] = 4 * B
    {{{934282339813791ULL, 1846903124198670ULL, 1172395437954843ULL, 1007037127761661ULL, 1830588347719256ULL}},
     {{1694390458783935ULL, 1735906047636159ULL, 705069562067493ULL, 648033061693059ULL, 696214010414170ULL}},
     {{1121406372216585ULL, 192876649532226ULL, 190294192191717ULL, 1994165897297032ULL, 2245000007398739ULL}}},

    // [5] = 5 * B
    {{{769950342298419ULL, 132954430919746ULL, 844085933195555ULL, 974092374476333ULL, 726076285546016ULL}},
     {{425251763115706ULL, 608463272472562ULL, 442562545713235ULL, 837766094556764ULL, 374555092627893ULL}},
     {{1086255230780037ULL, 274979815921559ULL, 1960002765731872ULL, 929474102396301ULL, 1190409889297339ULL}}},

    // [6] = 6 * B
    {{{1388594989461809ULL, 316767091099457ULL, 394298842192982ULL, 1230079486801005ULL, 1440737038838979ULL}},
     {{7380825640100ULL, 146210432690483ULL, 304903576448906ULL, 1198869323871120ULL, 997689833219095ULL}},
     {{1181317918772081ULL, 114573476638901ULL, 262805072233344ULL, 265712217171332ULL, 294181933805782ULL}}},

    // [7] = 7 * B
    {{{665000864555967ULL, 2065379846933859ULL, 370231110385876ULL, 350988370788628ULL, 1233371373142985ULL}},
     {{2019367628972465ULL, 676711900706637ULL, 110710997811333ULL, 1108646842542025ULL, 517791959672113ULL}},
     {{965130719900578ULL, 247011430587952ULL, 526356006571389ULL, 91986625355052ULL, 2157223321444601ULL}}},

    // [8] = 8 * B
    {{{2068619540119183ULL, 1966274918058806ULL, 957728544705549ULL, 729906502578991ULL, 159834893065166ULL}},
     {{2073601412052185ULL, 31021124762708ULL, 264500969797082ULL, 248034690651703ULL, 1030252227928288ULL}},
     {{551790716293402ULL, 1989538725166328ULL, 801169423371717ULL, 2052451893578887ULL, 678432056995012ULL}}},

    // [9] = 9 * B
    {{{1802695059465007ULL, 1664899123557221ULL, 593559490740857ULL, 2160434469266659ULL, 927570450755031ULL}},
     {{1725674970513508ULL, 1933645953859181ULL, 1542344539275782ULL, 1767788773573747ULL, 1297447965928905ULL}},
     {{1381809363726107ULL, 1430341051343062ULL, 2061843536018959ULL, 1551778050872521ULL, 2036394857967624ULL}}},

    // [10] = 10 * B
    {{{1569908045411470ULL, 706723917266915ULL, 1500941167088851ULL, 271058246676941ULL, 1190527933001305ULL}},
     {{938493881647581ULL, 1913928661987006ULL, 2094455298711648ULL, 986546367603450ULL, 58515486184715ULL}},
     {{1454533688490200ULL, 416156769327623ULL, 1344514353803379ULL, 1816391251363763ULL, 259908591619060ULL}}},

    // [11] = 11 * B
    {{{1970894096313054ULL, 528066325833207ULL, 1619374932191227ULL, 2207306624415883ULL, 1169170329061080ULL}},
     {{2070390218572616ULL, 1458919061857835ULL, 624171843017421ULL, 1055332792707765ULL, 433987520732508ULL}},
     {{893653801273833ULL, 1168026499324677ULL, 1242553501121234ULL, 1306366254304474ULL, 1086752658510815ULL}}},

    // [12] = 12 * B
    {{{1548398643541305ULL, 838955728976966ULL, 116266075650295ULL, 1878116023572280ULL, 132675799667661ULL}},
     {{2114866412082361ULL, 591083254091949ULL, 940561138633470ULL, 412059816539947ULL, 2134627974686210ULL}},
     {{1571032457823571ULL, 1253760059932116ULL, 665829584253800ULL, 109400965270906ULL, 981221002823741ULL}}},

    // [13] = 13 * B
    {{{213454002618221ULL, 939771523987438ULL, 1159882208056014ULL, 317388369627517ULL, 621213314200687ULL}},
     {{1971678598905747ULL, 338026507889165ULL, 762398079972271ULL, 655096486107477ULL, 42299032696322ULL}},
     {{177130678690680ULL, 1754759263300204ULL, 1864311296286618ULL, 1180675631479880ULL, 1292726903152791ULL}}},

    // [14] = 14 * B
    {{{124159973735922ULL, 12085856625887ULL, 570609322991103ULL, 870869641855508ULL, 1947192330052817ULL}},
     {{996453150823040ULL, 557931626380283ULL, 1039170142840520ULL, 115485616863415ULL, 808203906823112ULL}},
     {{498660636760962ULL, 1605652986893012ULL, 893278769679967ULL, 1769999239723039ULL, 646478004325289ULL}}},

    // [15] = 15 * B
    {{{1913163449625248ULL, 460779200291993ULL, 2193883288642314ULL, 1008900146920800ULL, 1721983679009502ULL}},
     {{1070401523076875ULL, 1272492007800961ULL, 1910153608563310ULL, 2075579521696771ULL, 1191169788841221ULL}},
     {{692896803108118ULL, 500174642072499ULL, 2068223309439677ULL, 1162190621851337ULL, 1426986007309901ULL}}},
};

// ─────────────────────────────────────────────────────────────
// Scalar multiplication: Radix-16 windowed method
//
// Processes the 256-bit scalar as 64 radix-16 digits (4 bits each).
// Uses Horner evaluation from MSB to LSB:
//   Q = (...((e[63] * 16 + e[62]) * 16 + e[61]) * 16 + ...) * 16 + e[0]
//
// Cost: 252 doublings + 64 precomp adds vs 256 doublings + ~128 cached adds
// Key advantage: NO branch divergence — all threads do identical operations.
// ─────────────────────────────────────────────────────────────

__device__ void ed25519_scalarmult_base(ge25519_p3* result, const uint8_t scalar[32]) {
    ge25519_set_neutral(result);

    // Process 64 radix-16 digits from most significant to least
    for (int i = 63; i >= 0; i--) {
        // Multiply accumulator by 16 (4 doublings) — skip for first digit
        if (i < 63) {
            ge25519_p2 p2;
            ge25519_p1p1 pp;

            p2.X = result->X; p2.Y = result->Y; p2.Z = result->Z;
            ge25519_double(&pp, &p2);
            ge25519_p1p1_to_p2(&p2, &pp);

            ge25519_double(&pp, &p2);
            ge25519_p1p1_to_p2(&p2, &pp);

            ge25519_double(&pp, &p2);
            ge25519_p1p1_to_p2(&p2, &pp);

            ge25519_double(&pp, &p2);
            ge25519_p1p1_to_p3(result, &pp);
        }

        // Extract 4-bit digit: low nibble of byte i/2 for even i,
        // high nibble for odd i
        int byte_idx = i >> 1;           // i / 2
        int shift    = (i & 1) << 2;     // 0 or 4
        int digit    = (scalar[byte_idx] >> shift) & 0xF;

        // Add BP_TABLE[digit] to accumulator
        // When digit=0, this adds the neutral element (mathematically a no-op,
        // but we always execute it to avoid branch divergence).
        ge25519_p1p1 pp;
        ge25519_add_precomp(&pp, result, &BP_TABLE[digit]);
        ge25519_p1p1_to_p3(result, &pp);
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
