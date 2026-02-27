#include "CPUVerify.h"
#include "Ed25519_ref10.h"
#include <cstdio>
#include <cstring>
#include <cctype>

// ─────────────────────────────────────────────────────────────
// Minimal CPU implementations of SHA-256, SHA-512, RIPEMD-160, Base58
// (Independent of GPU code — serves as ground truth for verification)
// ─────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════
// SHA-256 (CPU reference)
// ═══════════════════════════════════════════════════════════════

namespace cpu_sha256 {

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t Sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
static inline uint32_t Sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
static inline uint32_t sig0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x>>3); }
static inline uint32_t sig1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x>>10); }

static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];
}
static inline void put_be32(uint8_t* p, uint32_t v) {
    p[0]=uint8_t(v>>24); p[1]=uint8_t(v>>16); p[2]=uint8_t(v>>8); p[3]=uint8_t(v);
}

void hash(const uint8_t* msg, int len, uint8_t digest[32]) {
    if (len < 0 || len > 55) {
        fprintf(stderr, "FATAL: cpu_sha256::hash len=%d exceeds 55\n", len);
        abort();
    }
    uint8_t block[64] = {};
    if (len > 0) memcpy(block, msg, len);
    block[len] = 0x80;
    put_be32(block + 60, uint32_t(len) << 3);

    uint32_t W[64];
    for (int i = 0; i < 16; i++) W[i] = be32(block + i*4);
    for (int i = 16; i < 64; i++) W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    uint32_t a=0x6a09e667, b=0xbb67ae85, c=0x3c6ef372, d=0xa54ff53a;
    uint32_t e=0x510e527f, f=0x9b05688c, g=0x1f83d9ab, h=0x5be0cd19;

    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + Sig1(e) + Ch(e,f,g) + K[i] + W[i];
        uint32_t T2 = Sig0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    put_be32(digest+ 0, a+0x6a09e667); put_be32(digest+ 4, b+0xbb67ae85);
    put_be32(digest+ 8, c+0x3c6ef372); put_be32(digest+12, d+0xa54ff53a);
    put_be32(digest+16, e+0x510e527f); put_be32(digest+20, f+0x9b05688c);
    put_be32(digest+24, g+0x1f83d9ab); put_be32(digest+28, h+0x5be0cd19);
}

} // namespace cpu_sha256

// ═══════════════════════════════════════════════════════════════
// SHA-512 (CPU reference)
// ═══════════════════════════════════════════════════════════════

namespace cpu_sha512 {

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline uint64_t rotr(uint64_t x, int n) { return (x>>n)|(x<<(64-n)); }
static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) { return (x&y)^(~x&z); }
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x&y)^(x&z)^(y&z); }
static inline uint64_t Sig0(uint64_t x) { return rotr(x,28)^rotr(x,34)^rotr(x,39); }
static inline uint64_t Sig1(uint64_t x) { return rotr(x,14)^rotr(x,18)^rotr(x,41); }
static inline uint64_t sig0(uint64_t x) { return rotr(x,1)^rotr(x,8)^(x>>7); }
static inline uint64_t sig1(uint64_t x) { return rotr(x,19)^rotr(x,61)^(x>>6); }

static inline uint64_t be64(const uint8_t* p) {
    return (uint64_t(p[0])<<56)|(uint64_t(p[1])<<48)|(uint64_t(p[2])<<40)|(uint64_t(p[3])<<32)|
           (uint64_t(p[4])<<24)|(uint64_t(p[5])<<16)|(uint64_t(p[6])<<8)|p[7];
}
static inline void put_be64(uint8_t* p, uint64_t v) {
    p[0]=uint8_t(v>>56); p[1]=uint8_t(v>>48); p[2]=uint8_t(v>>40); p[3]=uint8_t(v>>32);
    p[4]=uint8_t(v>>24); p[5]=uint8_t(v>>16); p[6]=uint8_t(v>>8); p[7]=uint8_t(v);
}

void hash(const uint8_t* msg, int len, uint8_t digest[64]) {
    if (len < 0 || len > 111) { fprintf(stderr, "FATAL: cpu_sha512 len=%d\n", len); abort(); }
    uint8_t block[128] = {};
    if (len > 0) memcpy(block, msg, len);
    block[len] = 0x80;
    put_be64(block + 120, uint64_t(len) << 3);

    uint64_t W[80];
    for (int i = 0; i < 16; i++) W[i] = be64(block + i*8);
    for (int i = 16; i < 80; i++) W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    uint64_t a=0x6a09e667f3bcc908ULL, b=0xbb67ae8584caa73bULL;
    uint64_t c=0x3c6ef372fe94f82bULL, d=0xa54ff53a5f1d36f1ULL;
    uint64_t e=0x510e527fade682d1ULL, f=0x9b05688c2b3e6c1fULL;
    uint64_t g=0x1f83d9abfb41bd6bULL, h=0x5be0cd19137e2179ULL;

    for (int i = 0; i < 80; i++) {
        uint64_t T1 = h + Sig1(e) + Ch(e,f,g) + K[i] + W[i];
        uint64_t T2 = Sig0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    put_be64(digest+ 0, a+0x6a09e667f3bcc908ULL); put_be64(digest+ 8, b+0xbb67ae8584caa73bULL);
    put_be64(digest+16, c+0x3c6ef372fe94f82bULL); put_be64(digest+24, d+0xa54ff53a5f1d36f1ULL);
    put_be64(digest+32, e+0x510e527fade682d1ULL); put_be64(digest+40, f+0x9b05688c2b3e6c1fULL);
    put_be64(digest+48, g+0x1f83d9abfb41bd6bULL); put_be64(digest+56, h+0x5be0cd19137e2179ULL);
}

void hash_half(const uint8_t* msg, int len, uint8_t out[32]) {
    uint8_t full[64];
    hash(msg, len, full);
    memcpy(out, full, 32);
}

} // namespace cpu_sha512

// ═══════════════════════════════════════════════════════════════
// RIPEMD-160 (CPU reference)
// ═══════════════════════════════════════════════════════════════

namespace cpu_ripemd160 {

static inline uint32_t rotl(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
static inline uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
}
static inline void put_le32(uint8_t* p, uint32_t v) {
    p[0]=uint8_t(v); p[1]=uint8_t(v>>8); p[2]=uint8_t(v>>16); p[3]=uint8_t(v>>24);
}

static inline uint32_t F(uint32_t x,uint32_t y,uint32_t z){return x^y^z;}
static inline uint32_t G(uint32_t x,uint32_t y,uint32_t z){return (x&y)|(~x&z);}
static inline uint32_t H(uint32_t x,uint32_t y,uint32_t z){return (x|~y)^z;}
static inline uint32_t I(uint32_t x,uint32_t y,uint32_t z){return (x&z)|(y&~z);}
static inline uint32_t J(uint32_t x,uint32_t y,uint32_t z){return x^(y|~z);}

static const int RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
static const int RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
static const int SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
static const int SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

void hash(const uint8_t* msg, int len, uint8_t digest[20]) {
    if (len < 0 || len > 55) { fprintf(stderr, "FATAL: cpu_ripemd160 len=%d\n", len); abort(); }
    uint8_t block[64] = {};
    if (len > 0) memcpy(block, msg, len);
    block[len] = 0x80;
    put_le32(block + 56, uint32_t(len) << 3);

    uint32_t X[16];
    for (int i = 0; i < 16; i++) X[i] = le32(block + i*4);

    uint32_t al=0x67452301, bl=0xefcdab89, cl=0x98badcfe, dl=0x10325476, el=0xc3d2e1f0;
    uint32_t ar=al, br=bl, cr=cl, dr=dl, er=el;

    const uint32_t KL[5] = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
    const uint32_t KR[5] = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};

    for (int j = 0; j < 80; j++) {
        int r = j/16;
        uint32_t fl, fr;
        switch(r) {
            case 0: fl=F(bl,cl,dl); fr=J(br,cr,dr); break;
            case 1: fl=G(bl,cl,dl); fr=I(br,cr,dr); break;
            case 2: fl=H(bl,cl,dl); fr=H(br,cr,dr); break;
            case 3: fl=I(bl,cl,dl); fr=G(br,cr,dr); break;
            default:fl=J(bl,cl,dl); fr=F(br,cr,dr); break;
        }
        uint32_t tl = rotl(al+fl+X[RL[j]]+KL[r], SL[j])+el;
        al=el; el=dl; dl=rotl(cl,10); cl=bl; bl=tl;
        uint32_t tr = rotl(ar+fr+X[RR[j]]+KR[r], SR[j])+er;
        ar=er; er=dr; dr=rotl(cr,10); cr=br; br=tr;
    }

    // Final addition (cyclic shift of h-values per RIPEMD-160 spec)
    uint32_t t = 0xefcdab89+cl+dr;       // h0' = h1 + CL + DR
    put_le32(digest+ 0, t);
    put_le32(digest+ 4, 0x98badcfe+dl+er); // h1' = h2 + DL + ER
    put_le32(digest+ 8, 0x10325476+el+ar); // h2' = h3 + EL + AR
    put_le32(digest+12, 0xc3d2e1f0+al+br); // h3' = h4 + AL + BR
    put_le32(digest+16, 0x67452301+bl+cr); // h4' = h0 + BL + CR
}

} // namespace cpu_ripemd160

// ═══════════════════════════════════════════════════════════════
// Base58Check (CPU reference) — XRPL alphabet
// ═══════════════════════════════════════════════════════════════

namespace cpu_base58 {

static const char ALPHABET[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

std::string encode_check(const uint8_t* payload, int len) {
    // Work on a copy
    uint8_t temp[64];
    memcpy(temp, payload, len);

    // Extract digits (least significant first)
    char reversed[50];
    int pos = 0;
    while (true) {
        bool all_zero = true;
        for (int i = 0; i < len; i++)
            if (temp[i] != 0) { all_zero = false; break; }
        if (all_zero) break;

        uint32_t rem = 0;
        for (int i = 0; i < len; i++) {
            uint32_t val = (rem << 8) | temp[i];
            temp[i] = uint8_t(val / 58);
            rem = val % 58;
        }
        reversed[pos++] = ALPHABET[rem];
    }

    // Leading zeros → leading 'r'
    std::string result;
    for (int i = 0; i < len && payload[i] == 0; i++)
        result += 'r';
    for (int i = pos - 1; i >= 0; i--)
        result += reversed[i];

    return result;
}

} // namespace cpu_base58

// ═══════════════════════════════════════════════════════════════
// XRPL seed encoding (sEd... format)
// ═══════════════════════════════════════════════════════════════

namespace cpu_seed {

std::string encode(const uint8_t entropy[16]) {
    // XRPL Ed25519 family seed format (must match src/crypto.rs):
    // payload = [0x01, 0xE1, 0x4B] (3 prefix bytes) + entropy (16 bytes) = 19 bytes
    // checksum = SHA256(SHA256(payload[0..19]))[0..4]
    // base58(23 bytes) → "sEd..." (always 31 characters)
    uint8_t payload[23];
    payload[0] = 0x01;
    payload[1] = 0xE1;
    payload[2] = 0x4B;
    memcpy(payload + 3, entropy, 16);

    uint8_t hash1[32], hash2[32];
    cpu_sha256::hash(payload, 19, hash1);
    cpu_sha256::hash(hash1, 32, hash2);
    payload[19] = hash2[0];
    payload[20] = hash2[1];
    payload[21] = hash2[2];
    payload[22] = hash2[3];

    return cpu_base58::encode_check(payload, 23);
}

} // namespace cpu_seed

// ═══════════════════════════════════════════════════════════════
// CPUVerify implementation
// ═══════════════════════════════════════════════════════════════

CPUResult CPUVerify::derive(const uint8_t entropy[16]) {
    CPUResult r;
    memcpy(r.entropy, entropy, 16);

    // Step 1: SHA-512-Half → private key (Ed25519 "seed")
    cpu_sha512::hash_half(entropy, 16, r.private_key);

    // Step 2: RFC 8032 Ed25519 public key derivation:
    // SHA-512(seed) → first 32 bytes → clamp → scalar * B
    // (ed25519_dalek's SigningKey::from_bytes does this internally)
    uint8_t ed_hash[64];
    cpu_sha512::hash(r.private_key, 32, ed_hash);
    cpu_ed25519_derive_pubkey(ed_hash, r.public_key);

    // Step 3: 0xED + pubkey → SHA-256 → RIPEMD-160
    uint8_t prefixed[33];
    prefixed[0] = 0xED;
    memcpy(prefixed + 1, r.public_key, 32);

    uint8_t sha_out[32];
    cpu_sha256::hash(prefixed, 33, sha_out);
    cpu_ripemd160::hash(sha_out, 32, r.account_id);

    // Step 4: Base58Check
    uint8_t payload[25];
    payload[0] = 0x00;
    memcpy(payload + 1, r.account_id, 20);
    cpu_sha256::hash(payload, 21, sha_out);
    uint8_t sha_out2[32];
    cpu_sha256::hash(sha_out, 32, sha_out2);
    memcpy(payload + 21, sha_out2, 4);

    std::string addr = cpu_base58::encode_check(payload, 25);
    strncpy(r.address, addr.c_str(), 35);
    r.address[35] = '\0';

    // Step 5: Seed
    std::string seed = cpu_seed::encode(entropy);
    strncpy(r.seed, seed.c_str(), 31);
    r.seed[31] = '\0';

    return r;
}

bool CPUVerify::verify(const uint8_t entropy[16], const char* gpu_address) {
    CPUResult cpu = derive(entropy);
    return strcmp(cpu.address, gpu_address) == 0;
}

std::string CPUVerify::entropy_to_seed(const uint8_t entropy[16]) {
    return cpu_seed::encode(entropy);
}

bool CPUVerify::pattern_matches(const char* address,
                                 const char* pattern, int pattern_len,
                                 int pattern_type, bool case_insensitive) {
    int addr_len = (int)strlen(address);

    if (pattern_type == 0) {
        // Prefix (after 'r')
        if (addr_len < pattern_len + 1) return false;
        for (int i = 0; i < pattern_len; i++) {
            char a = address[i + 1];
            char p = pattern[i];
            if (case_insensitive) {
                if (tolower(a) != tolower(p)) return false;
            } else {
                if (a != p) return false;
            }
        }
        return true;
    }
    else if (pattern_type == 1) {
        // Suffix
        if (addr_len < pattern_len) return false;
        for (int i = 0; i < pattern_len; i++) {
            char a = address[addr_len - pattern_len + i];
            char p = pattern[i];
            if (case_insensitive) {
                if (tolower(a) != tolower(p)) return false;
            } else {
                if (a != p) return false;
            }
        }
        return true;
    }
    else {
        // Contains
        for (int s = 0; s <= addr_len - pattern_len; s++) {
            bool match = true;
            for (int i = 0; i < pattern_len; i++) {
                char a = address[s + i];
                char p = pattern[i];
                if (case_insensitive) {
                    if (tolower(a) != tolower(p)) { match = false; break; }
                } else {
                    if (a != p) { match = false; break; }
                }
            }
            if (match) return true;
        }
        return false;
    }
}

std::string CPUVerify::hex_encode(const uint8_t* data, int len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (int i = 0; i < len; i++) {
        result += hex_chars[data[i] >> 4];
        result += hex_chars[data[i] & 0x0F];
    }
    return result;
}

bool CPUVerify::run_kat() {
    printf("Running Known-Answer Tests (KAT)...\n");

    // KAT vectors generated from Rust v2.3 reference (src/crypto.rs)
    struct KATVector {
        uint8_t entropy[16];
        uint8_t private_key[32];
        uint8_t public_key[32];
        uint8_t account_id[20];
        const char* address;
        const char* seed;
    };

    static const KATVector vectors[] = {
        // Vector 0: All-zeros entropy
        {
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
            {0x0b,0x6c,0xba,0xc8,0x38,0xdf,0xe7,0xf4,0x7e,0xa1,0xbd,0x0d,0xf0,0x0e,0xc2,0x82,0xfd,0xf4,0x55,0x10,0xc9,0x21,0x61,0x07,0x2c,0xcf,0xb8,0x40,0x35,0x39,0x0c,0x4d},
            {0x1a,0x7c,0x08,0x28,0x46,0xcf,0xf5,0x8f,0xf9,0xa8,0x92,0xba,0x4b,0xa2,0x59,0x31,0x51,0xcc,0xf1,0xdb,0xa5,0x9f,0x37,0x71,0x4c,0xc9,0xed,0x39,0x82,0x4a,0xf8,0x5f},
            {0x62,0x9c,0xcc,0x14,0x4a,0xc8,0x46,0x45,0x61,0xf1,0x1d,0x88,0x70,0xa5,0x7d,0xc3,0x76,0xa0,0xd1,0x91},
            "r9zRhGr7b6xPekLvT6wP4qNdWMryaumZS7",
            "sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE"
        },
        // Vector 1: All-0xFF entropy
        {
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xf6,0x37,0xfb,0x3a,0xe4,0x4b,0x36,0x46,0xcf,0xd3,0x37,0x1d,0x92,0xb3,0x8c,0x00,0xad,0x34,0x29,0x93,0xe5,0x5e,0x21,0x3e,0x38,0x50,0xe7,0x2b,0x7f,0xcb,0xad,0x4d},
            {0x3e,0x2a,0xc4,0x34,0xea,0x40,0x1b,0x70,0x7b,0x1d,0x38,0xa8,0xd0,0xbe,0x50,0xcf,0x42,0x36,0x57,0xde,0xed,0x4a,0xe7,0x06,0xaa,0xb1,0x06,0xc0,0xaf,0xfa,0xbd,0x6b},
            {0x55,0x81,0x71,0x3a,0x49,0x4b,0xf6,0xd3,0xf0,0x9f,0x81,0x84,0x0d,0x44,0x03,0xce,0x52,0x10,0xd9,0x2b},
            "r3ofWfcM2UoBw6fnP7BFbsY5XneivkGyrY",
            "sEdV19BLfeQeKdEXyYA4NhjPJe6XBfG"
        },
        // Vector 2: Sequential 0x01..0x10 entropy
        {
            {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10},
            {0xb4,0xc4,0xe0,0x46,0x82,0x6b,0xd2,0x61,0x90,0xd0,0x97,0x15,0xfc,0x31,0xf4,0xe6,0xa7,0x28,0x20,0x4e,0xad,0xd1,0x12,0x90,0x5b,0x08,0xb1,0x4b,0x7f,0x15,0xc4,0xf3},
            {0x01,0xfa,0x53,0xfa,0x5a,0x7e,0x77,0x79,0x8f,0x88,0x2e,0xce,0x20,0xb1,0xab,0xc0,0x0b,0xb3,0x58,0xa9,0xe5,0x5a,0x20,0x2d,0x0d,0x06,0x76,0xbd,0x0c,0xe3,0x7a,0x63},
            {0xd2,0x8b,0x17,0x7e,0x48,0xd9,0xa8,0xd0,0x57,0xe7,0x0f,0x7e,0x46,0x4b,0x49,0x83,0x67,0x28,0x1b,0x98},
            "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD",
            "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r"
        },
    };

    int num_vectors = sizeof(vectors) / sizeof(vectors[0]);
    bool all_ok = true;

    for (int v = 0; v < num_vectors; v++) {
        const KATVector& kat = vectors[v];
        printf("  KAT vector %d: ", v);

        CPUResult cpu = derive(kat.entropy);

        // Check private key (SHA-512-Half)
        if (memcmp(cpu.private_key, kat.private_key, 32) != 0) {
            fprintf(stderr, "FAIL private_key\n");
            fprintf(stderr, "    expected: %s\n", hex_encode(kat.private_key, 32).c_str());
            fprintf(stderr, "    got:      %s\n", hex_encode(cpu.private_key, 32).c_str());
            all_ok = false;
            continue;
        }

        // Check public key (Ed25519)
        if (memcmp(cpu.public_key, kat.public_key, 32) != 0) {
            fprintf(stderr, "FAIL public_key\n");
            fprintf(stderr, "    expected: %s\n", hex_encode(kat.public_key, 32).c_str());
            fprintf(stderr, "    got:      %s\n", hex_encode(cpu.public_key, 32).c_str());
            all_ok = false;
            continue;
        }

        // Check account ID (SHA-256 + RIPEMD-160)
        if (memcmp(cpu.account_id, kat.account_id, 20) != 0) {
            fprintf(stderr, "FAIL account_id\n");
            fprintf(stderr, "    expected: %s\n", hex_encode(kat.account_id, 20).c_str());
            fprintf(stderr, "    got:      %s\n", hex_encode(cpu.account_id, 20).c_str());
            all_ok = false;
            continue;
        }

        // Check address (Base58Check)
        if (strcmp(cpu.address, kat.address) != 0) {
            fprintf(stderr, "FAIL address\n");
            fprintf(stderr, "    expected: %s\n", kat.address);
            fprintf(stderr, "    got:      %s\n", cpu.address);
            all_ok = false;
            continue;
        }

        // Check seed (sEd... format)
        if (strcmp(cpu.seed, kat.seed) != 0) {
            fprintf(stderr, "FAIL seed\n");
            fprintf(stderr, "    expected: %s\n", kat.seed);
            fprintf(stderr, "    got:      %s\n", cpu.seed);
            all_ok = false;
            continue;
        }

        printf("OK (address=%s, seed=%s)\n", cpu.address, cpu.seed);
    }

    if (all_ok) {
        printf("All %d KAT vectors passed.\n\n", num_vectors);
    } else {
        fprintf(stderr, "KAT FAILURES detected!\n\n");
    }
    return all_ok;
}
