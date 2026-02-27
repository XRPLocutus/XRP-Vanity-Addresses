#pragma once
#include <cstdint>

// XRPL Base58Check encoding and pattern matching on GPU
// XRPL uses a custom Base58 alphabet (no 0, O, I, l)

// XRPL Base58 alphabet (ripple)
__device__ __constant__ char XRPL_B58_ALPHABET[] =
    "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

// Big-integer division: divide a 25-byte big-endian number by 58
// Returns the remainder (0..57) and modifies the number in-place
__device__ __forceinline__
int bigint_divmod58(uint8_t* num, int len) {
    uint32_t rem = 0;
    for (int i = 0; i < len; i++) {
        uint32_t val = (rem << 8) | num[i];
        num[i] = uint8_t(val / 58);
        rem = val % 58;
    }
    return int(rem);
}

// Full Base58Check encode of 25-byte payload → address string
// Returns length of encoded string
__device__ int base58check_encode(const uint8_t payload[25], char* out) {
    // Work on a copy
    uint8_t temp[25];
    for (int i = 0; i < 25; i++) temp[i] = payload[i];

    // Extract Base58 digits (least significant first)
    char reversed[35];
    int pos = 0;

    // Keep dividing until number is zero
    for (int iter = 0; iter < 35; iter++) {
        // Check if temp is all zeros
        bool all_zero = true;
        for (int i = 0; i < 25; i++) {
            if (temp[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) break;

        int digit = bigint_divmod58(temp, 25);
        reversed[pos++] = XRPL_B58_ALPHABET[digit];
    }

    // Count leading zeros in payload → map to leading 'r' characters
    int leading = 0;
    for (int i = 0; i < 25; i++) {
        if (payload[i] != 0) break;
        leading++;
    }

    // Write output: leading 'r's + reversed digits
    int outpos = 0;
    for (int i = 0; i < leading; i++)
        out[outpos++] = 'r'; // XRPL alphabet[0] = 'r'

    for (int i = pos - 1; i >= 0; i--)
        out[outpos++] = reversed[i];

    out[outpos] = '\0';
    return outpos;
}

// ─────────────────────────────────────────────────────────────
// Pattern matching (early-exit optimized)
// ─────────────────────────────────────────────────────────────

__device__ __forceinline__
char to_lower_gpu(char c) {
    return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

// Check if the Base58Check-encoded address matches the search pattern
// Encodes just enough characters for the comparison
// pattern_type: 0=prefix, 1=suffix, 2=contains
__device__ bool check_pattern_match(
    const uint8_t payload[25],
    const char* pattern,
    int pattern_len,
    int pattern_type,    // 0=prefix, 1=suffix, 2=contains
    int case_insensitive
) {
    // For prefix matching, we can do a fast path:
    // XRPL addresses always start with 'r' (payload[0]=0x00)
    // So the prefix pattern is checked against chars after 'r'

    // Full encode (we need the full address for suffix/contains)
    char addr[36];
    int addr_len = base58check_encode(payload, addr);

    if (pattern_type == 0) {
        // Prefix match: compare pattern against addr[1..] (skip leading 'r')
        if (addr_len < pattern_len + 1) return false;
        for (int i = 0; i < pattern_len; i++) {
            char a = addr[i + 1];
            char p = pattern[i];
            if (case_insensitive) {
                if (to_lower_gpu(a) != to_lower_gpu(p)) return false;
            } else {
                if (a != p) return false;
            }
        }
        return true;
    }
    else if (pattern_type == 1) {
        // Suffix match
        if (addr_len < pattern_len) return false;
        int start = addr_len - pattern_len;
        for (int i = 0; i < pattern_len; i++) {
            char a = addr[start + i];
            char p = pattern[i];
            if (case_insensitive) {
                if (to_lower_gpu(a) != to_lower_gpu(p)) return false;
            } else {
                if (a != p) return false;
            }
        }
        return true;
    }
    else {
        // Contains match: substring search
        for (int start = 0; start <= addr_len - pattern_len; start++) {
            bool match = true;
            for (int i = 0; i < pattern_len; i++) {
                char a = addr[start + i];
                char p = pattern[i];
                if (case_insensitive) {
                    if (to_lower_gpu(a) != to_lower_gpu(p)) { match = false; break; }
                } else {
                    if (a != p) { match = false; break; }
                }
            }
            if (match) return true;
        }
        return false;
    }
}
