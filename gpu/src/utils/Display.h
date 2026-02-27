#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include "Timer.h"

namespace Display {

constexpr int BOX_WIDTH = 84;

inline void top() {
    printf("\xE2\x95\x94");
    for (int i = 0; i < BOX_WIDTH; i++) printf("\xE2\x95\x90");
    printf("\xE2\x95\x97\n");
}

inline void bottom() {
    printf("\xE2\x95\x9A");
    for (int i = 0; i < BOX_WIDTH; i++) printf("\xE2\x95\x90");
    printf("\xE2\x95\x9D\n");
}

inline void rule() {
    printf("\xE2\x95\xA0");
    for (int i = 0; i < BOX_WIDTH; i++) printf("\xE2\x95\x90");
    printf("\xE2\x95\xA3\n");
}

inline void line(const char* label, const char* value) {
    char content[256];
    snprintf(content, sizeof(content), "  %-18s%s", label, value);
    int pad = BOX_WIDTH - (int)strlen(content);
    if (pad < 0) pad = 0;
    printf("\xE2\x95\x91%s%*s\xE2\x95\x91\n", content, pad, "");
}

inline void title(const char* text) {
    char content[256];
    snprintf(content, sizeof(content), "  %s", text);
    int pad = BOX_WIDTH - (int)strlen(content);
    if (pad < 0) pad = 0;
    printf("\xE2\x95\x91%s%*s\xE2\x95\x91\n", content, pad, "");
}

inline void empty() {
    printf("\xE2\x95\x91%*s\xE2\x95\x91\n", BOX_WIDTH, "");
}

// Estimate avg attempts for a pattern of length n: 58^n
inline uint64_t estimate_attempts(int pattern_len) {
    uint64_t result = 1;
    for (int i = 0; i < pattern_len; i++) {
        if (result > UINT64_MAX / 58) return UINT64_MAX;
        result *= 58;
    }
    return result;
}

}  // namespace Display
