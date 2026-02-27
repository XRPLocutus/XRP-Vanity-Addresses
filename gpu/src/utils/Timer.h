#pragma once
#include <chrono>
#include <string>
#include <cstdio>

class Timer {
public:
    Timer() : start_(std::chrono::high_resolution_clock::now()) {}

    void reset() { start_ = std::chrono::high_resolution_clock::now(); }

    double elapsed_ms() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - start_).count();
    }

    double elapsed_sec() const { return elapsed_ms() / 1000.0; }

    static std::string format_duration(double seconds) {
        char buf[64];
        if (seconds < 1.0)
            snprintf(buf, sizeof(buf), "%.0fms", seconds * 1000.0);
        else if (seconds < 60.0)
            snprintf(buf, sizeof(buf), "%.1fs", seconds);
        else if (seconds < 3600.0)
            snprintf(buf, sizeof(buf), "%.1f min", seconds / 60.0);
        else if (seconds < 86400.0)
            snprintf(buf, sizeof(buf), "%.1f hrs", seconds / 3600.0);
        else
            snprintf(buf, sizeof(buf), "%.1f days", seconds / 86400.0);
        return std::string(buf);
    }

    static std::string format_count(uint64_t n) {
        char buf[64];
        if (n >= 1000000000ULL)
            snprintf(buf, sizeof(buf), "%.2fB", n / 1e9);
        else if (n >= 1000000ULL)
            snprintf(buf, sizeof(buf), "%.2fM", n / 1e6);
        else if (n >= 1000ULL)
            snprintf(buf, sizeof(buf), "%.1fK", n / 1e3);
        else
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)n);
        return std::string(buf);
    }

private:
    std::chrono::high_resolution_clock::time_point start_;
};
