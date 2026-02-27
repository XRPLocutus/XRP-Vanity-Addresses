#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include "GPU/GPUEngine.h"
#include "CPU/CPUVerify.h"

struct VanityConfig {
    std::string prefix;
    std::string suffix;
    std::string contains;
    int         count          = 1;
    bool        case_insensitive = false;
    int         gpu_id         = -1;    // -1 = auto (all GPUs)
    int         grid_blocks    = 0;     // 0 = auto
    int         block_threads  = 256;
    bool        no_gpu         = false;
    bool        clear_screen   = false;
};

struct VanityResult {
    std::string address;
    std::string seed;       // sEd... family seed
    std::string hex_secret; // hex-encoded private key
    double      elapsed_sec;
    uint64_t    attempts;
};

class Vanity {
public:
    Vanity(const VanityConfig& config);
    ~Vanity();

    // Run the search. Blocks until count matches found or interrupted.
    // Returns the results.
    std::vector<VanityResult> run();

    // Signal to stop (called from Ctrl+C handler)
    void stop();

private:
    VanityConfig config_;
    std::atomic<bool> should_stop_;
    std::vector<VanityResult> results_;

    // Determine pattern type and validate
    int get_pattern_type() const;
    std::string get_pattern_string() const;

    // Display progress
    void print_progress(uint64_t checked, double elapsed);

    // Display a found result
    void print_result(const VanityResult& result, int index);

    // Generate cryptographically secure seed
    void generate_seed(uint32_t seed[8]);
};
