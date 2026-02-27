#include "Vanity.h"
#include "utils/Timer.h"
#include <cstdio>
#include <cstring>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// ─────────────────────────────────────────────────────────────
// XRPL Base58 alphabet for validation
// ─────────────────────────────────────────────────────────────

static const char* XRPL_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

static bool is_valid_xrpl_char(char c) {
    return strchr(XRPL_ALPHABET, c) != nullptr;
}

static bool is_valid_xrpl_char_ci(char c) {
    // Case-insensitive: check both cases
    for (const char* p = XRPL_ALPHABET; *p; p++) {
        if (tolower(*p) == tolower(c)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────
// Constructor / Destructor
// ─────────────────────────────────────────────────────────────

Vanity::Vanity(const VanityConfig& config)
    : config_(config)
    , should_stop_(false)
{
}

Vanity::~Vanity() = default;

// ─────────────────────────────────────────────────────────────
// Pattern helpers
// ─────────────────────────────────────────────────────────────

int Vanity::get_pattern_type() const {
    if (!config_.prefix.empty()) return 0;
    if (!config_.suffix.empty()) return 1;
    if (!config_.contains.empty()) return 2;
    return 0;
}

std::string Vanity::get_pattern_string() const {
    if (!config_.prefix.empty()) return config_.prefix;
    if (!config_.suffix.empty()) return config_.suffix;
    if (!config_.contains.empty()) return config_.contains;
    return "";
}

// ─────────────────────────────────────────────────────────────
// Secure RNG seed generation
// ─────────────────────────────────────────────────────────────

void Vanity::generate_seed(uint32_t seed[8]) {
#ifdef _WIN32
    // Use Windows BCryptGenRandom (CSPRNG)
    NTSTATUS status = BCryptGenRandom(
        NULL, (PUCHAR)seed, 32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        fprintf(stderr, "ERROR: BCryptGenRandom failed (status: 0x%lx)\n", status);
        exit(1);
    }
#else
    // Use /dev/urandom on Linux/macOS
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
        exit(1);
    }
    ssize_t n = read(fd, seed, 32);
    close(fd);
    if (n != 32) {
        fprintf(stderr, "ERROR: Short read from /dev/urandom\n");
        exit(1);
    }
#endif

    // Sanity check: seed must not be all zeros
    bool all_zero = true;
    for (int i = 0; i < 8; i++) {
        if (seed[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        fprintf(stderr, "ERROR: OS CSPRNG returned all zeros!\n");
        exit(1);
    }
}

// ─────────────────────────────────────────────────────────────
// Progress display
// ─────────────────────────────────────────────────────────────

void Vanity::print_progress(uint64_t checked, double elapsed) {
    double rate = (elapsed > 0) ? checked / elapsed : 0;

    std::string checked_str = Timer::format_count(checked);
    std::string rate_str = Timer::format_count((uint64_t)rate);
    std::string time_str = Timer::format_duration(elapsed);

    fprintf(stderr, "\r  Searched %s addresses (%s/sec) in %s",
            checked_str.c_str(), rate_str.c_str(), time_str.c_str());
    fflush(stderr);
}

// ─────────────────────────────────────────────────────────────
// Result display
// ─────────────────────────────────────────────────────────────

void Vanity::print_result(const VanityResult& result, int index) {
    printf("\n");
    printf("  ╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("  ║  XRPL Vanity Address Found (#%d)                                              ║\n", index + 1);
    printf("  ╠════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("  ║  Address:  %-67s ║\n", result.address.c_str());
    printf("  ║  Seed:     %-67s ║\n", result.seed.c_str());
    printf("  ║  Secret:   %-67s ║\n", result.hex_secret.c_str());
    printf("  ╠════════════════════════════════════════════════════════════════════════════════╣\n");

    std::string stats = "Found in " + Timer::format_count(result.attempts) +
                        " attempts (" + Timer::format_duration(result.elapsed_sec) + ")";
    printf("  ║  %-76s ║\n", stats.c_str());
    printf("  ╠════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("  ║  WARNING: Save your seed/secret securely. It will NOT be shown again.        ║\n");
    printf("  ╚════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// ─────────────────────────────────────────────────────────────
// Main search loop
// ─────────────────────────────────────────────────────────────

std::vector<VanityResult> Vanity::run() {
    // Validate pattern
    std::string pattern = get_pattern_string();
    if (pattern.empty()) {
        fprintf(stderr, "ERROR: No search pattern specified.\n");
        return {};
    }

    // Validate characters
    for (char c : pattern) {
        if (config_.case_insensitive) {
            if (!is_valid_xrpl_char_ci(c)) {
                fprintf(stderr, "ERROR: '%c' is not a valid XRPL Base58 character.\n", c);
                return {};
            }
        } else {
            if (!is_valid_xrpl_char(c)) {
                fprintf(stderr, "ERROR: '%c' is not a valid XRPL Base58 character.\n", c);
                return {};
            }
        }
    }

    int pattern_type = get_pattern_type();

    printf("\n");
    printf("  XRPL Vanity Address Generator v3.0 (GPU)\n");
    printf("  ─────────────────────────────────────────\n");
    printf("  Pattern:   %s (%s%s)\n", pattern.c_str(),
           pattern_type == 0 ? "prefix" : pattern_type == 1 ? "suffix" : "contains",
           config_.case_insensitive ? ", case-insensitive" : "");
    printf("  Target:    %d address%s\n", config_.count, config_.count > 1 ? "es" : "");
    printf("\n");

    // Run CPU self-tests
    if (!CPUVerify::run_kat()) {
        fprintf(stderr, "ERROR: CPU self-tests failed. Aborting.\n");
        return {};
    }

    if (config_.no_gpu) {
        fprintf(stderr, "CPU-only mode not yet implemented in v3.0.\n");
        fprintf(stderr, "Use the Rust v2.3 binary for CPU-only search.\n");
        return {};
    }

    // Initialize GPU
    int gpu_id = config_.gpu_id >= 0 ? config_.gpu_id : 0;
    GPUEngine gpu(gpu_id, config_.grid_blocks, config_.block_threads);

    if (!gpu.init()) {
        fprintf(stderr, "ERROR: GPU initialization failed.\n");
        return {};
    }

    // GPU KAT: derive a known entropy on GPU and verify against CPU
    {
        uint8_t kat_entropy[16] = {0}; // all-zeros = KAT vector 0
        HostResult gpu_kat = gpu.derive_single(kat_entropy);
        CPUResult  cpu_kat = CPUVerify::derive(kat_entropy);

        if (strcmp(gpu_kat.address, cpu_kat.address) != 0) {
            fprintf(stderr, "\n  GPU KAT FAILED:\n");
            fprintf(stderr, "    GPU address: %s\n", gpu_kat.address);
            fprintf(stderr, "    CPU address: %s\n", cpu_kat.address);
            fprintf(stderr, "  GPU and CPU produce different addresses. Aborting.\n");
            return {};
        }
        printf("  GPU KAT: OK (%s)\n", gpu_kat.address);
    }

    // Set search parameters
    gpu.set_pattern(pattern, pattern_type, config_.case_insensitive);

    // Generate and upload CSPRNG seed
    uint32_t seed[8];
    generate_seed(seed);
    gpu.set_seed(seed);

    printf("  Searching on %s (%d SMs)...\n\n", gpu.device_name().c_str(), gpu.sm_count());

    // Search loop
    Timer timer;
    uint64_t batch_num = 0;
    uint64_t grid_size = uint64_t(gpu.grid_blocks_count()) * gpu.block_threads_count();
    int gpu_results_processed = 0;  // Track how many GPU results we've already seen

    while (!should_stop_.load(std::memory_order_relaxed)) {
        uint64_t start_iter = batch_num * grid_size * ITERATIONS_PER_THREAD;
        int new_found = gpu.search_batch(start_iter);

        // Update progress
        uint64_t total = gpu.get_total_checked();
        double elapsed = timer.elapsed_sec();

        if (batch_num % 10 == 0) {
            print_progress(total, elapsed);
        }

        // Process any new results
        if (new_found > 0) {
            auto gpu_results = gpu.get_results();
            for (int ri = gpu_results_processed; ri < (int)gpu_results.size(); ri++) {
                const auto& gr = gpu_results[ri];
                gpu_results_processed = ri + 1;

                if ((int)results_.size() >= config_.count) break;

                // CPU-side verification
                bool verified = CPUVerify::verify(gr.entropy, gr.address);
                if (!verified) {
                    fprintf(stderr, "\n  WARNING: GPU/CPU mismatch (skipping)\n");
                    continue;
                }

                // Verified! Build final result
                VanityResult vr;
                vr.address = gr.address;
                vr.seed = CPUVerify::entropy_to_seed(gr.entropy);
                vr.hex_secret = CPUVerify::hex_encode(gr.private_key, 32);
                vr.elapsed_sec = elapsed;
                vr.attempts = total;

                results_.push_back(vr);
                print_result(vr, (int)results_.size() - 1);

                if ((int)results_.size() >= config_.count) {
                    should_stop_.store(true);
                    break;
                }
            }
        }

        batch_num++;

        // Check if we've found enough
        if ((int)results_.size() >= config_.count) break;
    }

    // Final progress
    uint64_t total = gpu.get_total_checked();
    double elapsed = timer.elapsed_sec();
    fprintf(stderr, "\r  Total: %s addresses checked in %s\n",
            Timer::format_count(total).c_str(),
            Timer::format_duration(elapsed).c_str());

    // Clear screen if requested
    if (config_.clear_screen && !results_.empty()) {
        printf("\nPress Enter to clear screen and scrollback...");
        fflush(stdout);
        getchar();
        // ANSI: clear screen + clear scrollback + move cursor home
        printf("\033[2J\033[3J\033[H");
        fflush(stdout);
    }

    // Zero out the seed from memory
    memset(seed, 0, sizeof(seed));

    return results_;
}

void Vanity::stop() {
    should_stop_.store(true, std::memory_order_relaxed);
}
