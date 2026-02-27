#include "Vanity.h"
#include "utils/Timer.h"
#include "utils/Display.h"
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
    NTSTATUS status = BCryptGenRandom(
        NULL, (PUCHAR)seed, 32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        fprintf(stderr, "ERROR: BCryptGenRandom failed (status: 0x%lx)\n", status);
        exit(1);
    }
#else
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

void Vanity::print_progress(uint64_t checked, double elapsed, uint64_t avg_est) {
    double rate = (elapsed > 0) ? checked / elapsed : 0;

    std::string checked_str = Timer::format_count(checked);
    std::string rate_str = Timer::format_count((uint64_t)rate);

    std::string eta_str;
    if (rate > 0 && avg_est > 0) {
        double remaining = ((double)avg_est * config_.count - (double)checked) / rate;
        if (remaining > 0)
            eta_str = Timer::format_duration(remaining);
        else
            eta_str = "any moment";
    } else {
        eta_str = "calculating...";
    }

    fprintf(stderr, "\r  > %s attempts | %s/s | est. remaining: %s          ",
            checked_str.c_str(), rate_str.c_str(), eta_str.c_str());
    fflush(stderr);
}

// ─────────────────────────────────────────────────────────────
// Result display
// ─────────────────────────────────────────────────────────────

void Vanity::print_result(const VanityResult& result, int index) {
    // Clear progress line
    fprintf(stderr, "\r%*s\r", 90, "");

    printf("\n");
    Display::top();

    if (config_.count == 1) {
        Display::title("FOUND!");
    } else {
        char title_buf[64];
        snprintf(title_buf, sizeof(title_buf), "FOUND #%d", index + 1);
        Display::title(title_buf);
    }

    Display::rule();
    Display::empty();
    Display::line("Address:", result.address.c_str());
    Display::line("Seed:", result.seed.c_str());
    Display::line("Secret (hex):", result.hex_secret.c_str());
    Display::empty();
    Display::rule();

    Display::line("Attempts:", Timer::format_count(result.attempts).c_str());
    Display::line("Duration:", Timer::format_duration(result.elapsed_sec).c_str());

    double rate = (result.elapsed_sec > 0) ?
        result.attempts / result.elapsed_sec : 0;
    char speed[64];
    snprintf(speed, sizeof(speed), "%s/sec", Timer::format_count((uint64_t)rate).c_str());
    Display::line("Speed:", speed);

    Display::rule();
    Display::empty();
    Display::title("IMPORTANT: Save your seed/secret securely!");
    Display::title("Anyone with the seed controls the wallet.");
    Display::empty();
    Display::bottom();
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

    // CPU KAT — silent on success
    if (!CPUVerify::run_kat()) {
        fprintf(stderr, "ERROR: CPU self-tests failed. Aborting.\n");
        return {};
    }

    if (config_.no_gpu) {
        fprintf(stderr, "CPU-only mode not yet implemented in v3.0.\n");
        fprintf(stderr, "Use the Rust v2.3 binary for CPU-only search.\n");
        return {};
    }

    // Initialize GPU — silent
    int gpu_id = config_.gpu_id >= 0 ? config_.gpu_id : 0;
    GPUEngine gpu(gpu_id, config_.grid_blocks, config_.block_threads);

    if (!gpu.init()) {
        fprintf(stderr, "ERROR: GPU initialization failed.\n");
        return {};
    }

    // GPU KAT — silent on success
    {
        uint8_t kat_entropy[16] = {0};
        HostResult gpu_kat = gpu.derive_single(kat_entropy);
        CPUResult  cpu_kat = CPUVerify::derive(kat_entropy);

        if (strcmp(gpu_kat.address, cpu_kat.address) != 0) {
            fprintf(stderr, "FATAL: GPU/CPU self-test mismatch!\n");
            fprintf(stderr, "  GPU: %s\n  CPU: %s\n", gpu_kat.address, cpu_kat.address);
            return {};
        }
    }

    // Banner
    printf("\n");
    Display::top();
    Display::title("XRPL Vanity Address Generator v3.0 (GPU)");
    Display::rule();

    char pat_desc[128];
    snprintf(pat_desc, sizeof(pat_desc), "%s (%s%s)", pattern.c_str(),
        pattern_type == 0 ? "prefix" : pattern_type == 1 ? "suffix" : "contains",
        config_.case_insensitive ? ", case-insensitive" : "");
    Display::line("Pattern:", pat_desc);

    Display::line("Case-sensitive:", config_.case_insensitive ? "No" : "Yes");

    char target_desc[64];
    snprintf(target_desc, sizeof(target_desc), "%d address%s",
        config_.count, config_.count > 1 ? "es" : "");
    Display::line("Target:", target_desc);

    uint64_t avg_est = Display::estimate_attempts((int)pattern.size());
    char est_desc[64];
    snprintf(est_desc, sizeof(est_desc), "~%s per match",
        Timer::format_count(avg_est).c_str());
    Display::line("Avg. attempts:", est_desc);

    Display::rule();

    char gpu_desc[128];
    snprintf(gpu_desc, sizeof(gpu_desc), "%s (%d SMs, CC %d.%d)",
        gpu.device_name().c_str(), gpu.sm_count(),
        gpu.compute_major(), gpu.compute_minor());
    Display::line("GPU:", gpu_desc);

    int concurrent = gpu.grid_blocks_count() * gpu.block_threads_count();
    char grid_desc[128];
    snprintf(grid_desc, sizeof(grid_desc), "%d blocks x %d threads (%s concurrent)",
        gpu.grid_blocks_count(), gpu.block_threads_count(),
        Timer::format_count(concurrent).c_str());
    Display::line("Grid:", grid_desc);

    Display::line("Self-test:", "OK");
    Display::bottom();
    printf("\n");

    // Set search parameters
    gpu.set_pattern(pattern, pattern_type, config_.case_insensitive);

    // Generate and upload CSPRNG seed
    uint32_t seed[8];
    generate_seed(seed);
    gpu.set_seed(seed);

    // Search loop
    Timer timer;
    uint64_t batch_num = 0;
    uint64_t grid_size = uint64_t(gpu.grid_blocks_count()) * gpu.block_threads_count();
    int gpu_results_processed = 0;

    while (!should_stop_.load(std::memory_order_relaxed)) {
        uint64_t start_iter = batch_num * grid_size * ITERATIONS_PER_THREAD;
        int new_found = gpu.search_batch(start_iter);

        uint64_t total = gpu.get_total_checked();
        double elapsed = timer.elapsed_sec();

        if (batch_num % 10 == 0) {
            print_progress(total, elapsed, avg_est);
        }

        if (new_found > 0) {
            auto gpu_results = gpu.get_results();
            for (int ri = gpu_results_processed; ri < (int)gpu_results.size(); ri++) {
                const auto& gr = gpu_results[ri];
                gpu_results_processed = ri + 1;

                if ((int)results_.size() >= config_.count) break;

                bool verified = CPUVerify::verify(gr.entropy, gr.address);
                if (!verified) {
                    fprintf(stderr, "\n  WARNING: GPU/CPU mismatch (skipping)\n");
                    continue;
                }

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

        if ((int)results_.size() >= config_.count) break;
    }

    // Clear progress line
    fprintf(stderr, "\r%*s\r", 90, "");

    // Clear screen if requested
    if (config_.clear_screen && !results_.empty()) {
        printf("\nPress Enter to clear screen and scrollback...");
        fflush(stdout);
        getchar();
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
