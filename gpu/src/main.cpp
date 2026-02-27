#include "Vanity.h"
#include <cstdio>
#include <cstring>
#include <csignal>
#include <string>

// ─────────────────────────────────────────────────────────────
// Global Vanity pointer for signal handler
// ─────────────────────────────────────────────────────────────

static Vanity* g_vanity = nullptr;

static void signal_handler(int sig) {
    (void)sig;
    fprintf(stderr, "\n  Ctrl+C received — stopping search...\n");
    if (g_vanity) g_vanity->stop();
}

// ─────────────────────────────────────────────────────────────
// CLI argument parsing
// ─────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    printf("\n");
    printf("  XRPL Vanity Address Generator v3.0 (GPU-accelerated)\n");
    printf("  ────────────────────────────────────────────────────\n");
    printf("\n");
    printf("  Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("  Search Options:\n");
    printf("    -p, --prefix <PATTERN>     Desired prefix after 'r'\n");
    printf("    -s, --suffix <PATTERN>     Desired suffix\n");
    printf("    -c, --contains <PATTERN>   Substring anywhere in address\n");
    printf("    -n, --count <N>            Find N matches (default: 1)\n");
    printf("    -i, --case-insensitive     Case-insensitive matching\n");
    printf("\n");
    printf("  GPU Options:\n");
    printf("    --gpu-id <ID>              Use specific GPU (default: 0)\n");
    printf("    --gpu-grid <BLOCKS>        Grid blocks (default: auto = SM count)\n");
    printf("    --gpu-threads <THREADS>    Threads per block (default: 256)\n");
    printf("    --no-gpu                   CPU-only mode (use Rust v2.3 instead)\n");
    printf("\n");
    printf("  Other:\n");
    printf("    --clear                    Clear screen after showing results\n");
    printf("    -h, --help                 Show this help\n");
    printf("    -V, --version              Show version\n");
    printf("\n");
    printf("  Examples:\n");
    printf("    %s -p Bob              Find rBob...\n", prog);
    printf("    %s -p XRP -i           Find rXRP... (case-insensitive)\n", prog);
    printf("    %s -s XRP -n 5         Find 5 addresses ending in XRP\n", prog);
    printf("    %s -c Locutus          Find address containing Locutus\n", prog);
    printf("\n");
}

static bool match_arg(const char* arg, const char* short_name, const char* long_name) {
    if (short_name && strcmp(arg, short_name) == 0) return true;
    if (long_name && strcmp(arg, long_name) == 0) return true;
    return false;
}

int main(int argc, char* argv[]) {
    VanityConfig config;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];

        if (match_arg(arg, "-h", "--help")) {
            print_usage(argv[0]);
            return 0;
        }
        if (match_arg(arg, "-V", "--version")) {
            printf("xrpl-vanity-gpu 3.0.0\n");
            return 0;
        }
        if (match_arg(arg, "-p", "--prefix")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.prefix = argv[i];
        }
        else if (match_arg(arg, "-s", "--suffix")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.suffix = argv[i];
        }
        else if (match_arg(arg, "-c", "--contains")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.contains = argv[i];
        }
        else if (match_arg(arg, "-n", "--count")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.count = atoi(argv[i]);
            if (config.count < 1) config.count = 1;
        }
        else if (match_arg(arg, "-i", "--case-insensitive")) {
            config.case_insensitive = true;
        }
        else if (match_arg(arg, nullptr, "--gpu-id")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.gpu_id = atoi(argv[i]);
        }
        else if (match_arg(arg, nullptr, "--gpu-grid")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.grid_blocks = atoi(argv[i]);
        }
        else if (match_arg(arg, nullptr, "--gpu-threads")) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", arg); return 1; }
            config.block_threads = atoi(argv[i]);
        }
        else if (match_arg(arg, nullptr, "--no-gpu")) {
            config.no_gpu = true;
        }
        else if (match_arg(arg, nullptr, "--clear")) {
            config.clear_screen = true;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Require at least one pattern
    if (config.prefix.empty() && config.suffix.empty() && config.contains.empty()) {
        fprintf(stderr, "ERROR: Specify at least one of --prefix, --suffix, or --contains\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // Set up signal handler
    Vanity vanity(config);
    g_vanity = &vanity;
    signal(SIGINT, signal_handler);

    // Run the search
    auto results = vanity.run();

    g_vanity = nullptr;

    if (results.empty()) {
        fprintf(stderr, "\n  No matches found.\n\n");
        return 1;
    }

    return 0;
}
