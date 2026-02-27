#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Iterations per thread per kernel launch (must match xrpl_kernel.cuh)
#ifndef ITERATIONS_PER_THREAD
#define ITERATIONS_PER_THREAD 64
#endif

// Host-side result with all intermediate values
struct HostResult {
    uint8_t  entropy[16];
    uint8_t  private_key[32];
    uint8_t  public_key[32];
    uint8_t  account_id[20];
    char     address[36];
};

class GPUEngine {
public:
    GPUEngine(int device_id = 0, int grid_blocks = 0, int block_threads = 256);
    ~GPUEngine();

    // Initialize GPU: allocate device memory, upload basepoint table
    bool init();

    // Set search parameters
    void set_pattern(const std::string& pattern, int type, bool case_insensitive);

    // Upload CSPRNG seed (32 bytes = 8 x uint32_t)
    void set_seed(const uint32_t seed[8]);

    // Launch one batch of the search kernel
    // Returns number of new matches found
    int search_batch(uint64_t start_iteration);

    // Get results from last search_batch call
    std::vector<HostResult> get_results() const;

    // Get total addresses checked so far
    uint64_t get_total_checked() const;

    // Reset found counter for a new search
    void reset();

    // Derive a single address on GPU (for KAT validation)
    HostResult derive_single(const uint8_t entropy[16]);

    // GPU info
    std::string device_name() const { return device_name_; }
    int sm_count() const { return sm_count_; }
    int compute_major() const { return compute_major_; }
    int compute_minor() const { return compute_minor_; }
    int grid_blocks_count() const { return grid_blocks_; }
    int block_threads_count() const { return block_threads_; }

private:
    int device_id_;
    int grid_blocks_;
    int block_threads_;
    int max_results_;

    std::string device_name_;
    int sm_count_;
    int compute_major_;
    int compute_minor_;

    // Device memory pointers (opaque — only used in .cu file)
    void* d_seed_;
    void* d_params_;
    void* d_results_;
    void* d_found_count_;
    void* d_total_checked_;
    void* d_entropy_single_;
    void* d_result_single_;

    // Host-side state (plain structs, no CUDA types)
    uint64_t h_total_checked_;
    int      h_found_count_;
};
