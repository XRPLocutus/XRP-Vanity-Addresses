#include "GPUEngine.h"
#include "kernels/xrpl_kernel.cuh"
#include <cuda_runtime.h>
#include <cstdio>
#include <cstring>

// ─────────────────────────────────────────────────────────────
// Ed25519 basepoint table generation (CPU-side)
// ─────────────────────────────────────────────────────────────

// The Ed25519 basepoint B (compressed form)
static const uint8_t ED25519_BASEPOINT_BYTES[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

// Basepoint in extended coordinates (Y=4/5 mod p, X chosen for positive)
// These are the standard Ed25519 base point coordinates:
// x = 15112221349535807912866137220509078750507884956996801397370759635002884272941
// y = 46316835694926478169428394003475163141307993866256225615783033890098355573289

// For the precomputed table, we compute: table[i][j] = (j+1) * 16^i * B
// where i = 0..31, j = 0..7
// This allows 4-bit windowed scalar multiplication

// Helper macro for CUDA error checking
#define CUDA_CHECK(call) do { \
    cudaError_t err = (call); \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", \
                __FILE__, __LINE__, cudaGetErrorString(err)); \
        return false; \
    } \
} while(0)

#define CUDA_CHECK_VOID(call) do { \
    cudaError_t err = (call); \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", \
                __FILE__, __LINE__, cudaGetErrorString(err)); \
    } \
} while(0)

// ─────────────────────────────────────────────────────────────
// Constructor / Destructor
// ─────────────────────────────────────────────────────────────

GPUEngine::GPUEngine(int device_id, int grid_blocks, int block_threads)
    : device_id_(device_id)
    , grid_blocks_(grid_blocks)
    , block_threads_(block_threads)
    , max_results_(256)
    , sm_count_(0)
    , d_seed_(nullptr)
    , d_params_(nullptr)
    , d_results_(nullptr)
    , d_found_count_(nullptr)
    , d_total_checked_(nullptr)
    , d_entropy_single_(nullptr)
    , d_result_single_(nullptr)
    , h_total_checked_(0)
    , h_found_count_(0)
{
    memset(&h_params_, 0, sizeof(h_params_));
}

GPUEngine::~GPUEngine() {
    if (d_seed_)            cudaFree(d_seed_);
    if (d_params_)          cudaFree(d_params_);
    if (d_results_)         cudaFree(d_results_);
    if (d_found_count_)     cudaFree(d_found_count_);
    if (d_total_checked_)   cudaFree(d_total_checked_);
    if (d_entropy_single_)  cudaFree(d_entropy_single_);
    if (d_result_single_)   cudaFree(d_result_single_);
}

// ─────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────

bool GPUEngine::init() {
    // Select device
    cudaError_t err = cudaSetDevice(device_id_);
    if (err != cudaSuccess) {
        fprintf(stderr, "Failed to select GPU %d: %s\n",
                device_id_, cudaGetErrorString(err));
        return false;
    }

    // Query device properties
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device_id_));
    device_name_ = prop.name;
    sm_count_ = prop.multiProcessorCount;

    printf("GPU %d: %s (%d SMs, CC %d.%d)\n",
           device_id_, prop.name, sm_count_, prop.major, prop.minor);

    // Auto-detect grid size if not specified
    if (grid_blocks_ <= 0) {
        grid_blocks_ = sm_count_;
    }

    printf("Grid: %d blocks x %d threads = %d concurrent threads\n",
           grid_blocks_, block_threads_, grid_blocks_ * block_threads_);

    // Allocate device memory
    CUDA_CHECK(cudaMalloc(&d_seed_,           8 * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&d_params_,         sizeof(SearchParams)));
    CUDA_CHECK(cudaMalloc(&d_results_,        max_results_ * sizeof(GPUResult)));
    CUDA_CHECK(cudaMalloc(&d_found_count_,    sizeof(int)));
    CUDA_CHECK(cudaMalloc(&d_total_checked_,  sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_entropy_single_, 16));
    CUDA_CHECK(cudaMalloc(&d_result_single_,  sizeof(GPUResult)));

    // Initialize counters to zero
    CUDA_CHECK(cudaMemset(d_found_count_,   0, sizeof(int)));
    CUDA_CHECK(cudaMemset(d_total_checked_, 0, sizeof(uint64_t)));

    // Upload basepoint table
    if (!upload_basepoint_table()) {
        fprintf(stderr, "Failed to upload basepoint table\n");
        return false;
    }

    return true;
}

bool GPUEngine::upload_basepoint_table() {
    // TODO: Compute the full precomputed basepoint table on CPU
    // and upload to __constant__ BASEPOINT_TABLE on GPU.
    //
    // For now, we'll compute it at startup:
    // table[i][j] = (j+1) * 16^i * B for i=0..31, j=0..7
    //
    // This requires CPU-side Ed25519 point arithmetic, which is
    // implemented in CPUVerify. For the initial version, we'll
    // defer this to the integration phase and use a placeholder.

    printf("Basepoint table: will be computed at startup (Phase 3)\n");
    return true;
}

// ─────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────

void GPUEngine::set_pattern(const std::string& pattern, int type, bool case_insensitive) {
    memset(&h_params_, 0, sizeof(h_params_));
    int len = (int)pattern.size();
    if (len > 31) len = 31;
    memcpy(h_params_.pattern, pattern.c_str(), len);
    h_params_.pattern_len = len;
    h_params_.pattern_type = type;
    h_params_.case_insensitive = case_insensitive ? 1 : 0;

    CUDA_CHECK_VOID(cudaMemcpy(d_params_, &h_params_, sizeof(SearchParams), cudaMemcpyHostToDevice));
}

void GPUEngine::set_seed(const uint32_t seed[8]) {
    CUDA_CHECK_VOID(cudaMemcpy(d_seed_, seed, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice));
}

// ─────────────────────────────────────────────────────────────
// Search
// ─────────────────────────────────────────────────────────────

int GPUEngine::search_batch(uint64_t start_iteration) {
    // Read current found count before launch
    int prev_found = 0;
    CUDA_CHECK_VOID(cudaMemcpy(&prev_found, d_found_count_, sizeof(int), cudaMemcpyDeviceToHost));

    // Launch kernel
    xrpl_vanity_kernel<<<grid_blocks_, block_threads_>>>(
        d_seed_,
        d_params_,
        start_iteration,
        d_results_,
        d_found_count_,
        max_results_,
        d_total_checked_
    );

    // Wait for completion
    CUDA_CHECK_VOID(cudaDeviceSynchronize());

    // Read updated counters
    CUDA_CHECK_VOID(cudaMemcpy(&h_found_count_, d_found_count_, sizeof(int), cudaMemcpyDeviceToHost));
    CUDA_CHECK_VOID(cudaMemcpy(&h_total_checked_, d_total_checked_, sizeof(uint64_t), cudaMemcpyDeviceToHost));

    return h_found_count_ - prev_found;
}

std::vector<HostResult> GPUEngine::get_results() const {
    int count = h_found_count_;
    if (count > max_results_) count = max_results_;

    std::vector<GPUResult> gpu_results(count);
    if (count > 0) {
        cudaMemcpy(gpu_results.data(), d_results_, count * sizeof(GPUResult), cudaMemcpyDeviceToHost);
    }

    // Convert to HostResult
    std::vector<HostResult> results(count);
    for (int i = 0; i < count; i++) {
        memcpy(results[i].entropy,     gpu_results[i].entropy,     16);
        memcpy(results[i].private_key, gpu_results[i].private_key, 32);
        memcpy(results[i].public_key,  gpu_results[i].public_key,  32);
        memcpy(results[i].account_id,  gpu_results[i].account_id,  20);
        memcpy(results[i].address,     gpu_results[i].address,     36);
    }

    return results;
}

uint64_t GPUEngine::get_total_checked() const {
    return h_total_checked_;
}

void GPUEngine::reset() {
    h_found_count_ = 0;
    h_total_checked_ = 0;
    CUDA_CHECK_VOID(cudaMemset(d_found_count_,   0, sizeof(int)));
    CUDA_CHECK_VOID(cudaMemset(d_total_checked_, 0, sizeof(uint64_t)));
}

// ─────────────────────────────────────────────────────────────
// Single derivation (KAT validation)
// ─────────────────────────────────────────────────────────────

HostResult GPUEngine::derive_single(const uint8_t entropy[16]) {
    // Upload entropy
    CUDA_CHECK_VOID(cudaMemcpy(d_entropy_single_, entropy, 16, cudaMemcpyHostToDevice));

    // Launch single-thread kernel
    xrpl_derive_single<<<1, 1>>>(d_entropy_single_, d_result_single_);
    CUDA_CHECK_VOID(cudaDeviceSynchronize());

    // Download result
    GPUResult gpu_result;
    CUDA_CHECK_VOID(cudaMemcpy(&gpu_result, d_result_single_, sizeof(GPUResult), cudaMemcpyDeviceToHost));

    HostResult result;
    memcpy(result.entropy,     gpu_result.entropy,     16);
    memcpy(result.private_key, gpu_result.private_key, 32);
    memcpy(result.public_key,  gpu_result.public_key,  32);
    memcpy(result.account_id,  gpu_result.account_id,  20);
    memcpy(result.address,     gpu_result.address,     36);

    return result;
}
