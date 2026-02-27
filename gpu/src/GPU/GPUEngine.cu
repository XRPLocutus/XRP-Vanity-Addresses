#include "GPUEngine.h"
#include "kernels/xrpl_kernel.cuh"
#include <cuda_runtime.h>
#include <cstdio>
#include <cstring>

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
    , compute_major_(0)
    , compute_minor_(0)
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
    cudaError_t err = cudaSetDevice(device_id_);
    if (err != cudaSuccess) {
        fprintf(stderr, "Failed to select GPU %d: %s\n",
                device_id_, cudaGetErrorString(err));
        return false;
    }

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device_id_));
    device_name_ = prop.name;
    sm_count_ = prop.multiProcessorCount;
    compute_major_ = prop.major;
    compute_minor_ = prop.minor;

    if (grid_blocks_ <= 0) {
        grid_blocks_ = sm_count_;
    }

    // Allocate device memory
    CUDA_CHECK(cudaMalloc(&d_seed_,           8 * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&d_params_,         sizeof(SearchParams)));
    CUDA_CHECK(cudaMalloc(&d_results_,        max_results_ * sizeof(GPUResult)));
    CUDA_CHECK(cudaMalloc(&d_found_count_,    sizeof(int)));
    CUDA_CHECK(cudaMalloc(&d_total_checked_,  sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_entropy_single_, 16));
    CUDA_CHECK(cudaMalloc(&d_result_single_,  sizeof(GPUResult)));

    // Initialize counters
    CUDA_CHECK(cudaMemset(d_found_count_,   0, sizeof(int)));
    CUDA_CHECK(cudaMemset(d_total_checked_, 0, sizeof(uint64_t)));

    return true;
}

// ─────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────

void GPUEngine::set_pattern(const std::string& pattern, int type, bool case_insensitive) {
    SearchParams h_params;
    memset(&h_params, 0, sizeof(h_params));
    int len = (int)pattern.size();
    if (len > 31) len = 31;
    memcpy(h_params.pattern, pattern.c_str(), len);
    h_params.pattern_len = len;
    h_params.pattern_type = type;
    h_params.case_insensitive = case_insensitive ? 1 : 0;

    CUDA_CHECK_VOID(cudaMemcpy(d_params_, &h_params, sizeof(SearchParams), cudaMemcpyHostToDevice));
}

void GPUEngine::set_seed(const uint32_t seed[8]) {
    CUDA_CHECK_VOID(cudaMemcpy(d_seed_, seed, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice));
}

// ─────────────────────────────────────────────────────────────
// Search
// ─────────────────────────────────────────────────────────────

int GPUEngine::search_batch(uint64_t start_iteration) {
    int prev_found = 0;
    CUDA_CHECK_VOID(cudaMemcpy(&prev_found, d_found_count_, sizeof(int), cudaMemcpyDeviceToHost));

    xrpl_vanity_kernel<<<grid_blocks_, block_threads_>>>(
        static_cast<uint32_t*>(d_seed_),
        static_cast<SearchParams*>(d_params_),
        start_iteration,
        static_cast<GPUResult*>(d_results_),
        static_cast<int*>(d_found_count_),
        max_results_,
        static_cast<uint64_t*>(d_total_checked_)
    );

    CUDA_CHECK_VOID(cudaDeviceSynchronize());

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
    CUDA_CHECK_VOID(cudaMemcpy(d_entropy_single_, entropy, 16, cudaMemcpyHostToDevice));

    xrpl_derive_single<<<1, 1>>>(
        static_cast<uint8_t*>(d_entropy_single_),
        static_cast<GPUResult*>(d_result_single_)
    );
    CUDA_CHECK_VOID(cudaDeviceSynchronize());

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
