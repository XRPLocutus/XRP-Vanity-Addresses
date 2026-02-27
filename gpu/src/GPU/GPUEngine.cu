#include "GPUEngine.h"
#include "kernels/xrpl_kernel.cuh"
#include "../CPU/Ed25519_ref10.h"
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

    printf("GPU %d: %s (%d SMs, CC %d.%d)\n",
           device_id_, prop.name, sm_count_, prop.major, prop.minor);

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

    // Initialize counters
    CUDA_CHECK(cudaMemset(d_found_count_,   0, sizeof(int)));
    CUDA_CHECK(cudaMemset(d_total_checked_, 0, sizeof(uint64_t)));

    if (!upload_basepoint_table()) {
        fprintf(stderr, "Failed to upload basepoint table\n");
        return false;
    }

    return true;
}

bool GPUEngine::upload_basepoint_table() {
    printf("Computing Ed25519 basepoint table on CPU...\n");

    // Compute on CPU
    cpu_ge25519_precomp cpu_table[32][8];
    cpu_ed25519_compute_basepoint_table(cpu_table);

    // The GPU ge25519_precomp has 3 fe25519 fields, each with 5 uint64_t limbs.
    // cpu_ge25519_precomp has identical layout (3 arrays of 5 uint64_t).
    // Upload directly via cudaMemcpyToSymbol.
    CUDA_CHECK(cudaMemcpyToSymbol(BASEPOINT_TABLE, cpu_table, sizeof(cpu_table)));

    printf("Basepoint table uploaded to GPU constant memory (%zu bytes)\n",
           sizeof(cpu_table));
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
// Field arithmetic test kernel
// ─────────────────────────────────────────────────────────────

__global__ void test_fe_kernel(uint64_t* output) {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;

    // Test 1: 5 * 7 = 35
    fe25519 a, b, c;
    fe25519_zero(&a); a.v[0] = 5;
    fe25519_zero(&b); b.v[0] = 7;
    fe25519_mul(&c, &a, &b);
    for (int i = 0; i < 5; i++) output[i] = c.v[i];  // expect {35,0,0,0,0}

    // Test 2: D * 1 = D (tests constant memory access)
    fe25519_one(&a);
    fe25519_mul(&c, &ED25519_D, &a);
    for (int i = 0; i < 5; i++) output[5+i] = c.v[i]; // expect D limbs

    // Test 3: D^2
    fe25519_sq(&c, &ED25519_D);
    for (int i = 0; i < 5; i++) output[10+i] = c.v[i];

    // Test 4: BX * BY (basepoint T coordinate)
    fe25519_mul(&c, &ED25519_BX, &ED25519_BY);
    for (int i = 0; i < 5; i++) output[15+i] = c.v[i];

    // Test 5: scalar*B for clamped all-zero scalar
    // Clamped all-zero: scalar[0]=0, scalar[31]=64 (bit 254 set)
    uint8_t scalar[32] = {};
    scalar[31] = 64;
    ge25519_p3 point;
    ed25519_scalarmult_base(&point, scalar);
    // Output the affine Y coordinate (pack would do inv + mul)
    for (int i = 0; i < 5; i++) output[20+i] = point.X.v[i];
    for (int i = 0; i < 5; i++) output[25+i] = point.Y.v[i];
    for (int i = 0; i < 5; i++) output[30+i] = point.Z.v[i];

    // Test 6: Pack the point to get compressed pubkey bytes
    uint8_t pubkey[32];
    ge25519_pack(pubkey, &point);
    // Store as uint64_t for easy transfer
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w |= (uint64_t)pubkey[i*8+j] << (j*8);
        output[35+i] = w;
    }
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

// ─────────────────────────────────────────────────────────────
// Field arithmetic test
// ─────────────────────────────────────────────────────────────

bool GPUEngine::test_field_arithmetic() {
    // Allocate device output (40 uint64_t values)
    uint64_t* d_output = nullptr;
    cudaError_t err = cudaMalloc(&d_output, 40 * sizeof(uint64_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "test_field_arithmetic: cudaMalloc failed\n");
        return false;
    }
    cudaMemset(d_output, 0, 40 * sizeof(uint64_t));

    test_fe_kernel<<<1, 1>>>(d_output);
    cudaDeviceSynchronize();

    uint64_t h_output[40];
    cudaMemcpy(h_output, d_output, 40 * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaFree(d_output);

    bool all_ok = true;

    // Test 1: 5 * 7 = 35
    printf("  FE Test 1 (5*7=35): ");
    if (h_output[0] == 35 && h_output[1] == 0 && h_output[2] == 0 && h_output[3] == 0 && h_output[4] == 0) {
        printf("OK\n");
    } else {
        printf("FAIL [%llu, %llu, %llu, %llu, %llu]\n",
               (unsigned long long)h_output[0], (unsigned long long)h_output[1],
               (unsigned long long)h_output[2], (unsigned long long)h_output[3],
               (unsigned long long)h_output[4]);
        all_ok = false;
    }

    // Test 2: D * 1 = D
    // CPU D limbs:
    static const uint64_t D_limbs[5] = {929955233495203ULL, 466365720129213ULL, 1662059464998953ULL, 2033849074728123ULL, 1442794654840575ULL};
    printf("  FE Test 2 (D*1=D): ");
    bool d_ok = true;
    for (int i = 0; i < 5; i++) {
        if (h_output[5+i] != D_limbs[i]) { d_ok = false; break; }
    }
    if (d_ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        printf("    GPU: [%llu, %llu, %llu, %llu, %llu]\n",
               (unsigned long long)h_output[5], (unsigned long long)h_output[6],
               (unsigned long long)h_output[7], (unsigned long long)h_output[8],
               (unsigned long long)h_output[9]);
        printf("    CPU: [%llu, %llu, %llu, %llu, %llu]\n",
               (unsigned long long)D_limbs[0], (unsigned long long)D_limbs[1],
               (unsigned long long)D_limbs[2], (unsigned long long)D_limbs[3],
               (unsigned long long)D_limbs[4]);
        all_ok = false;
    }

    // Test 3: D^2 - compute on CPU for comparison
    // Use the CPU fe_sq from Ed25519_ref10.cpp (not accessible directly, so just print GPU result)
    printf("  FE Test 3 (D^2): GPU=[%llu, %llu, %llu, %llu, %llu]\n",
           (unsigned long long)h_output[10], (unsigned long long)h_output[11],
           (unsigned long long)h_output[12], (unsigned long long)h_output[13],
           (unsigned long long)h_output[14]);

    // Test 4: BX * BY (T coordinate of basepoint)
    printf("  FE Test 4 (BX*BY): GPU=[%llu, %llu, %llu, %llu, %llu]\n",
           (unsigned long long)h_output[15], (unsigned long long)h_output[16],
           (unsigned long long)h_output[17], (unsigned long long)h_output[18],
           (unsigned long long)h_output[19]);

    // Test 5: scalar*B projective coords (scalar = clamped all-zeros: bit 254 set only)
    printf("  FE Test 5 (scalar*B): X[0]=%llu Y[0]=%llu Z[0]=%llu\n",
           (unsigned long long)h_output[20], (unsigned long long)h_output[25],
           (unsigned long long)h_output[30]);

    // Test 6: packed pubkey
    uint8_t gpu_pubkey[32];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            gpu_pubkey[i*8+j] = (uint8_t)(h_output[35+i] >> (j*8));
        }
    }
    printf("  FE Test 6 (packed pubkey): ");
    for (int i = 0; i < 32; i++) printf("%02x", gpu_pubkey[i]);
    printf("\n");

    return all_ok;
}
