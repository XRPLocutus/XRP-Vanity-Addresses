# XRPL Vanity Generator v3.0 — GPU Architecture Plan

## Executive Summary

Version 3.0 adds CUDA GPU acceleration to the XRPL vanity address generator. The target platform is an NVIDIA RTX 5090 (Blackwell, 21,760 CUDA cores, 170 SMs, Compute Capability 10.x). The goal is a **50–100x speedup** over the CPU-only v2.3.0, enabling 7–8 character vanity patterns in hours instead of days.

**Estimated performance targets:**

| Platform | Speed | 6-char pattern | 7-char pattern |
|----------|-------|----------------|----------------|
| CPU v2.3 (16-core) | ~2–3M addr/s | ~3.5 hrs | ~8.5 days |
| GPU v3.0 (RTX 5090) | ~150–300M addr/s | ~2 min | ~2 hrs |

---

## 1. Why GPU Is Hard for XRPL Ed25519

The hot loop in v2.3 consists of:

| Operation | CPU Time Share | GPU Difficulty |
|-----------|---------------|----------------|
| Ed25519 Scalar Multiply | ~70% | ⚠️ Very hard — 256-bit field arithmetic |
| SHA-512 (key derivation) | ~10% | ✅ Straightforward |
| SHA-256 (3x, address hash) | ~15% | ✅ Straightforward |
| RIPEMD-160 | ~3% | ✅ Moderate |
| Base58Check + Pattern Match | ~2% | ✅ Trivial |

The bottleneck is **Ed25519 scalar multiplication** on the Curve25519 twisted Edwards curve. This requires ~255 iterations of point-double + conditional point-add, each involving multiple 256-bit modular multiplications in GF(2²⁵⁵ - 19). GPUs are 32-bit integer machines — each 256-bit multiply decomposes into ~64 `IMAD` (integer multiply-add) instructions with carry propagation.

**Key insight:** This is fundamentally different from secp256k1 (Bitcoin), where VanitySearch achieves 1+ GKey/s on GPUs. Secp256k1 uses a 256-bit prime with special structure (p = 2²⁵⁶ - 2³² - 977) that enables efficient reduction. Curve25519's prime (2²⁵⁵ - 19) is also special-form but uses a different limb representation (5×51-bit or 10×26-bit) that maps differently to GPU registers.

---

## 2. Architecture Options

### Option A: Full Custom CUDA Kernel (Recommended)

Write a complete CUDA kernel that performs the entire pipeline on-GPU:

```
Entropy Generation (GPU-side PRNG)
  → SHA-512-Half (key derivation)
    → Ed25519 Fixed-Base Scalar Multiply
      → Prefix with 0xED
        → SHA-256 → RIPEMD-160 (Account ID)
          → Base58Check partial encode
            → Pattern match
              → If match: write result to global memory
```

**Pros:** Maximum throughput, no CPU-GPU data transfer in the hot loop.
**Cons:** 2–4 weeks development, complex 256-bit arithmetic in CUDA.

### Option B: Fork VanitySearch (Best ROI)

VanitySearch by JeanLucPons is a proven, high-performance GPU vanity address generator for Bitcoin (secp256k1). It achieves >1 GKey/s on high-end GPUs. The approach:

1. **Replace secp256k1 with Curve25519/Ed25519** in the CUDA kernel
2. **Replace Bitcoin address derivation with XRPL** (0xED prefix, RIPEMD-160, XRPL Base58)
3. **Keep the proven GPU infrastructure** (grid sizing, batch management, multi-GPU support)

**Pros:** Battle-tested GPU framework, multi-GPU support, proven performance patterns.
**Cons:** VanitySearch is C++ (not Rust), secp256k1→Ed25519 replacement is non-trivial.

### Option C: Hybrid CPU+GPU

GPU only handles hashing (SHA-512, SHA-256, RIPEMD-160), CPU does Ed25519. Batches of pubkeys are transferred to GPU for address derivation.

**Pros:** Simple, uses existing Rust code.
**Cons:** Only ~2–3x speedup (Ed25519 stays on CPU), CPU-GPU transfer overhead dominates.

### Recommendation

**Option B (VanitySearch fork)** offers the best effort-to-result ratio. The GPU elliptic curve infrastructure is the hardest part, and VanitySearch has solved it for secp256k1. Adapting to Ed25519/Curve25519 is a well-defined task.

If Option B proves too complex (secp256k1 and Ed25519 have very different internal representations), fall back to **Option A** using research papers on Curve25519 CUDA implementations as a guide.

---

## 3. Detailed Architecture (Option B: VanitySearch Fork)

### 3.1 Project Structure

```
xrpl-vanity-gpu/
├── src/
│   ├── main.cpp              # CLI, configuration, result display
│   ├── Vanity.cpp            # Search coordinator (CPU-side)
│   ├── Vanity.h
│   ├── GPU/
│   │   ├── GPUEngine.cu      # CUDA kernel launcher
│   │   ├── GPUEngine.h
│   │   ├── GPUCompute.h      # Kernel dispatch interface
│   │   ├── Ed25519.cuh       # Ed25519 scalar multiply (DEVICE CODE)
│   │   ├── Curve25519.cuh    # Curve25519 field arithmetic (DEVICE CODE)
│   │   ├── SHA512.cuh        # SHA-512 for key derivation
│   │   ├── SHA256.cuh        # SHA-256 for address hashing
│   │   ├── RIPEMD160.cuh     # RIPEMD-160 for Account ID
│   │   ├── Base58.cuh        # Partial Base58 encode + pattern match
│   │   └── XRPL.cuh          # Full XRPL address derivation pipeline
│   ├── CPU/
│   │   ├── CPUEngine.cpp     # CPU fallback (existing v2.3 logic)
│   │   └── CPUEngine.h
│   ├── crypto/
│   │   ├── ed25519.cpp       # CPU-side Ed25519 (for result verification)
│   │   ├── sha512.cpp
│   │   ├── sha256.cpp
│   │   ├── ripemd160.cpp
│   │   └── base58.cpp
│   └── utils/
│       ├── Timer.cpp
│       └── Random.cpp
├── Makefile
├── CMakeLists.txt
├── xrpl-vanity-gpu.vcxproj   # Visual Studio project
└── README.md
```

### 3.2 CUDA Kernel Design

#### Thread Model

Each CUDA thread independently:
1. Generates its own entropy from a thread-specific seed
2. Derives the full XRPL address
3. Checks for pattern match
4. Writes match to global memory (if found)

```
Grid:    170 blocks (= SM count of RTX 5090)
Block:   256 threads
Total:   43,520 concurrent threads
Rekey:   Every thread processes N iterations before getting new entropy
```

#### Entropy Generation on GPU

Using a counter-based PRNG seeded from host-side CSPRNG:

```cuda
// Each thread gets a unique counter derived from:
//   host_seed (32 bytes, from OS CSPRNG) +
//   block_id +
//   thread_id +
//   iteration_counter
//
// Counter-based: Philox-4x32 or ChaCha20 quarter-round
__device__ void generate_entropy(
    const uint32_t* host_seed,
    uint32_t block_id,
    uint32_t thread_id,
    uint64_t iteration,
    uint8_t entropy[16]
) {
    // Philox-4x32-10 rounds (proven CSPRNG, GPU-friendly)
    uint32_t ctr[4] = {
        thread_id,
        block_id,
        (uint32_t)(iteration),
        (uint32_t)(iteration >> 32)
    };
    uint32_t key[2] = { host_seed[0], host_seed[1] };
    philox4x32_10(ctr, key);
    memcpy(entropy, ctr, 16);
}
```

#### Curve25519 Field Arithmetic

The performance-critical component. Two main representation options:

**Option 1: 5×51-bit limbs (ref10 style)**
- Each field element = 5 × uint64_t
- Fits in 5 GPU registers (good register pressure)
- Requires 64-bit multiply (`mul.hi.u64` + `mul.lo.u64`)
- RTX 5090 has native 64-bit integer support

**Option 2: 10×26-bit limbs (donna style)**
- Each field element = 10 × uint32_t
- Uses only 32-bit multiplies (native on all GPUs)
- More registers but simpler carry propagation
- Better for older GPUs, competitive on modern ones

**Recommendation: 5×51-bit** for RTX 5090 (Blackwell has good 64-bit int throughput).

```cuda
// Field element in GF(2^255 - 19)
typedef struct {
    uint64_t v[5];  // 5 × 51-bit limbs
} fe25519;

__device__ void fe25519_mul(fe25519* r, const fe25519* a, const fe25519* b) {
    // 25 partial products (5×5) with reduction mod 2^255-19
    // Each partial product: mul.lo.u64 + mul.hi.u64
    // Reduction: multiply overflow by 19 (since 2^255 ≡ 19 mod p)
    uint128_t t[5]; // Using PTX for 128-bit intermediates
    // ... ~50 IMAD instructions total
}

__device__ void fe25519_sq(fe25519* r, const fe25519* a) {
    // Optimized squaring: only 15 unique products (with doubling)
    // ~30 IMAD instructions
}
```

#### Ed25519 Scalar Multiplication

Fixed-base scalar multiplication (base point B is constant):

```cuda
// Pre-computed lookup table in constant memory
// 8 tables × 32 entries × 4 coordinates = 1024 points
// Fits in 48KB constant memory (RTX 5090: 64KB per SM)
__constant__ ge25519_precomp BASEPOINT_TABLE[8][32];

__device__ void ed25519_scalarmult_base(
    ge25519_p3* result,
    const uint8_t scalar[32]
) {
    // Windowed scalar multiplication with pre-computed table
    // Window size: 4 bits → 64 point additions
    // Each addition: 8 field multiplies + 7 field adds
    
    ge25519_p3 Q;
    ge25519_set_neutral(&Q);
    
    for (int i = 63; i >= 0; i--) {
        ge25519_double(&Q, &Q);  // Always double
        int window = get_4bit_window(scalar, i);
        if (window != 0) {
            ge25519_add_precomp(&Q, &BASEPOINT_TABLE[...][window]);
        }
    }
    *result = Q;
}
```

#### Full Pipeline Kernel

```cuda
__global__ void xrpl_vanity_kernel(
    const uint32_t* __restrict__ host_seed,
    const uint8_t* __restrict__ prefix_pattern,
    int prefix_len,
    int case_insensitive,
    uint64_t start_iteration,
    // Output
    uint8_t* __restrict__ found_entropy,    // 16 bytes
    uint8_t* __restrict__ found_address,    // 35 bytes max
    int* __restrict__ found_flag,
    uint64_t* __restrict__ total_checked
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t iter = start_iteration + tid;
    
    // Early exit if another thread already found a match
    if (*found_flag) return;
    
    for (int batch = 0; batch < ITERATIONS_PER_THREAD; batch++) {
        // 1. Generate 16-byte entropy
        uint8_t entropy[16];
        generate_entropy(host_seed, blockIdx.x, threadIdx.x, iter, entropy);
        
        // 2. SHA-512-Half → 32-byte private key
        uint8_t private_key[32];
        sha512_half(entropy, 16, private_key);
        
        // 3. Ed25519 scalar mult → public key
        ge25519_p3 pubpoint;
        ed25519_scalarmult_base(&pubpoint, private_key);
        uint8_t pubkey[32];
        ge25519_pack(pubkey, &pubpoint);
        
        // 4. [0xED] + pubkey → SHA-256 → RIPEMD-160
        uint8_t prefixed[33];
        prefixed[0] = 0xED;
        memcpy(prefixed + 1, pubkey, 32);
        
        uint8_t sha_out[32];
        sha256(prefixed, 33, sha_out);
        
        uint8_t account_id[20];
        ripemd160(sha_out, 32, account_id);
        
        // 5. Base58Check (partial — only encode prefix_len + 1 chars)
        uint8_t payload[25];
        payload[0] = 0x00;
        memcpy(payload + 1, account_id, 20);
        // Double SHA-256 checksum
        sha256(payload, 21, sha_out);
        uint8_t sha_out2[32];
        sha256(sha_out, 32, sha_out2);
        memcpy(payload + 21, sha_out2, 4);
        
        // 6. Partial Base58 encode + pattern match
        //    Key optimization: only encode enough characters to check the pattern
        //    Full 25-byte payload → ~33 Base58 chars, but we only need first N
        if (check_prefix_match(payload, prefix_pattern, prefix_len, case_insensitive)) {
            // Full match! Write result atomically
            if (atomicCAS(found_flag, 0, 1) == 0) {
                memcpy(found_entropy, entropy, 16);
                // Encode full address for output
                base58check_encode(payload, 25, found_address);
            }
            return;
        }
        
        iter += gridDim.x * blockDim.x;
    }
    
    // Update global counter
    atomicAdd(total_checked, ITERATIONS_PER_THREAD);
}
```

### 3.3 Host-Side Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     HOST (CPU)                          │
│                                                         │
│  ┌──────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │ CLI      │──▶│ Search       │──▶│ Result         │  │
│  │ (clap)   │   │ Coordinator  │   │ Verification   │  │
│  └──────────┘   └──────┬───────┘   │ (CPU Ed25519)  │  │
│                        │           └────────────────┘  │
│              ┌─────────┼─────────┐                     │
│              ▼         ▼         ▼                     │
│         ┌────────┐ ┌────────┐ ┌────────┐              │
│         │ GPU 0  │ │ GPU 1  │ │ CPU    │              │
│         │ Engine │ │ Engine │ │ Engine │              │
│         └───┬────┘ └───┬────┘ └────────┘              │
└─────────────┼──────────┼─────────────────────────────┘
              ▼          ▼
         ┌────────┐ ┌────────┐
         │RTX 5090│ │RTX ... │   (multi-GPU support)
         └────────┘ └────────┘
```

**Search Loop (host side):**

```
1. Generate 32-byte master seed (OS CSPRNG)
2. Upload seed + pattern to GPU constant memory
3. Launch kernel with grid = (SM_count, 256)
4. While not found:
   a. Kernel runs ITERATIONS_PER_THREAD per thread
   b. Check found_flag
   c. Read total_checked for progress display
   d. Re-launch kernel with incremented start_iteration
5. Download found_entropy
6. Verify on CPU (re-derive address, must match)
7. Display result with sEd... seed
```

**Critical: CPU-side verification.** The GPU result is always re-verified on the CPU using the trusted v2.3 Rust code. This catches any GPU computation errors.

### 3.4 Early-Exit Base58 Optimization

Full Base58 encoding of 25 bytes into ~33 characters is expensive (repeated big-integer division). For prefix matching, we only need the first N characters.

**Approach:** Partial Base58 encoding that computes only the leading characters.

The XRPL Base58 address is essentially a big-endian base-58 representation of a 25-byte integer. The most significant "digit" depends on the entire number, but we can compute the first few digits with partial division:

```cuda
__device__ bool check_prefix_fast(
    const uint8_t payload[25],
    const uint8_t* pattern,
    int pattern_len
) {
    // Convert 25-byte payload to big integer
    // Repeatedly divide by 58 to extract digits (from most significant)
    // Compare each digit against pattern
    // Return false as soon as mismatch found
    
    uint8_t temp[25];
    memcpy(temp, payload, 25);
    
    // For XRPL, first char is always 'r' (payload[0] = 0x00 → first Base58 digit = 'r')
    // So we only need to check pattern against chars 1..N
    
    for (int i = 0; i < pattern_len + 1; i++) {
        int digit = bigint_divmod58(temp, 25);
        if (i > 0) {  // Skip leading 'r'
            uint8_t expected = pattern[i - 1];
            uint8_t actual = XRPL_ALPHABET[digit];
            if (case_insensitive) {
                if (to_lower(actual) != to_lower(expected)) return false;
            } else {
                if (actual != expected) return false;
            }
        }
    }
    return true;
}
```

---

## 4. Build System

### Prerequisites

- **NVIDIA CUDA Toolkit 12.8+** (for Blackwell/sm_100 support)
- **Visual Studio 2022** with "Desktop development with C++" workload
- **CMake 3.24+**

### CMakeLists.txt (Outline)

```cmake
cmake_minimum_required(VERSION 3.24)
project(xrpl-vanity-gpu CUDA CXX)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

# Target RTX 5090 (Blackwell = sm_100)
set(CMAKE_CUDA_ARCHITECTURES 100)

# Optimization flags
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 --use_fast_math")
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")

add_executable(xrpl-vanity-gpu
    src/main.cpp
    src/Vanity.cpp
    src/GPU/GPUEngine.cu
    src/CPU/CPUEngine.cpp
    src/crypto/ed25519.cpp
    src/crypto/sha512.cpp
    src/crypto/sha256.cpp
    src/crypto/ripemd160.cpp
    src/crypto/base58.cpp
)

target_include_directories(xrpl-vanity-gpu PRIVATE src/)
```

### Build Commands

```powershell
# Windows (Visual Studio 2022 + CUDA 12.8)
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Linux
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## 5. Performance Tuning

### Register Pressure

Ed25519 scalar multiplication uses many temporary field elements (each 5 × uint64_t = 40 bytes). With extended coordinates (X, Y, Z, T), a single point = 160 bytes = 20 registers.

**RTX 5090:** 65,536 registers per SM × 170 SMs. Target 128 threads/block to allow ~256 registers per thread (enough for 2–3 temporary points + hash state).

### Occupancy

| Parameter | Value | Notes |
|-----------|-------|-------|
| Threads per block | 128–256 | Balance occupancy vs register pressure |
| Blocks per SM | 1–2 | Limited by register usage |
| Shared memory | ~16KB/block | For precomputed table subset |
| Total active threads | ~21,760–43,520 | 1–2 warps per SM |

### Memory Hierarchy

- **Constant memory (64KB):** Ed25519 basepoint precomputed table (~32KB)
- **Shared memory (per SM):** Partial lookup tables, shared hash state
- **Registers:** All hot-path field elements
- **Global memory:** Only for results + progress counter

### Key Optimization: Batch Modular Inversion

When computing Base58Check encoding, modular inverse can be batched using Montgomery's trick: compute N inverses with only 1 inversion + 3(N-1) multiplications. This is relevant if multiple threads share intermediate results.

---

## 6. Implementation Phases

### Phase 1: Hash Kernels (3–5 days)
- Implement SHA-256, SHA-512, RIPEMD-160 as CUDA device functions
- Unit test against CPU reference implementation
- Benchmark hash throughput independently

### Phase 2: Curve25519 Field Arithmetic (5–7 days)
- Implement fe25519 (5×51-bit limb representation)
- Operations: add, sub, mul, sq, inv, pow22523
- Use PTX inline assembly for critical multiply instructions
- Unit test every operation against libsodium reference

### Phase 3: Ed25519 Scalar Multiply (5–7 days)
- Implement ge25519 point operations (add, double, pack/unpack)
- Pre-compute fixed basepoint table
- Implement windowed scalar multiplication
- Verify: same entropy must produce same pubkey as CPU code

### Phase 4: Full Pipeline Integration (3–5 days)
- Wire up complete kernel: entropy → address → match
- Host-side search coordinator with progress display
- CPU-side result verification
- Multi-GPU support (enumerate + distribute work)

### Phase 5: Optimization & Testing (3–5 days)
- Profile with NVIDIA Nsight Compute
- Tune grid size, block size, registers per thread
- Test with known vanity patterns
- Fuzz testing: verify N thousand random entropies produce matching CPU/GPU addresses
- Edge cases: very short patterns, very long patterns, suffix, contains

### Total estimated effort: 3–4 weeks

---

## 7. GPU Correctness Validation

A GPU vanity generator is only useful if it produces addresses that are actually spendable on the XRPL. A subtle bug in 256-bit field arithmetic, byte order, or hash chaining could produce addresses that look valid but don't correspond to the derived seed — making any found wallet unrecoverable. This section defines a multi-layered correctness strategy.

### 7.1 Startup Known-Answer Test (KAT)

Before the search begins, the GPU pipeline is validated against hardcoded reference vectors. These vectors are pre-computed by the trusted CPU v2.3 implementation and compiled into the binary.

```cpp
// Compiled-in test vectors (from v2.3 Rust reference implementation)
struct KAT_Vector {
    uint8_t entropy[16];         // Input
    uint8_t private_key[32];     // SHA-512-Half(entropy)
    uint8_t public_key[32];      // Ed25519 scalar mult result
    uint8_t account_id[20];      // RIPEMD-160(SHA-256(0xED + pubkey))
    char    address[36];         // Full Base58Check address
    char    seed[29];            // sEd... family seed
};

static const KAT_Vector KAT_VECTORS[] = {
    // Vector 1: All-zeros entropy (edge case: small scalar)
    { {0x00, ...}, {...}, {...}, {...}, "rXXXXXXXXXXXXX...", "sEdXXXXXXXXXXX..." },
    // Vector 2: All-0xFF entropy (edge case: large scalar near group order)
    { {0xFF, ...}, {...}, {...}, {...}, "rXXXXXXXXXXXXX...", "sEdXXXXXXXXXXX..." },
    // Vector 3: Known "rLocutus" address (real-world validation)
    { {0xAB, ...}, {...}, {...}, {...}, "rXXXXXXXXXXXXX...", "sEdXXXXXXXXXXX..." },
    // Vector 4: Entropy that produces pubkey with leading zero bytes
    { {0x37, ...}, {...}, {...}, {...}, "rXXXXXXXXXXXXX...", "sEdXXXXXXXXXXX..." },
    // Vector 5: Entropy that produces account_id with leading zero byte
    { {0xC2, ...}, {...}, {...}, {...}, "rXXXXXXXXXXXXX...", "sEdXXXXXXXXXXX..." },
};
```

**The startup test validates every intermediate step, not just the final address:**

```cpp
bool run_gpu_validation(GPUEngine& gpu) {
    printf("Running GPU correctness validation...\n");

    for (int i = 0; i < NUM_KAT_VECTORS; i++) {
        const auto& v = KAT_VECTORS[i];

        // Upload single entropy to GPU
        GPUResult result = gpu.derive_single(v.entropy);

        // 1. Check SHA-512-Half (key derivation)
        if (memcmp(result.private_key, v.private_key, 32) != 0) {
            fprintf(stderr, "FAIL: KAT vector %d — SHA-512-Half mismatch\n", i);
            fprintf(stderr, "  Expected: %s\n", hex(v.private_key, 32));
            fprintf(stderr, "  Got:      %s\n", hex(result.private_key, 32));
            return false;
        }

        // 2. Check Ed25519 scalar multiplication
        if (memcmp(result.public_key, v.public_key, 32) != 0) {
            fprintf(stderr, "FAIL: KAT vector %d — Ed25519 pubkey mismatch\n", i);
            fprintf(stderr, "  This usually indicates a bug in Curve25519 field "
                            "arithmetic\n");
            fprintf(stderr, "  Expected: %s\n", hex(v.public_key, 32));
            fprintf(stderr, "  Got:      %s\n", hex(result.public_key, 32));
            return false;
        }

        // 3. Check Account ID (SHA-256 + RIPEMD-160 chain)
        if (memcmp(result.account_id, v.account_id, 20) != 0) {
            fprintf(stderr, "FAIL: KAT vector %d — Account ID mismatch\n", i);
            fprintf(stderr, "  Check: 0xED prefix, SHA-256, RIPEMD-160, "
                            "byte order\n");
            return false;
        }

        // 4. Check full Base58Check address
        if (strcmp(result.address, v.address) != 0) {
            fprintf(stderr, "FAIL: KAT vector %d — Address mismatch\n", i);
            fprintf(stderr, "  Expected: %s\n", v.address);
            fprintf(stderr, "  Got:      %s\n", result.address);
            return false;
        }

        printf("  KAT vector %d: OK (%s)\n", i, v.address);
    }

    printf("All %d KAT vectors passed. GPU pipeline is correct.\n\n",
           NUM_KAT_VECTORS);
    return true;
}
```

**KAT edge cases and what they catch:**

| Vector | Edge Case | Catches |
|--------|-----------|---------|
| All-zeros entropy | Scalar = SHA-512-Half(0x00...) | Neutral element handling, zero-limb bugs |
| All-0xFF entropy | Large scalar near group order | Scalar clamping, reduction mod L |
| Known real address | Full round-trip | General pipeline correctness |
| Pubkey with leading 0x00 | Short Ed25519 encoding | Byte padding / length bugs |
| Account ID with leading 0x00 | Base58 leading-zero encoding | Base58 '1'-prefix handling (XRPL: 'r') |

**If any KAT vector fails, the program prints a diagnostic error and exits immediately. No search is started.**

### 7.2 Continuous Fuzz Validation (Phase 5 Testing)

During development, a fuzz harness validates GPU correctness at scale:

```cpp
// Generate N random entropies on CPU
// Send each to GPU pipeline AND CPU reference (v2.3 Rust via FFI)
// Compare all intermediate results
// Report any mismatch with full diagnostic dump

void fuzz_gpu_vs_cpu(GPUEngine& gpu, int iterations) {
    std::mt19937_64 rng(std::random_device{}());

    for (int i = 0; i < iterations; i++) {
        uint8_t entropy[16];
        for (int j = 0; j < 16; j++)
            entropy[j] = rng() & 0xFF;

        GPUResult  gpu_result = gpu.derive_single(entropy);
        CPUResult  cpu_result = cpu_derive(entropy);  // calls v2.3 Rust code

        assert(memcmp(gpu_result.private_key,
                      cpu_result.private_key, 32) == 0);
        assert(memcmp(gpu_result.public_key,
                      cpu_result.public_key,  32) == 0);
        assert(memcmp(gpu_result.account_id,
                      cpu_result.account_id,  20) == 0);
        assert(strcmp(gpu_result.address,
                      cpu_result.address)         == 0);

        if (i % 10000 == 0)
            printf("  Fuzz: %d/%d passed\n", i, iterations);
    }
    printf("Fuzz validation: %d random entropies — all matched.\n",
           iterations);
}
```

**Target: 100,000+ random entropies must match before a release build is considered correct.**

### 7.3 Runtime Result Verification

Every match found during the actual search is re-verified on the CPU before being shown to the user:

```cpp
void on_gpu_match_found(const uint8_t entropy[16],
                        const char* gpu_address) {
    // Step 1: CPU independently re-derives the address
    CPUResult cpu = cpu_derive(entropy);

    // Step 2: Verify GPU and CPU agree
    if (strcmp(gpu_address, cpu.address) != 0) {
        fprintf(stderr,
            "WARNING: GPU/CPU address mismatch! Discarding result.\n");
        fprintf(stderr, "  GPU: %s\n", gpu_address);
        fprintf(stderr, "  CPU: %s\n", cpu.address);
        return;  // Discard — do NOT show to user
    }

    // Step 3: Verify address actually matches the search pattern
    if (!pattern_matches(cpu.address, search_pattern)) {
        fprintf(stderr,
            "WARNING: Address doesn't match pattern! Discarding.\n");
        return;
    }

    // Step 4: Verify seed round-trip
    //   Encode entropy as sEd... seed, decode back, compare
    char seed[29];
    entropy_to_seed(entropy, seed);
    uint8_t decoded_entropy[16];
    seed_to_entropy(seed, decoded_entropy);
    if (memcmp(entropy, decoded_entropy, 16) != 0) {
        fprintf(stderr, "FATAL: Seed encoding round-trip failed!\n");
        return;
    }

    // Step 5: All checks passed — display to user
    display_result(cpu.address, seed, cpu.public_key, cpu.private_key);
}
```

### 7.4 Validation Summary

```
 STARTUP (before search)
 ┌──────────────────────────────────────────────────┐
 │  5 KAT vectors × 4 intermediate checks each     │
 │  = 20 assertions                                 │
 │  Tests: SHA-512, Ed25519, SHA-256, RIPEMD-160,   │
 │         Base58, edge cases                       │
 │  FAIL → exit immediately, no search              │
 └──────────────────────────────────────────────────┘
                        │ PASS
                        ▼
 DEVELOPMENT (Phase 5)
 ┌──────────────────────────────────────────────────┐
 │  100,000+ random entropies                       │
 │  GPU result vs CPU reference (v2.3 Rust)         │
 │  All intermediate values must match              │
 │  FAIL → fix GPU code, do not release             │
 └──────────────────────────────────────────────────┘
                        │ PASS
                        ▼
 RUNTIME (every match)
 ┌──────────────────────────────────────────────────┐
 │  CPU re-derives address from found entropy       │
 │  Verifies: GPU addr == CPU addr                  │
 │  Verifies: address matches search pattern        │
 │  Verifies: seed round-trip (encode → decode)     │
 │  FAIL → discard result, log warning              │
 └──────────────────────────────────────────────────┘
                        │ PASS
                        ▼
              Display seed to user
```

**This three-layer approach guarantees:** The user never receives a seed for an address that doesn't exist on the XRPL. Systematic bugs are caught at startup (KAT), rare arithmetic edge cases are caught by fuzz testing (development), and any transient GPU error (thermal, bit-flip) is caught at runtime (verification).

---

## 8. Security Considerations

### PRNG on GPU

The GPU PRNG (Philox-4x32) is seeded from the host's OS CSPRNG. Philox is a counter-based CSPRNG used by NVIDIA's cuRAND library and has been analyzed for cryptographic use. Each thread gets a unique (key, counter) pair, ensuring no two threads ever generate the same entropy.

### GPU Memory Side-Channels

- **Private keys exist in GPU global memory briefly.** They are overwritten each iteration.
- **Found results** are written to global memory once and read by the host.
- **No GPU memory encryption** (unlike CPU with TME). For maximum paranoia, run in an air-gapped system.
- **PCIe bus:** The only sensitive data transferred is the 16-byte found entropy (once, at the end).

### Result Verification

See Section 7 (GPU Correctness Validation) for the full three-layer verification strategy.

---

## 9. CLI Interface

Maintain compatibility with v2.3 where possible:

```
xrpl-vanity-gpu [OPTIONS]

OPTIONS:
  -p, --prefix <PATTERN>    Desired prefix after 'r'
  -s, --suffix <PATTERN>    Desired suffix
  -c, --contains <PATTERN>  Substring anywhere
  -n, --count <N>           Find N matches (default: 1)
  -i, --case-insensitive    Case-insensitive matching
  -t, --threads <N>         CPU threads (default: all cores)
  --gpu                     Enable GPU acceleration (default: auto-detect)
  --gpu-id <ID>             Specific GPU to use (default: all)
  --gpu-grid <GxB>          Grid size (e.g. "170x256", default: auto)
  --no-gpu                  Disable GPU, CPU-only mode
  --clear                   Clear screen after displaying results
  --progress-every-million <N>  Progress interval (default: 100)
  -h, --help                Show help
  -V, --version             Show version
```

---

## 10. Open Questions & Risks

1. **Ed25519 vs secp256k1 GPU efficiency gap.** Research suggests Ed25519 scalar multiply is ~2–3x slower than secp256k1 on GPUs due to the different field arithmetic. This means we may not reach the 1+ GKey/s that VanitySearch achieves for Bitcoin, but 150–300M addr/s is realistic.

2. **Register pressure.** Extended twisted Edwards coordinates need 4 field elements per point (X, Y, Z, T). With 5×51-bit limbs, that's 20 uint64_t = 160 bytes per point. The kernel needs ~3–4 temporary points → 60–80 registers just for EC math. This limits occupancy but may not matter if the kernel is compute-bound.

3. **Blackwell compute capability.** The RTX 5090 is Compute Capability 10.x (sm_100). CUDA 12.8+ is required. Some PTX instructions may have new optimizations for Blackwell that aren't yet documented.

4. **Base58 on GPU.** Full Base58 encoding requires repeated big-integer division, which is slow on GPUs. The early-exit optimization (only encode enough chars to check the pattern) is essential for performance.

5. **Language choice.** VanitySearch is C++/CUDA. Our CPU version is Rust. Options:
   - Pure C++/CUDA (easiest GPU integration, lose Rust safety)
   - Rust + cuda-sys FFI (keep Rust host code, CUDA kernels in .cu files)
   - Rust + cudarc (higher-level Rust CUDA bindings, less mature)

   **Recommendation:** C++/CUDA for the GPU version. Keep the Rust v2.3 CPU version as a separate tool and for verification.

---

## 11. References

- JeanLucPons/VanitySearch — [github.com/JeanLucPons/VanitySearch](https://github.com/JeanLucPons/VanitySearch)
- "Fast GPGPU-Based Elliptic Curve Scalar Multiplication" — [eprint.iacr.org/2014/198](https://eprint.iacr.org/2014/198.pdf)
- "AsyncGBP: Efficient CUDA Ed25519 on RTX 3070" — [ACM DL](https://dl.acm.org/doi/fullHtml/10.1145/3605573.3605620)
- "gECC: GPU-based ECC Framework" — [arxiv.org/abs/2501.03245](https://arxiv.org/html/2501.03245v1)
- 8891689/Secp256k1-CUDA-ecc — [github.com/8891689/Secp256k1-CUDA-ecc](https://github.com/8891689/Secp256k1-CUDA-ecc)
- HareInWeed/gec — [github.com/HareInWeed/gec](https://github.com/HareInWeed/gec)
- Daniel J. Bernstein: "Curve25519: new Diffie-Hellman speed records"
- NVIDIA CUDA Programming Guide, Compute Capability 10.x
