cmake_minimum_required(VERSION 3.24)
project(xrpl-vanity-gpu CUDA CXX)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

# Target architectures: Ampere (sm_86), Ada Lovelace (sm_89), Blackwell (sm_100)
set(CMAKE_CUDA_ARCHITECTURES 86 89 100)

# Allow newer MSVC versions (CUDA 13.1 officially supports up to VS 2022)
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --allow-unsupported-compiler")

# Optimization flags
set(CMAKE_CUDA_FLAGS_RELEASE "${CMAKE_CUDA_FLAGS_RELEASE} -O3 --use_fast_math")
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")

add_executable(xrpl-vanity-gpu
    src/main.cpp
    src/Vanity.cpp
    src/GPU/GPUEngine.cu
    src/CPU/CPUVerify.cpp
)

target_include_directories(xrpl-vanity-gpu PRIVATE src/)
