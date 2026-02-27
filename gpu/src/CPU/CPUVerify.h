#pragma once
#include <cstdint>
#include <string>

// CPU-side XRPL address derivation for result verification
// Uses standard, well-tested implementations (not GPU code)
// Every GPU result is re-verified here before being shown to the user.

struct CPUResult {
    uint8_t  entropy[16];
    uint8_t  private_key[32];
    uint8_t  public_key[32];
    uint8_t  account_id[20];
    char     address[36];
    char     seed[30];          // sEd... family seed
};

class CPUVerify {
public:
    // Derive full XRPL address from 16-byte entropy
    static CPUResult derive(const uint8_t entropy[16]);

    // Verify that a GPU result matches CPU derivation
    // Returns true if all fields match
    static bool verify(const uint8_t entropy[16], const char* gpu_address);

    // Encode entropy as XRPL family seed (sEd... format)
    static std::string entropy_to_seed(const uint8_t entropy[16]);

    // Check pattern match against an address
    static bool pattern_matches(const char* address,
                                const char* pattern, int pattern_len,
                                int pattern_type, bool case_insensitive);

    // Run Known-Answer Tests (KAT) — returns true if all pass
    static bool run_kat();

    // Hex encode for diagnostic output
    static std::string hex_encode(const uint8_t* data, int len);
};
