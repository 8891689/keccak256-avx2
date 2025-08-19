// File: sha1_test_avx2.c
// g++ / gcc -o sha1_avx2_test sha1_test_avx2.c sha1_avx2.c -O3 -march=native -Wall -mavx2 -flto

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <stdint.h>  
#include "sha1_avx2.h"

// For pretty printing test results
#define KGRN  "\x1B[32m"
#define KRED  "\x1B[31m"
#define KNRM  "\x1B[0m"

// ============================================================================
// ==                                                                        ==
// ==                          Helper Functions                              ==
// ==                                                                        ==
// ============================================================================

// Helper to convert a hex string hash to a byte array for memcmp
void hex_string_to_bytes(const char* hex_str, uint8_t byte_array[20]) {
    for (size_t i = 0; i < 20; ++i) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
}

// Helper to print and track test status
bool check_and_print(const char* test_name, const uint8_t* result, const char* expected_hex) {
    uint8_t expected_bytes[20];
    hex_string_to_bytes(expected_hex, expected_bytes);

    printf("  Test: %s\n", test_name);
    printf("    Result:   "); PrintSHA1(result); printf("\n");
    printf("    Expected: %s\n", expected_hex);

    if (memcmp(result, expected_bytes, 20) == 0) {
        printf("    Status: %s[PASS]%s\n\n", KGRN, KNRM);
        return true;
    } else {
        printf("    Status: %s[FAIL]%s\n\n", KRED, KNRM);
        return false;
    }
}


// ============================================================================
// ==                                                                        ==
// ==                       Correctness Test Section                         ==
// ==                                                                        ==
// ============================================================================

bool run_correctness_tests() {
    printf("--- Running Correctness Tests ---\n\n");
    bool all_passed = true;

    // --- 1. Basic Scalar SHA-1 Test ---
    printf("--- [Section 1: Scalar Implementation] ---\n");
    const char* str1 = "abc";
    SHA1_CTX ctx_s;
    uint8_t hash_s[20];
    SHA1_Init(&ctx_s);
    SHA1_Update(&ctx_s, (const uint8_t*)str1, strlen(str1));
    SHA1_Final(&ctx_s, hash_s);
    all_passed &= check_and_print("Scalar 'abc'", hash_s, "a9993e364706816aba3e25717850c26c9cd0d89d");


    // --- 2. Basic AVX2 Batch SHA-1 Test ---
    printf("--- [Section 2: Basic AVX2 Batch] ---\n");
    const char* test_strings[] = {
        "abc",
        "",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "This is a test string.",
        "AVX2 implementation",
        "A slightly longer string to test multi-block processing capability.",
        "12345",
        "Another test!"
    };
    const char* expected_hashes[] = {
        "a9993e364706816aba3e25717850c26c9cd0d89d", // abc
        "da39a3ee5e6b4b0d3255bfef95601890afd80709", // ""
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1", // abcd...
        "3532499280b4e2f32f6417e556901a526d69143c", // This is a test string.
        "0d11fa540ff1aa4796cdd2a91fcb63205bac4cfa", // AVX2 implementation
        "ef19a54dc106616b6296d175d68a20ef457016d8", // A slightly longer...
        "8cb2237d0679ca88db6464eac60da96345513964", // 12345
        "52adbb608a63ba56f12bcd9e56465ee0f6a31780"  // Another test!
    };

    const uint8_t* data[SHA1_AVX2_LANES];
    size_t lens[SHA1_AVX2_LANES];
    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        data[i] = (const uint8_t*)test_strings[i];
        lens[i] = strlen(test_strings[i]);
    }

    SHA1_CTX_AVX2 ctx_avx;
    uint8_t digests[SHA1_AVX2_LANES][20];
    SHA1BatchInit(&ctx_avx);
    SHA1BatchUpdate(&ctx_avx, data, lens);
    SHA1BatchFinal(&ctx_avx, digests);

    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        char test_name[128];
        snprintf(test_name, sizeof(test_name), "AVX2 Lane %d ('%.10s...')", i, test_strings[i]);
        all_passed &= check_and_print(test_name, digests[i], expected_hashes[i]);
    }

    // --- 3. Edge Case Tests for Padding and Block Boundaries ---
    printf("--- [Section 3: AVX2 Edge Cases (Padding)] ---\n");
    char edge_buffer[SHA1_AVX2_LANES][66];
    const char* edge_hashes[SHA1_AVX2_LANES] = {
        "c1c8bbdc22796e28c0e15163d20899b65621d65a", // 55 bytes ('a') -> padding fits in one block
        "049adea016c8a8e3b7a9054aeeaa8643453bebd9", // 56 bytes ('b') -> padding requires a new block
        "3f85dc2655c3426a4937d49028c01a066c535ce0", // 63 bytes ('c')
        "7d4f9b6d084894fb8640dc55aab16ad0e021e4c8", // 64 bytes ('d')
        "00c26b97f0dceca9387928bffdc36d303e31d536", // 65 bytes ('e')
        "", "", "" // Unused lanes
    };
    
    memset(edge_buffer[0], 'a', 55); edge_buffer[0][55] = '\0';
    memset(edge_buffer[1], 'b', 56); edge_buffer[1][56] = '\0';
    memset(edge_buffer[2], 'c', 63); edge_buffer[2][63] = '\0';
    memset(edge_buffer[3], 'd', 64); edge_buffer[3][64] = '\0';
    memset(edge_buffer[4], 'e', 65); edge_buffer[4][65] = '\0';

    for (int i = 0; i < 5; ++i) { // Only test the first 5 lanes
        data[i] = (const uint8_t*)edge_buffer[i];
        lens[i] = strlen(edge_buffer[i]);
    }
    for (int i = 5; i < SHA1_AVX2_LANES; ++i) { // Empty strings for unused lanes
        data[i] = (const uint8_t*)"";
        lens[i] = 0;
    }

    SHA1BatchInit(&ctx_avx);
    SHA1BatchUpdate(&ctx_avx, data, lens);
    SHA1BatchFinal(&ctx_avx, digests);

    for (int i = 0; i < 5; ++i) {
        char test_name[128];
        snprintf(test_name, sizeof(test_name), "AVX2 Edge Case (len=%zu)", lens[i]);
        all_passed &= check_and_print(test_name, digests[i], edge_hashes[i]);
    }

    // --- 4. Multiple Update Test (Streaming Data Simulation) ---
    printf("--- [Section 4: AVX2 Multiple Updates (Streaming)] ---\n");
    const char* streaming_str = "This string will be processed byte by byte.";
    const char* streaming_hash = "913a4ec9683a2a0caf9709fbf64bca37d28f0812";
    
    // Prepare data for all lanes (all process the same string)
    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        lens[i] = 1; // We update one byte at a time
    }

    SHA1BatchInit(&ctx_avx);
    // Update byte by byte for all lanes
    for (size_t j = 0; j < strlen(streaming_str); ++j) {
        for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
            data[i] = (const uint8_t*)&streaming_str[j];
        }
        SHA1BatchUpdate(&ctx_avx, data, lens);
    }
    SHA1BatchFinal(&ctx_avx, digests);

    // Check one of the lanes (they should all be the same)
    all_passed &= check_and_print("AVX2 Streaming Test", digests[0], streaming_hash);


    printf("--- Correctness Tests Finished ---\n");
    if (all_passed) {
        printf("Result: %sAll tests passed.%s\n\n", KGRN, KNRM);
    } else {
        printf("Result: %sOne or more tests failed.%s\n\n", KRED, KNRM);
    }
    
    return all_passed;
}


// ============================================================================
// ==                                                                        ==
// ==                       Performance Test Section                         ==
// ==                                                                        ==
// ============================================================================

#define PERF_BUFFER_SIZE (16 * 1024 * 1024) 
#define PERF_TEST_SECONDS 3                

void run_performance_tests() {
    printf("--- Running Throughput Performance Tests ---\n");
    printf("Buffer size: %d MB/lane, Test duration: ~%d seconds\n\n", PERF_BUFFER_SIZE / (1024 * 1024), PERF_TEST_SECONDS);

    struct timespec start, end;
    long long total_bytes;
    double elapsed_time;
    
    // --- Scalar Performance Test ---
    uint8_t* scalar_buffer = (uint8_t*)malloc(PERF_BUFFER_SIZE);
    if (!scalar_buffer) {
        printf("Failed to allocate memory for scalar performance test.\n");
        return;
    }
    for (size_t i = 0; i < PERF_BUFFER_SIZE; ++i) {
        scalar_buffer[i] = (uint8_t)i;
    }

    printf("Testing Scalar throughput...\n");
    total_bytes = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        SHA1_CTX ctx;
        uint8_t digest[20];
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, scalar_buffer, PERF_BUFFER_SIZE);
        SHA1_Final(&ctx, digest);
        total_bytes += PERF_BUFFER_SIZE;
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    } while (elapsed_time < PERF_TEST_SECONDS);

    double scalar_throughput = (double)total_bytes / elapsed_time / (1024 * 1024 * 1024);
    printf("  Result: %.2f GB/s\n\n", scalar_throughput);
    free(scalar_buffer);

    // --- AVX2 Batch Performance Test ---
    uint8_t* avx_buffers[SHA1_AVX2_LANES];
    const uint8_t* data[SHA1_AVX2_LANES];
    size_t lens[SHA1_AVX2_LANES];

    bool allocation_ok = true;
    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        avx_buffers[i] = (uint8_t*)malloc(PERF_BUFFER_SIZE);
        if (!avx_buffers[i]) {
            fprintf(stderr, "Failed to allocate memory for AVX2 perf test lane %d.\n", i);
            allocation_ok = false;
            break;
        }
        for (size_t j = 0; j < PERF_BUFFER_SIZE; ++j) {
            avx_buffers[i][j] = (uint8_t)(j + i);
        }
        data[i] = avx_buffers[i];
        lens[i] = PERF_BUFFER_SIZE;
    }

    if(allocation_ok) {
        printf("Testing AVX2 Batch throughput...\n");
        total_bytes = 0;
        clock_gettime(CLOCK_MONOTONIC, &start);
        do {
            SHA1_CTX_AVX2 ctx;
            uint8_t digests[SHA1_AVX2_LANES][20];
            SHA1BatchInit(&ctx);
            SHA1BatchUpdate(&ctx, data, lens);
            SHA1BatchFinal(&ctx, digests);
            total_bytes += (long long)PERF_BUFFER_SIZE * SHA1_AVX2_LANES;
            clock_gettime(CLOCK_MONOTONIC, &end);
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        } while (elapsed_time < PERF_TEST_SECONDS);
        
        double avx2_throughput = (double)total_bytes / elapsed_time / (1024 * 1024 * 1024);
        printf("  Result: %.2f GB/s\n\n", avx2_throughput);
        
        printf("--- Performance Summary ---\n");
        printf("Improvement: %.2fx\n\n", avx2_throughput / scalar_throughput);
    }
    
    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        if (avx_buffers[i]) free(avx_buffers[i]);
    }
}


// ============================================================================
// ==                                                                        ==
// ==                             Test Main Function                         ==
// ==                                                                        ==
// ============================================================================
int main() {
    bool passed = run_correctness_tests();
    
    if (passed) {
        run_performance_tests();
    } else {
        printf("Skipping performance tests due to correctness test failures.\n");
    }

    return passed ? 0 : 1; // Return 0 on success, 1 on failure
}
