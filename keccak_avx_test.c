// main.c  gcc -O3 -mavx2 -mfma -march=native keccak_avx_test.c keccak256_avx.c -o keccak_avx_test
// Author: 8891689
// https://github.com/8891689
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>    
#include "keccak256_avx.h" 

#define NUM_LANES 8
#define BENCHMARK_DURATION_SECONDS 5.0

static uint8_t input_data_8blocks_for_abc[NUM_LANES][KECCAK_RATE_BYTES] __attribute__((aligned(32)));
static uint8_t input_data_8blocks_for_bench[NUM_LANES][KECCAK_RATE_BYTES] __attribute__((aligned(32)));
static uint8_t output_hashes_8lanes[NUM_LANES][KECCAK_HASH_BYTES] __attribute__((aligned(32)));


void print_hash_lane(const uint8_t *hash_val, size_t len, int lane_idx) {
    printf("Lane %d: ", lane_idx);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", hash_val[i]);
    }
    printf("\n");
}


int prepare_keccak_padded_block(const char* message, size_t message_len, uint8_t* block) {
    memset(block, 0, KECCAK_RATE_BYTES); 


    if (message_len > KECCAK_RATE_BYTES) {
        fprintf(stderr, "Error: Message (len %zu) too long for single block simple padding (max rate %d).\n", message_len, KECCAK_RATE_BYTES);
        return 1;
    }
    if (message_len == KECCAK_RATE_BYTES) {

        memcpy(block, message, message_len);
        printf("Warning: Message (len %zu) fills the entire block. Padding (0x01...0x80) would require a new block (not fully handled by this simple absorb test).\n", message_len);
 
        return 0; 
    }
    if (message_len == KECCAK_RATE_BYTES - 1) {
        memcpy(block, message, message_len);
        block[message_len] = 0x01;
        printf("Warning: Message (len %zu) leaves 1 byte. 0x01 is padded. 0x80 would require a new block (not fully handled by this simple absorb test).\n", message_len);
        return 0; 
    }

    memcpy(block, message, message_len);
    block[message_len] = 0x01; 
    block[KECCAK_RATE_BYTES - 1] |= 0x80; 
    return 0;
}


int main() {
    KECCAK_CTX_AVX8 ctx;

    // --- Test and print hash of "abc" using Keccak256 padding ---
    printf("Calculating Keccak256 of \"abc\" for all %d lanes:\n", NUM_LANES);
    const char *abc_message = "abc";
    size_t abc_len = strlen(abc_message);

    if (abc_len > KECCAK_RATE_BYTES - 2) {
        fprintf(stderr, "Error: Message \"%s\" (len %zu) is too long for the simple single-block padding test with KECCAK_RATE_BYTES = %d. Max len supported is %d.\n",
                abc_message, abc_len, KECCAK_RATE_BYTES, KECCAK_RATE_BYTES - 2);
        return 1;
    }

    for (int i = 0; i < NUM_LANES; ++i) {
        if (prepare_keccak_padded_block(abc_message, abc_len, input_data_8blocks_for_abc[i]) != 0) {
            fprintf(stderr, "Failed to prepare padded block for \"abc\" in lane %d.\n", i);
            return 1;
        }
    }
    init_keccak_ctx_avx8(&ctx);
    keccak_absorb_8blocks_avx8(&ctx, input_data_8blocks_for_abc); 
    keccak_extract_hash_8lanes_avx8(&ctx, output_hashes_8lanes);

    // Keccak256("abc") hash (common/Ethereum variant):
    // 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    printf("Expected Keccak256(\"abc\"): 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45\n");
    for (int i = 0; i < NUM_LANES; ++i) {
        print_hash_lane(output_hashes_8lanes[i], KECCAK_HASH_BYTES, i);
    }
    printf("======================================\n\n");

    printf("Starting benchmark for approximately %.1f seconds...\n", BENCHMARK_DURATION_SECONDS);
    printf("Each operation processes %d bytes per lane (%d bytes total per 8-lane op).\n",
           KECCAK_RATE_BYTES, KECCAK_RATE_BYTES * NUM_LANES);
    for (int i = 0; i < NUM_LANES; ++i) {
        for (int j = 0; j < KECCAK_RATE_BYTES; ++j) {
            input_data_8blocks_for_bench[i][j] = (uint8_t)(i + j * 3 + 7);
        }
    }

    struct timespec bench_start_time, bench_current_time;
    double wall_time_used = 0.0;
    long long operations_count = 0;
    init_keccak_ctx_avx8(&ctx);

    clock_gettime(CLOCK_MONOTONIC, &bench_start_time);
    while (wall_time_used < BENCHMARK_DURATION_SECONDS) {
        keccak_absorb_8blocks_avx8(&ctx, input_data_8blocks_for_bench);
        operations_count++;
        if (operations_count % 1000 == 0) { 
            clock_gettime(CLOCK_MONOTONIC, &bench_current_time);
            wall_time_used = (double)(bench_current_time.tv_sec - bench_start_time.tv_sec) +
                             (double)(bench_current_time.tv_nsec - bench_start_time.tv_nsec) / 1000000000.0;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &bench_current_time);
    wall_time_used = (double)(bench_current_time.tv_sec - bench_start_time.tv_sec) +
                     (double)(bench_current_time.tv_nsec - bench_start_time.tv_nsec) / 1000000000.0;
    keccak_extract_hash_8lanes_avx8(&ctx, output_hashes_8lanes);


    printf("\nBenchmark finished.\n");
    printf("--------------------------------------\n");
    printf("Total 8-lane operations:  %lld\n", operations_count);
    long long total_hashes_calculated = operations_count * NUM_LANES; 
    long long total_bytes_processed = operations_count * (long long)NUM_LANES * KECCAK_RATE_BYTES;

    printf("Total individual hashes (streams processed): %lld\n", total_hashes_calculated);
    printf("Actual wall time taken:   %.4f seconds\n", wall_time_used);

    if (wall_time_used > 0.0001) { 
        double hashes_per_second_total = (double)total_hashes_calculated / wall_time_used;
        double megabytes_processed = (double)total_bytes_processed / (1024.0 * 1024.0);
        double megabytes_per_second = megabytes_processed / wall_time_used;

        printf("Individual Hashes/sec (streams): %.2f\n", hashes_per_second_total);
        printf("Total data processed:              %.2f MB\n", megabytes_processed);
        printf("Data processing rate:              %.2f MB/s\n", megabytes_per_second);
    } else {
        printf("Wall time taken was too short (%.6f s) to calculate rates accurately.\n", wall_time_used);
    }
    printf("======================================\n");

    if (operations_count > 0) {
       printf("Sample hash from benchmark (Lane 0) after %lld operations:\n", operations_count);
       print_hash_lane(output_hashes_8lanes[0], KECCAK_HASH_BYTES, 0);
    }

    return 0;
}
