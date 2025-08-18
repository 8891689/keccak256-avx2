// gcc -o md5_avx2_test md5_test_avx2.c md5_avx2.c -O3 -march=native -Wall -mavx2 -flto -fno-trapping-math -fno-math-errno
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <immintrin.h>
#include "md5_avx2.h"

#define BATCH_SIZE MD5_AVX2_LANES
#define DATA_SIZE (128 * 1024 * 1024)  // 128MB per stream
#define NUM_STREAMS BATCH_SIZE
#define NUM_ITERATIONS 5
#define ALIGNMENT 32

// Forward declaration for a helper function used in verification
extern void PrintMD5(const uint8_t digest[16]); 

// Error handling macro
#define CHECK_ALLOC(ptr, msg) \
    if(!(ptr)) { \
        perror(msg); \
        exit(EXIT_FAILURE); \
    }

// Data initialization
static void initialize_streams(uint8_t** streams) {
    for(int i = 0; i < NUM_STREAMS; i++) {
        uint8_t* stream = streams[i];
        
        // Use AVX2 to accelerate initialization
        size_t offset = 0;
        for(; offset + 32 <= DATA_SIZE; offset += 32) {
            __m256i data_vec = _mm256_setr_epi8(
                i, i+1, i+2, i+3, i+4, i+5, i+6, i+7,
                i+8, i+9, i+10, i+11, i+12, i+13, i+14, i+15,
                i+16, i+17, i+18, i+19, i+20, i+21, i+22, i+23,
                i+24, i+25, i+26, i+27, i+28, i+29, i+30, i+31
            );
            _mm256_store_si256((__m256i*)(stream + offset), data_vec);
        }
        
        // Handle the remainder
        for(; offset < DATA_SIZE; offset++) {
            stream[offset] = (uint8_t)(i + offset);
        }
    }
}

// Run the test and return the average time
static double run_test(double* throughput, void (*test_func)(void*), void* context, size_t total_size) {
    struct timespec start, end;
    double total_time = 0.0;
    
    for(int iter = 0; iter < NUM_ITERATIONS; iter++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        test_func(context);
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double elapsed = (end.tv_sec - start.tv_sec) + 
                         (end.tv_nsec - start.tv_nsec) * 1e-9;
        total_time += elapsed;
        
        double iter_throughput = (double)total_size / elapsed / (1024 * 1024);
        throughput[iter] = iter_throughput;
    }
    
    return total_time / NUM_ITERATIONS;
}

// Scalar test context
typedef struct {
    uint8_t** streams;
    uint8_t (*digests)[16];
} ScalarTestContext;

static void scalar_test(void* ctx) {
    ScalarTestContext* context = (ScalarTestContext*)ctx;
    for(int i = 0; i < NUM_STREAMS; i++) {
        MD5_CTX c;
        MD5Init(&c);
        MD5Update(&c, context->streams[i], DATA_SIZE);
        MD5Final(&c, context->digests[i]);
    }
}

// AVX2 test context
typedef struct {
    uint8_t** streams;
    uint8_t (*digests)[16];
} AVX2TestContext;

static void avx2_test(void* ctx) {
    AVX2TestContext* context = (AVX2TestContext*)ctx;
    MD5_CTX_AVX2 ctx_avx2;
    MD5BatchInit(&ctx_avx2);
    
    const uint8_t* data_ptrs[BATCH_SIZE];
    size_t lens[BATCH_SIZE];
    
    for(int i = 0; i < BATCH_SIZE; i++) { 
        data_ptrs[i] = context->streams[i]; 
        lens[i] = DATA_SIZE; 
    }
    
    MD5BatchUpdate(&ctx_avx2, data_ptrs, lens);
    MD5BatchFinal(&ctx_avx2, context->digests);
}

int main() {
    const size_t total_data_size = (size_t)NUM_STREAMS * DATA_SIZE;
    
    printf("\n=== MD5 AVX2 High-Performance Benchmark ===\n");
    printf("Configuration: %d independent data streams, each %.2f MB\n", 
           NUM_STREAMS, (double)DATA_SIZE/(1024 * 1024));
    printf("Total data size: %.2f MB\n", (double)total_data_size/(1024 * 1024));
    printf("Number of test iterations: %d\n\n", NUM_ITERATIONS);

    // Memory setup
    uint8_t* data_streams[NUM_STREAMS];
    for(int i = 0; i < NUM_STREAMS; i++) {
        if(posix_memalign((void**)&data_streams[i], ALIGNMENT, DATA_SIZE)) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
    }
    
    // Data initialization
    printf("Initializing data streams...");
    fflush(stdout);
    initialize_streams(data_streams);
    printf("Done\n\n");

    // Prepare tests
    uint8_t scalar_digests[NUM_STREAMS][16] = {{0}};
    uint8_t avx2_digests[NUM_STREAMS][16] = {{0}};
    
    double scalar_throughput[NUM_ITERATIONS] = {0};
    double avx2_throughput[NUM_ITERATIONS] = {0};
    
    // Warm-up run
    printf("Performing warm-up run...");
    fflush(stdout);
    ScalarTestContext warm_ctx = {data_streams, scalar_digests};
    scalar_test(&warm_ctx);
    printf("Done\n");

    // Run benchmarks
    printf("\n=== Scalar Benchmark ===\n");
    ScalarTestContext scalar_ctx = {data_streams, scalar_digests};
    double avg_scalar_time = run_test(scalar_throughput, scalar_test, &scalar_ctx, total_data_size);
    double avg_scalar_throughput = (double)total_data_size / avg_scalar_time / (1024 * 1024);
    
    printf("Average time: %.4f seconds\n", avg_scalar_time);
    printf("Average throughput: %.2f MB/s\n", avg_scalar_throughput);
    printf("Throughput per iteration: [");
    for(int i = 0; i < NUM_ITERATIONS; i++) 
        printf(i ? ", %.2f" : "%.2f", scalar_throughput[i]);
    printf("] MB/s\n");
    
    printf("\n=== AVX2 Batch Processing Benchmark ===\n");
    AVX2TestContext avx2_ctx = {data_streams, avx2_digests};
    double avg_avx2_time = run_test(avx2_throughput, avx2_test, &avx2_ctx, total_data_size);
    double avg_avx2_throughput = (double)total_data_size / avg_avx2_time / (1024 * 1024);
    
    printf("Average time: %.4f seconds\n", avg_avx2_time);
    printf("Average throughput: %.2f MB/s\n", avg_avx2_throughput);
    printf("Throughput per iteration: [");
    for(int i = 0; i < NUM_ITERATIONS; i++) 
        printf(i ? ", %.2f" : "%.2f", avx2_throughput[i]);
    printf("] MB/s\n");

    // Verification and comparison
    printf("\n=== Verification and Comparison ===\n");
    int errors = 0;
    for(int i = 0; i < NUM_STREAMS; i++) {
        if(memcmp(scalar_digests[i], avx2_digests[i], 16) != 0) {
            if(errors < 3) { // Limit error output
                printf("✗ Mismatch found for stream %d\n", i);
                printf("  Scalar: ");
                PrintMD5(scalar_digests[i]);
                printf("\n  AVX2:   ");
                PrintMD5(avx2_digests[i]);
                printf("\n");
            }
            errors++;
        }
    }
    
    if(errors == 0) {
        printf("✓ Verification successful! All %d digests match\n", NUM_STREAMS);
    } else {
        printf("✗ Verification failed! %d out of %d digests do not match\n", errors, NUM_STREAMS);
    }
    
    if (avg_avx2_time > 0) {
        printf("Speedup: %.2fx\n", avg_scalar_time / avg_avx2_time);
    }
    
    // Free resources
    for(int i = 0; i < NUM_STREAMS; i++) {
        free(data_streams[i]);
    }

    printf("\nBenchmark finished\n");
    return errors ? EXIT_FAILURE : EXIT_SUCCESS;
}
