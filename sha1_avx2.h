/* sha1_avx2.h
 * Copyright [2024] [8891689]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * https://github.com/8891689
 */
 
#ifndef SHA1_AVX2_H
#define SHA1_AVX2_H

#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h> 

#ifdef __cplusplus
extern "C" {
#endif

// --- Scalar Version Interface ---

typedef struct {
    uint32_t state[5];
    uint64_t bit_count;
    uint8_t buffer[64];
} SHA1_CTX;

void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const uint8_t *input, size_t len);
void SHA1_Final(SHA1_CTX *ctx, uint8_t digest[20]);
void PrintSHA1(const uint8_t hash[20]);


// --- AVX2 Batch Version Interface ---

#define SHA1_AVX2_LANES 8

typedef struct {
    __m256i state[5]; // SHA-1 uses 5 state variables
    uint64_t bit_count[SHA1_AVX2_LANES];
    uint8_t buffer[SHA1_AVX2_LANES][64];
    size_t buffer_len[SHA1_AVX2_LANES];
    uint8_t active_mask;
} SHA1_CTX_AVX2;

void SHA1BatchInit(SHA1_CTX_AVX2 *ctx);
void SHA1BatchUpdate(SHA1_CTX_AVX2 *ctx, const uint8_t *data[], const size_t lens[]);
void SHA1BatchFinal(SHA1_CTX_AVX2 *ctx, uint8_t digests[SHA1_AVX2_LANES][20]);

/**
 * @brief A specialized function to compute SHA-1 for a batch of short messages (< 56 bytes) in one shot.
 *        This function is highly optimized for high-throughput, small-message hashing.
 * @param data      Array of pointers to the input messages.
 * @param lens      Array of lengths for each message. All lengths must be < 56.
 * @param digests   A 2D array to store the resulting 20-byte SHA-1 digests.
 */
void SHA1BatchOneShot(const uint8_t *data[SHA1_AVX2_LANES], const size_t lens[SHA1_AVX2_LANES], uint8_t digests[SHA1_AVX2_LANES][20]);

#ifdef __cplusplus
}
#endif

#endif // SHA1_AVX2_H
