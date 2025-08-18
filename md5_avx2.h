/* md5_avx2.h
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
#ifndef MD5_AVX2_H
#define MD5_AVX2_H

#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h> 

#ifdef __cplusplus
extern "C" {
#endif

// --- Scalar Version Interface ---

typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    uint8_t buffer[64];
} MD5_CTX;

/**
 * @brief Initialize MD5 context
 * @param ctx Pointer to MD5_CTX structure
 */
void MD5Init(MD5_CTX *ctx);

/**
 * @brief Update MD5 calculation (process data block)
 * @param ctx Pointer to MD5_CTX structure
 * @param input Pointer to input data
 * @param input_len Input data length
 */
void MD5Update(MD5_CTX *ctx, const uint8_t *input, size_t input_len);

/**
 * @brief Completes the MD5 calculation and outputs the digest.
 * @param ctx Pointer to the MD5_CTX structure.
 * @param digest Array storing the 16-byte MD5 digest.
 */
void MD5Final(MD5_CTX *ctx, uint8_t digest[16]);

/**
 * @brief Print MD5 digest (helper function)
 * @param hash 16-byte MD5 digest
 */
void PrintMD5(const uint8_t hash[16]);


// --- AVX2 Batch Version Interface ---

#define MD5_AVX2_LANES 8

typedef struct {
    __m256i state[4];
    uint64_t bit_count[MD5_AVX2_LANES];
    uint8_t buffer[MD5_AVX2_LANES][64];
    size_t buffer_len[MD5_AVX2_LANES];
    uint8_t active_mask;
} MD5_CTX_AVX2;

/**
 * @brief Initialize AVX2 batched MD5 context
 * @param ctx Pointer to MD5_CTX_AVX2 structure
 */
void MD5BatchInit(MD5_CTX_AVX2 *ctx);

/**
 * @brief Update MD5 calculations for multiple data streams in parallel using AVX2
 * @param ctx Pointer to an MD5_CTX_AVX2 structure
 * @param data Pointer to an array of data stream pointers
 * @param lens Array of the length of each data stream
 */
void MD5BatchUpdate(MD5_CTX_AVX2 *ctx, const uint8_t *data[], const size_t lens[]);

/**
 * @brief Completes MD5 calculations for all data streams and outputs digests
 * @param ctx Pointer to an MD5_CTX_AVX2 structure
 * @param digests A two-dimensional array storing multiple 16-byte MD5 digests
 */
void MD5BatchFinal(MD5_CTX_AVX2 *ctx, uint8_t digests[MD5_AVX2_LANES][16]);

#ifdef __cplusplus
}
#endif

#endif // MD5_AVX2_H
