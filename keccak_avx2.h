/* Apache License, Version 2.0
   Copyright [2025] [8891689]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   Author: 8891689 (https://github.com/8891689)
*/
#ifndef KECCAK_AVX2_H
#define KECCAK_AVX2_H

#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>

// Ensure memory is 32-byte aligned
#ifdef _MSC_VER
#define ALIGN32 __declspec(align(32))
#else
#define ALIGN32 __attribute__((aligned(32)))
#endif

// Output length definition (bytes)
#define KECCAK_224_DIGEST_LENGTH 28
#define KECCAK_256_DIGEST_LENGTH 32
#define KECCAK_384_DIGEST_LENGTH 48
#define KECCAK_512_DIGEST_LENGTH 64

//Number of parallel channels
#define NUM_LANES 8

// Single-threaded KECCAK context
typedef struct {
    uint64_t state[25];
    unsigned int rate;          // Absorption rate (bytes)
    unsigned int output_length; // Output summary length (bytes)
    unsigned char buffer[200];  // Input buffer
    unsigned int pos;           // Current position in the buffer
} keccak_ctx;

// Keccak-f[1600] permutation round constant (24 rounds)
extern const uint64_t keccakf_rc[24];
extern const int keccakf_rotc[24];
extern const int keccakf_piln[24];

#ifdef __cplusplus
extern "C" {
#endif

// Basic KECCAK function declaration
void keccak_224(const unsigned char *input, size_t inlen, unsigned char *output);
void keccak_256(const unsigned char *input, size_t inlen, unsigned char *output);
void keccak_384(const unsigned char *input, size_t inlen, unsigned char *output);
void keccak_512(const unsigned char *input, size_t inlen, unsigned char *output);

// AVX2 8-lane parallel functions
void keccak_8x_224(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs);
void keccak_8x_256(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs);
void keccak_8x_384(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs);
void keccak_8x_512(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs);


// Memory allocation functions
void* aligned_malloc(size_t size, size_t alignment);
void aligned_free(void* p);

#ifdef __cplusplus
}
#endif

#endif // KECCAK_AVX2_H
