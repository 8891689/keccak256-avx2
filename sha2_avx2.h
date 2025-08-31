/* sha2_avx2.h */
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

#ifndef SHA2_AVX2_H
#define SHA2_AVX2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 *                             基礎 C 語言接口                            *
 ******************************************************************************/
#define SHA224_BLOCK_SIZE 28
#define SHA256_BLOCK_SIZE 32
#define SHA384_BLOCK_SIZE 48
#define SHA512_BLOCK_SIZE 64
typedef struct { uint8_t data[64]; uint32_t datalen; uint64_t bitlen; uint32_t state[8]; } SHA256_CTX;
typedef SHA256_CTX SHA224_CTX;
typedef struct { uint8_t data[128]; uint32_t datalen; uint64_t bitlen[2]; uint64_t state[8]; } SHA512_CTX;
typedef SHA512_CTX SHA384_CTX;

void sha224_init(SHA224_CTX *ctx); 
void sha224_update(SHA224_CTX *ctx, const uint8_t data[], size_t len); 
void sha224_final(SHA224_CTX *ctx, uint8_t hash[]); void sha224(const uint8_t *data, size_t len, uint8_t *hash);

void sha256_init(SHA256_CTX *ctx); 
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len); 
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]); void sha256(const uint8_t *data, size_t len, uint8_t *hash);

void sha384_init(SHA384_CTX *ctx); 
void sha384_update(SHA384_CTX *ctx, const uint8_t data[], size_t len); 
void sha384_final(SHA384_CTX *ctx, uint8_t hash[]); void sha384(const uint8_t *data, size_t len, uint8_t *hash);

void sha512_init(SHA512_CTX *ctx); 
void sha512_update(SHA512_CTX *ctx, const uint8_t data[], size_t len); 
void sha512_final(SHA512_CTX *ctx, uint8_t hash[]); void sha512(const uint8_t *data, size_t len, uint8_t *hash);

/******************************************************************************
 *                             AVX2 接口                              *
 ******************************************************************************/
#if defined(__AVX2__)

// Opaque pointer for context. The actual definition is hidden in the .c file.
struct SHA2_x8_CTX;
typedef struct SHA2_x8_CTX SHA2_x8_CTX;

// --- SHA-224 (8-way parallel) ---
SHA2_x8_CTX* sha224_x8_create();
void sha224_x8_destroy(SHA2_x8_CTX* handle);
void sha224_x8_init(SHA2_x8_CTX* handle);
void sha224_x8_update(SHA2_x8_CTX* handle, const uint8_t input_blocks[8][64]);
void sha224_x8_final(SHA2_x8_CTX* handle, uint8_t hashes_out[8][32]);

// --- SHA-256 (8-way parallel) ---
SHA2_x8_CTX* sha256_x8_create();
void sha256_x8_destroy(SHA2_x8_CTX* handle);
void sha256_x8_init(SHA2_x8_CTX* handle);
void sha256_x8_update(SHA2_x8_CTX* handle, const uint8_t input_blocks[8][64]);
void sha256_x8_final(SHA2_x8_CTX* handle, uint8_t hashes_out[8][32]);

// --- SHA-384 (8-way parallel wrapper) ---
SHA2_x8_CTX* sha384_x8_create();
void sha384_x8_destroy(SHA2_x8_CTX* handle);
void sha384_x8_init(SHA2_x8_CTX* handle);
void sha384_x8_update(SHA2_x8_CTX* handle, const uint8_t input_blocks[8][128]);
void sha384_x8_final(SHA2_x8_CTX* handle, uint8_t hashes_out[8][64]);

// --- SHA-512 (8-way parallel wrapper) ---
SHA2_x8_CTX* sha512_x8_create();
void sha512_x8_destroy(SHA2_x8_CTX* handle);
void sha512_x8_init(SHA2_x8_CTX* handle);
void sha512_x8_update(SHA2_x8_CTX* handle, const uint8_t input_blocks[8][128]);
void sha512_x8_final(SHA2_x8_CTX* handle, uint8_t hashes_out[8][64]);

#endif // __AVX2__

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SHA2_AVX2_H
