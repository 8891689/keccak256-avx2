/* md5_avx2.c
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
 
#include "md5_avx2.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/param.h> // For MIN macro

// ============================================================================
// ==                                                                        ==
// ==                Basic version (SCALAR) implementation                   ==
// ==                                                                        ==
// ============================================================================

static const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t SHIFT[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

static inline uint32_t RotateLeft(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

void Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t M[16];
    uint32_t F, temp;

    // Convert the 64-byte block into 16 32-bit integers M
    for (int i = 0; i < 16; i++) {
        memcpy(&M[i], block + (i * sizeof(uint32_t)), sizeof(uint32_t));
    }

    // --- Round 1 (i = 0 to 15) ---
    // g = i
    // F = (b & c) | ((~b) & d)
    // Step 0
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[0] + T[0], SHIFT[0]); a = temp;
    // Step 1
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[1] + T[1], SHIFT[1]); a = temp;
    // Step 2
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[2] + T[2], SHIFT[2]); a = temp;
    // Step 3
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[3] + T[3], SHIFT[3]); a = temp;
    // Step 4
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[4] + T[4], SHIFT[4]); a = temp;
    // Step 5
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[5] + T[5], SHIFT[5]); a = temp;
    // Step 6
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[6] + T[6], SHIFT[6]); a = temp;
    // Step 7
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[7] + T[7], SHIFT[7]); a = temp;
    // Step 8
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[8] + T[8], SHIFT[8]); a = temp;
    // Step 9
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[9] + T[9], SHIFT[9]); a = temp;
    // Step 10
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[10] + T[10], SHIFT[10]); a = temp;
    // Step 11
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[11] + T[11], SHIFT[11]); a = temp;
    // Step 12
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[12] + T[12], SHIFT[12]); a = temp;
    // Step 13
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[13] + T[13], SHIFT[13]); a = temp;
    // Step 14
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[14] + T[14], SHIFT[14]); a = temp;
    // Step 15
    F = (b & c) | ((~b) & d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[15] + T[15], SHIFT[15]); a = temp;

    // --- Round 2 (i = 16 to 31) ---
    // g = (5*i + 1) % 16
    // F = (d & b) | ((~d) & c)
    // Step 16, g=1
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[1] + T[16], SHIFT[16]); a = temp;
    // Step 17, g=6
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[6] + T[17], SHIFT[17]); a = temp;
    // Step 18, g=11
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[11] + T[18], SHIFT[18]); a = temp;
    // Step 19, g=0
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[0] + T[19], SHIFT[19]); a = temp;
    // Step 20, g=5
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[5] + T[20], SHIFT[20]); a = temp;
    // Step 21, g=10
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[10] + T[21], SHIFT[21]); a = temp;
    // Step 22, g=15
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[15] + T[22], SHIFT[22]); a = temp;
    // Step 23, g=4
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[4] + T[23], SHIFT[23]); a = temp;
    // Step 24, g=9
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[9] + T[24], SHIFT[24]); a = temp;
    // Step 25, g=14
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[14] + T[25], SHIFT[25]); a = temp;
    // Step 26, g=3
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[3] + T[26], SHIFT[26]); a = temp;
    // Step 27, g=8
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[8] + T[27], SHIFT[27]); a = temp;
    // Step 28, g=13
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[13] + T[28], SHIFT[28]); a = temp;
    // Step 29, g=2
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[2] + T[29], SHIFT[29]); a = temp;
    // Step 30, g=7
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[7] + T[30], SHIFT[30]); a = temp;
    // Step 31, g=12
    F = (d & b) | ((~d) & c); temp = d; d = c; c = b; b += RotateLeft(a + F + M[12] + T[31], SHIFT[31]); a = temp;

    // --- Round 3 (i = 32 to 47) ---
    // g = (3*i + 5) % 16
    // F = b ^ c ^ d
    // Step 32, g=5
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[5] + T[32], SHIFT[32]); a = temp;
    // Step 33, g=8
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[8] + T[33], SHIFT[33]); a = temp;
    // Step 34, g=11
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[11] + T[34], SHIFT[34]); a = temp;
    // Step 35, g=14
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[14] + T[35], SHIFT[35]); a = temp;
    // Step 36, g=1
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[1] + T[36], SHIFT[36]); a = temp;
    // Step 37, g=4
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[4] + T[37], SHIFT[37]); a = temp;
    // Step 38, g=7
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[7] + T[38], SHIFT[38]); a = temp;
    // Step 39, g=10
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[10] + T[39], SHIFT[39]); a = temp;
    // Step 40, g=13
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[13] + T[40], SHIFT[40]); a = temp;
    // Step 41, g=0
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[0] + T[41], SHIFT[41]); a = temp;
    // Step 42, g=3
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[3] + T[42], SHIFT[42]); a = temp;
    // Step 43, g=6
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[6] + T[43], SHIFT[43]); a = temp;
    // Step 44, g=9
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[9] + T[44], SHIFT[44]); a = temp;
    // Step 45, g=12
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[12] + T[45], SHIFT[45]); a = temp;
    // Step 46, g=15
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[15] + T[46], SHIFT[46]); a = temp;
    // Step 47, g=2
    F = b ^ c ^ d; temp = d; d = c; c = b; b += RotateLeft(a + F + M[2] + T[47], SHIFT[47]); a = temp;

    // --- Round 4 (i = 48 to 63) ---
    // g = (7*i) % 16
    // F = c ^ (b | ~d)
    // Step 48, g=0
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[0] + T[48], SHIFT[48]); a = temp;
    // Step 49, g=7
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[7] + T[49], SHIFT[49]); a = temp;
    // Step 50, g=14
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[14] + T[50], SHIFT[50]); a = temp;
    // Step 51, g=5
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[5] + T[51], SHIFT[51]); a = temp;
    // Step 52, g=12
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[12] + T[52], SHIFT[52]); a = temp;
    // Step 53, g=3
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[3] + T[53], SHIFT[53]); a = temp;
    // Step 54, g=10
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[10] + T[54], SHIFT[54]); a = temp;
    // Step 55, g=1
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[1] + T[55], SHIFT[55]); a = temp;
    // Step 56, g=8
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[8] + T[56], SHIFT[56]); a = temp;
    // Step 57, g=15
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[15] + T[57], SHIFT[57]); a = temp;
    // Step 58, g=6
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[6] + T[58], SHIFT[58]); a = temp;
    // Step 59, g=13
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[13] + T[59], SHIFT[59]); a = temp;
    // Step 60, g=4
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[4] + T[60], SHIFT[60]); a = temp;
    // Step 61, g=11
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[11] + T[61], SHIFT[61]); a = temp;
    // Step 62, g=2
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[2] + T[62], SHIFT[62]); a = temp;
    // Step 63, g=9
    F = c ^ (b | ~d); temp = d; d = c; c = b; b += RotateLeft(a + F + M[9] + T[63], SHIFT[63]); a = temp;

    // Add the calculation result back to the state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5Init(MD5_CTX *ctx) {
    ctx->bit_count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void MD5Update(MD5_CTX *ctx, const uint8_t *input, size_t len) {
    size_t index = (size_t)((ctx->bit_count >> 3) & 0x3F);
    ctx->bit_count += (uint64_t)len << 3;
    
    size_t part_len = 64 - index;
    size_t i = 0;

    if (len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        Transform(ctx->state, ctx->buffer);
        
        for (i = part_len; i + 64 <= len; i += 64) {
            Transform(ctx->state, &input[i]);
        }
        index = 0;
    }
    
    if (i < len) {
        memcpy(&ctx->buffer[index], &input[i], len - i);
    }
}

void MD5Final(MD5_CTX *ctx, uint8_t digest[16]) {
    uint8_t bits[8];
    uint64_t bit_count = ctx->bit_count;
    
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)(bit_count >> (i * 8));
    }

    size_t index = (size_t)((ctx->bit_count >> 3) & 0x3F);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    
    uint8_t padding[128] = {0};
    padding[0] = 0x80;
    
    MD5Update(ctx, padding, pad_len);
    
    // MD5Update has already copied the first part of padding. 
    // Now we must form the final block with the length info.
    // The state inside MD5Update has processed all data up to the start of the length.
    // We update the buffer directly, then call Transform.
    memcpy(&ctx->buffer[56], bits, 8);
    Transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 4; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] & 0xFF);
        digest[i*4+1] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i*4+2] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4+3] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
    }
    
    memset(ctx, 0, sizeof(MD5_CTX));
}

void PrintMD5(const uint8_t hash[16]) {
    for (int i = 0; i < 16; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}


// ============================================================================
// ==                                                                        ==
// ==                   AVX2 batch implementation                            ==
// ==                                                                        ==
// ============================================================================

typedef union {
    uint32_t c[8];
    __m256i v;
} m256i_const_t;

#define TVEC_INIT(const_val) { {const_val, const_val, const_val, const_val, const_val, const_val, const_val, const_val} }

static const m256i_const_t TVec[64] __attribute__((aligned(32))) = {
    TVEC_INIT(0xd76aa478), TVEC_INIT(0xe8c7b756), TVEC_INIT(0x242070db), TVEC_INIT(0xc1bdceee),
    TVEC_INIT(0xf57c0faf), TVEC_INIT(0x4787c62a), TVEC_INIT(0xa8304613), TVEC_INIT(0xfd469501),
    TVEC_INIT(0x698098d8), TVEC_INIT(0x8b44f7af), TVEC_INIT(0xffff5bb1), TVEC_INIT(0x895cd7be),
    TVEC_INIT(0x6b901122), TVEC_INIT(0xfd987193), TVEC_INIT(0xa679438e), TVEC_INIT(0x49b40821),
    TVEC_INIT(0xf61e2562), TVEC_INIT(0xc040b340), TVEC_INIT(0x265e5a51), TVEC_INIT(0xe9b6c7aa),
    TVEC_INIT(0xd62f105d), TVEC_INIT(0x02441453), TVEC_INIT(0xd8a1e681), TVEC_INIT(0xe7d3fbc8),
    TVEC_INIT(0x21e1cde6), TVEC_INIT(0xc33707d6), TVEC_INIT(0xf4d50d87), TVEC_INIT(0x455a14ed),
    TVEC_INIT(0xa9e3e905), TVEC_INIT(0xfcefa3f8), TVEC_INIT(0x676f02d9), TVEC_INIT(0x8d2a4c8a),
    TVEC_INIT(0xfffa3942), TVEC_INIT(0x8771f681), TVEC_INIT(0x6d9d6122), TVEC_INIT(0xfde5380c),
    TVEC_INIT(0xa4beea44), TVEC_INIT(0x4bdecfa9), TVEC_INIT(0xf6bb4b60), TVEC_INIT(0xbebfbc70),
    TVEC_INIT(0x289b7ec6), TVEC_INIT(0xeaa127fa), TVEC_INIT(0xd4ef3085), TVEC_INIT(0x04881d05),
    TVEC_INIT(0xd9d4d039), TVEC_INIT(0xe6db99e5), TVEC_INIT(0x1fa27cf8), TVEC_INIT(0xc4ac5665),
    TVEC_INIT(0xf4292244), TVEC_INIT(0x432aff97), TVEC_INIT(0xab9423a7), TVEC_INIT(0xfc93a039),
    TVEC_INIT(0x655b59c3), TVEC_INIT(0x8f0ccc92), TVEC_INIT(0xffeff47d), TVEC_INIT(0x85845dd1),
    TVEC_INIT(0x6fa87e4f), TVEC_INIT(0xfe2ce6e0), TVEC_INIT(0xa3014314), TVEC_INIT(0x4e0811a1),
    TVEC_INIT(0xf7537e82), TVEC_INIT(0xbd3af235), TVEC_INIT(0x2ad7d2bb), TVEC_INIT(0xeb86d391)
};

#define ALL_ONES _mm256_set1_epi32(0xFFFFFFFF)
static inline __m256i RotateLeft_avx2(__m256i x, const int n) { return _mm256_or_si256(_mm256_slli_epi32(x,n),_mm256_srli_epi32(x,32-n));}
#define F(x,y,z) _mm256_or_si256(_mm256_and_si256(x,y),_mm256_andnot_si256(x,z))
#define G(x,y,z) _mm256_or_si256(_mm256_and_si256(x,z),_mm256_andnot_si256(z,y))
#define H(x,y,z) _mm256_xor_si256(x,_mm256_xor_si256(y,z))
#define I(x,y,z) _mm256_xor_si256(y,_mm256_or_si256(x, ALL_ONES ^ z))
#define STEP(f,a,b,c,d,M_val,k,s) a=_mm256_add_epi32(a,f(b,c,d));a=_mm256_add_epi32(a,M_val);a=_mm256_add_epi32(a,TVec[k].v);a=RotateLeft_avx2(a,s);a=_mm256_add_epi32(a,b);



static void Transform_avx2(__m256i state[4], const uint8_t blocks[MD5_AVX2_LANES][64]) {
    __m256i a = state[0], b = state[1], c = state[2], d = state[3];
    __m256i M[16] __attribute__((aligned(32)));

    for (int i = 0; i < 16; ++i) {
        M[i] = _mm256_set_epi32(
            *(const uint32_t*)&blocks[7][i*4],
            *(const uint32_t*)&blocks[6][i*4],
            *(const uint32_t*)&blocks[5][i*4],
            *(const uint32_t*)&blocks[4][i*4],
            *(const uint32_t*)&blocks[3][i*4],
            *(const uint32_t*)&blocks[2][i*4],
            *(const uint32_t*)&blocks[1][i*4],
            *(const uint32_t*)&blocks[0][i*4]
        );
    }

    
    #define AVX_STEP(f,a,b,c,d,M_val,k,s) \
        a = _mm256_add_epi32(a, f(b,c,d)); \
        a = _mm256_add_epi32(a, M_val); \
        a = _mm256_add_epi32(a, TVec[k].v); \
        a = RotateLeft_avx2(a,s); \
        a = _mm256_add_epi32(a,b)
    
    // Round 1
    AVX_STEP(F,a,b,c,d,M[0], 0, 7); AVX_STEP(F,d,a,b,c,M[1], 1,12); 
    AVX_STEP(F,c,d,a,b,M[2], 2,17); AVX_STEP(F,b,c,d,a,M[3], 3,22);
    
    AVX_STEP(F,a,b,c,d,M[4], 4, 7); AVX_STEP(F,d,a,b,c,M[5], 5,12); 
    AVX_STEP(F,c,d,a,b,M[6], 6,17); AVX_STEP(F,b,c,d,a,M[7], 7,22);
    
    AVX_STEP(F,a,b,c,d,M[8], 8, 7); AVX_STEP(F,d,a,b,c,M[9], 9,12); 
    AVX_STEP(F,c,d,a,b,M[10],10,17); AVX_STEP(F,b,c,d,a,M[11],11,22);
    
    AVX_STEP(F,a,b,c,d,M[12],12, 7); AVX_STEP(F,d,a,b,c,M[13],13,12); 
    AVX_STEP(F,c,d,a,b,M[14],14,17); AVX_STEP(F,b,c,d,a,M[15],15,22);
    
    // Round 2
    AVX_STEP(G,a,b,c,d,M[1], 16, 5); AVX_STEP(G,d,a,b,c,M[6], 17, 9); 
    AVX_STEP(G,c,d,a,b,M[11],18,14); AVX_STEP(G,b,c,d,a,M[0], 19,20);
    
    AVX_STEP(G,a,b,c,d,M[5], 20, 5); AVX_STEP(G,d,a,b,c,M[10],21, 9); 
    AVX_STEP(G,c,d,a,b,M[15],22,14); AVX_STEP(G,b,c,d,a,M[4], 23,20);
    
    AVX_STEP(G,a,b,c,d,M[9], 24, 5); AVX_STEP(G,d,a,b,c,M[14],25, 9); 
    AVX_STEP(G,c,d,a,b,M[3], 26,14); AVX_STEP(G,b,c,d,a,M[8], 27,20);
    
    AVX_STEP(G,a,b,c,d,M[13],28, 5); AVX_STEP(G,d,a,b,c,M[2], 29, 9); 
    AVX_STEP(G,c,d,a,b,M[7], 30,14); AVX_STEP(G,b,c,d,a,M[12],31,20);
    
    // Round 3
    AVX_STEP(H,a,b,c,d,M[5], 32, 4); AVX_STEP(H,d,a,b,c,M[8], 33,11); 
    AVX_STEP(H,c,d,a,b,M[11],34,16); AVX_STEP(H,b,c,d,a,M[14],35,23);
    
    AVX_STEP(H,a,b,c,d,M[1], 36, 4); AVX_STEP(H,d,a,b,c,M[4], 37,11); 
    AVX_STEP(H,c,d,a,b,M[7], 38,16); AVX_STEP(H,b,c,d,a,M[10],39,23);
    
    AVX_STEP(H,a,b,c,d,M[13],40, 4); AVX_STEP(H,d,a,b,c,M[0], 41,11); 
    AVX_STEP(H,c,d,a,b,M[3], 42,16); AVX_STEP(H,b,c,d,a,M[6], 43,23);
    
    AVX_STEP(H,a,b,c,d,M[9],44, 4); AVX_STEP(H,d,a,b,c,M[12],45,11); 
    AVX_STEP(H,c,d,a,b,M[15],46,16); AVX_STEP(H,b,c,d,a,M[2], 47,23);
    
    // Round 4
    AVX_STEP(I,a,b,c,d,M[0], 48, 6); AVX_STEP(I,d,a,b,c,M[7], 49,10); 
    AVX_STEP(I,c,d,a,b,M[14],50,15); AVX_STEP(I,b,c,d,a,M[5], 51,21);
    
    AVX_STEP(I,a,b,c,d,M[12],52, 6); AVX_STEP(I,d,a,b,c,M[3], 53,10); 
    AVX_STEP(I,c,d,a,b,M[10],54,15); AVX_STEP(I,b,c,d,a,M[1], 55,21);
    
    AVX_STEP(I,a,b,c,d,M[8], 56, 6); AVX_STEP(I,d,a,b,c,M[15],57,10); 
    AVX_STEP(I,c,d,a,b,M[6], 58,15); AVX_STEP(I,b,c,d,a,M[13],59,21);
    
    AVX_STEP(I,a,b,c,d,M[4], 60, 6); AVX_STEP(I,d,a,b,c,M[11],61,10); 
    AVX_STEP(I,c,d,a,b,M[2], 62,15); AVX_STEP(I,b,c,d,a,M[9], 63,21);
    
    #undef AVX_STEP 

    state[0] = _mm256_add_epi32(state[0], a);
    state[1] = _mm256_add_epi32(state[1], b);
    state[2] = _mm256_add_epi32(state[2], c);
    state[3] = _mm256_add_epi32(state[3], d);
}


void MD5BatchInit(MD5_CTX_AVX2 *ctx) {
    ctx->state[0] = _mm256_set1_epi32(0x67452301);
    ctx->state[1] = _mm256_set1_epi32(0xefcdab89);
    ctx->state[2] = _mm256_set1_epi32(0x98badcfe);
    ctx->state[3] = _mm256_set1_epi32(0x10325476);
    ctx->active_mask = 0;
    for (int i = 0; i < MD5_AVX2_LANES; ++i) {
        ctx->bit_count[i] = 0;
        ctx->buffer_len[i] = 0;
    }
}

void MD5BatchUpdate(MD5_CTX_AVX2 *ctx, const uint8_t *data[], const size_t lens[]) {
    size_t data_pos[MD5_AVX2_LANES] = {0};
    uint8_t current_batch[MD5_AVX2_LANES][64] __attribute__((aligned(32)));

    for (int i = 0; i < MD5_AVX2_LANES; ++i) {
        if (lens[i] > 0) {
            ctx->active_mask |= (1 << i);
            ctx->bit_count[i] += (uint64_t)lens[i] << 3;
        }
    }

    while (1) {
        int can_form_batch = 0;
        for (int i = 0; i < MD5_AVX2_LANES; ++i) {
            if (!((ctx->active_mask >> i) & 1)) continue;
            
            size_t total_len = ctx->buffer_len[i] + (lens[i] - data_pos[i]);
            if (total_len >= 64) {
                can_form_batch = 1;
                break;
            }
        }
        if (!can_form_batch) break;

        uint8_t transform_mask = 0;
        for (int i = 0; i < MD5_AVX2_LANES; ++i) {
            if (((ctx->active_mask >> i) & 1) && (ctx->buffer_len[i] + (lens[i] - data_pos[i]) >= 64)) {
                transform_mask |= (1 << i);
                
                size_t buffer_part = ctx->buffer_len[i];
                size_t data_part = 64 - buffer_part;
                
                memcpy(current_batch[i], ctx->buffer[i], buffer_part);
                memcpy(current_batch[i] + buffer_part, data[i] + data_pos[i], data_part);
                
                data_pos[i] += data_part;
                ctx->buffer_len[i] = 0;
            } else {
                 memset(current_batch[i], 0, 64);
            }
        }

        __m256i old_state[4];
        if (transform_mask != 0xFF) {
            for(int i=0; i<4; ++i) old_state[i] = ctx->state[i];
        }

        Transform_avx2(ctx->state, (const uint8_t(*)[64])current_batch);

        if (transform_mask != 0xFF) {
             __m256i mask = _mm256_cmpeq_epi32(
                 _mm256_set_epi32(
                     (transform_mask >> 7) & 1 ? -1 : 0, (transform_mask >> 6) & 1 ? -1 : 0,
                     (transform_mask >> 5) & 1 ? -1 : 0, (transform_mask >> 4) & 1 ? -1 : 0,
                     (transform_mask >> 3) & 1 ? -1 : 0, (transform_mask >> 2) & 1 ? -1 : 0,
                     (transform_mask >> 1) & 1 ? -1 : 0, (transform_mask >> 0) & 1 ? -1 : 0
                 ),
                 _mm256_set1_epi32(-1)
             );
            for(int i=0; i<4; ++i) {
                ctx->state[i] = _mm256_blendv_epi8(old_state[i], ctx->state[i], mask);
            }
        }
    }

    for (int i = 0; i < MD5_AVX2_LANES; ++i) {
        if (!((ctx->active_mask >> i) & 1)) continue;
        size_t remaining = lens[i] - data_pos[i];
        if (remaining > 0) {
            memcpy(ctx->buffer[i] + ctx->buffer_len[i], data[i] + data_pos[i], remaining);
            ctx->buffer_len[i] += remaining;
        }
    }
}

void MD5BatchFinal(MD5_CTX_AVX2 *ctx, uint8_t digests[MD5_AVX2_LANES][16]) {
    uint32_t scalar_states[MD5_AVX2_LANES][4];
    for (int i = 0; i < 4; ++i) {
        uint32_t t[8] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i*)t, ctx->state[i]);
        for (int j = 0; j < MD5_AVX2_LANES; ++j) {
            scalar_states[j][i] = t[j];
        }
    }

    for (int i = 0; i < MD5_AVX2_LANES; ++i) {
        if (!((ctx->active_mask >> i) & 1)) {
            memset(digests[i], 0, 16);
            continue;
        }
        MD5_CTX s_ctx;
        MD5Init(&s_ctx);
        memcpy(s_ctx.state, scalar_states[i], 16);
        
        s_ctx.bit_count = ctx->bit_count[i] - (ctx->buffer_len[i] << 3);
        
        MD5Update(&s_ctx, ctx->buffer[i], ctx->buffer_len[i]);
        
        MD5Final(&s_ctx, digests[i]);
    }
}
