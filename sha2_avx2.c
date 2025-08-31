/* sha2_AVX2.c */
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
/* sha2_avx2.c - FINAL AND COMPLETE CORRECTED FILE */
#include "sha2_avx2.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32) || defined(_WIN64)
    // For Windows, use _aligned_malloc
    #include <malloc.h>
    #define platform_aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
    #define platform_aligned_free(ptr) _aligned_free(ptr)
#else
    // For POSIX compliant systems (like Linux), use aligned_alloc
    #define platform_aligned_alloc(alignment, size) aligned_alloc(alignment, size)
    #define platform_aligned_free(ptr) free(ptr)
#endif

#ifndef __builtin_bswap64
#define __builtin_bswap64(x) (((x) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | ((x) << 56))
#endif

/******************************************************************************
 *                             基礎 C 語言實現                   *
 ******************************************************************************/

/*************************** SHA-256/224 CORE ***************************/

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)     (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)    (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) | ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    }
    for ( ; i < 64; ++i) {
        m[i] = m[i-16] + SIG0(m[i-15]) + m[i-7] + SIG1(m[i-2]);
    }
    
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    
    #define R(I) t1 = h + EP1(e) + CH(e,f,g) + k256[I] + m[I]; t2 = EP0(a) + MAJ(a,b,c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    R( 0) R( 1) R( 2) R( 3) R( 4) R( 5) R( 6) R( 7)
    R( 8) R( 9) R(10) R(11) R(12) R(13) R(14) R(15)
    R(16) R(17) R(18) R(19) R(20) R(21) R(22) R(23)
    R(24) R(25) R(26) R(27) R(28) R(29) R(30) R(31)
    R(32) R(33) R(34) R(35) R(36) R(37) R(38) R(39)
    R(40) R(41) R(42) R(43) R(44) R(45) R(46) R(47)
    R(48) R(49) R(50) R(51) R(52) R(53) R(54) R(55)
    R(56) R(57) R(58) R(59) R(60) R(61) R(62) R(63)
    #undef R

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}
void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i;

    uint64_t total_bitlen = ctx->bitlen + ((uint64_t)ctx->datalen * 8);

    ctx->data[ctx->datalen] = 0x80;
    ctx->datalen++;

    if (ctx->datalen > 56) {
        memset(ctx->data + ctx->datalen, 0, 64 - ctx->datalen);
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    } else {
        memset(ctx->data + ctx->datalen, 0, 56 - ctx->datalen);
    }

    ctx->data[56] = (uint8_t)(total_bitlen >> 56);
    ctx->data[57] = (uint8_t)(total_bitlen >> 48);
    ctx->data[58] = (uint8_t)(total_bitlen >> 40);
    ctx->data[59] = (uint8_t)(total_bitlen >> 32);
    ctx->data[60] = (uint8_t)(total_bitlen >> 24);
    ctx->data[61] = (uint8_t)(total_bitlen >> 16);
    ctx->data[62] = (uint8_t)(total_bitlen >> 8);
    ctx->data[63] = (uint8_t)(total_bitlen);

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        hash[i * 4 + 0] = (ctx->state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (ctx->state[i] >> 8)  & 0xff;
        hash[i * 4 + 3] = (ctx->state[i] >> 0)  & 0xff;
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA256_CTX ctx; sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, hash);
}

void sha224_init(SHA224_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0xc1059ed8; ctx->state[1] = 0x367cd507; ctx->state[2] = 0x3070dd17; ctx->state[3] = 0xf70e5939;
    ctx->state[4] = 0xffc00b31; ctx->state[5] = 0x68581511; ctx->state[6] = 0x64f98fa7; ctx->state[7] = 0xbefa4fa4;
}
void sha224_update(SHA224_CTX *ctx, const uint8_t data[], size_t len) { sha256_update(ctx, data, len); }
void sha224_final(SHA224_CTX *ctx, uint8_t hash[]) {
    uint8_t full_hash[SHA256_BLOCK_SIZE];
    sha256_final(ctx, full_hash);
    memcpy(hash, full_hash, SHA224_BLOCK_SIZE);
}
void sha224(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA224_CTX ctx; sha224_init(&ctx); sha224_update(&ctx, data, len); sha224_final(&ctx, hash);
}

/*************************** SHA-512/384 CORE ***************************/
#define ROTRIGHT64(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define CH64(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x) (ROTRIGHT64(x,28) ^ ROTRIGHT64(x,34) ^ ROTRIGHT64(x,39))
#define EP1_64(x) (ROTRIGHT64(x,14) ^ ROTRIGHT64(x,18) ^ ROTRIGHT64(x,41))
#define SIG0_64(x) (ROTRIGHT64(x,1) ^ ROTRIGHT64(x,8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTRIGHT64(x,19) ^ ROTRIGHT64(x,61) ^ ((x) >> 6))

static const uint64_t k512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void sha512_transform(SHA512_CTX *ctx, const uint8_t data[]) {
    uint64_t m[80], a, b, c, d, e, f, g, h, t1, t2;
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 8) {
        m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j+1] << 48) | ((uint64_t)data[j+2] << 40) | ((uint64_t)data[j+3] << 32) |
               ((uint64_t)data[j+4] << 24) | ((uint64_t)data[j+5] << 16) | ((uint64_t)data[j+6] << 8) | ((uint64_t)data[j+7]);
    }
    for ( ; i < 80; ++i) m[i] = SIG1_64(m[i-2]) + m[i-7] + SIG0_64(m[i-15]) + m[i-16];
    
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    
    #define R(I) t1 = h + EP1_64(e) + CH64(e,f,g) + k512[I] + m[I]; t2 = EP0_64(a) + MAJ64(a,b,c); h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    R( 0) R( 1) R( 2) R( 3) R( 4) R( 5) R( 6) R( 7)
    R( 8) R( 9) R(10) R(11) R(12) R(13) R(14) R(15)
    R(16) R(17) R(18) R(19) R(20) R(21) R(22) R(23)
    R(24) R(25) R(26) R(27) R(28) R(29) R(30) R(31)
    R(32) R(33) R(34) R(35) R(36) R(37) R(38) R(39)
    R(40) R(41) R(42) R(43) R(44) R(45) R(46) R(47)
    R(48) R(49) R(50) R(51) R(52) R(53) R(54) R(55)
    R(56) R(57) R(58) R(59) R(60) R(61) R(62) R(63)
    R(64) R(65) R(66) R(67) R(68) R(69) R(70) R(71)
    R(72) R(73) R(74) R(75) R(76) R(77) R(78) R(79)
    #undef R
    
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha512_init(SHA512_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen[0] = 0; ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667f3bcc908; ctx->state[1] = 0xbb67ae8584caa73b; ctx->state[2] = 0x3c6ef372fe94f82b; ctx->state[3] = 0xa54ff53a5f1d36f1;
    ctx->state[4] = 0x510e527fade682d1; ctx->state[5] = 0x9b05688c2b3e6c1f; ctx->state[6] = 0x1f83d9abfb41bd6b; ctx->state[7] = 0x5be0cd19137e2179;
}

void sha512_update(SHA512_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 128) {
            sha512_transform(ctx, ctx->data);
            uint64_t low = ctx->bitlen[0];
            ctx->bitlen[0] += 1024;
            if (ctx->bitlen[0] < low) ctx->bitlen[1]++;
            ctx->datalen = 0;
        }
    }
}

void sha512_final(SHA512_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    uint64_t low_orig = ctx->bitlen[0];
    ctx->bitlen[0] += (uint64_t)ctx->datalen * 8;
    if (ctx->bitlen[0] < low_orig) {
        ctx->bitlen[1]++;
    }
    ctx->data[i++] = 0x80;
    if (i > 112) {
        while (i < 128) ctx->data[i++] = 0x00;
        sha512_transform(ctx, ctx->data);
        memset(ctx->data, 0, 112);
    } else {
        while (i < 112) ctx->data[i++] = 0x00;
    }
    uint64_t be_high = __builtin_bswap64(ctx->bitlen[1]);
    uint64_t be_low = __builtin_bswap64(ctx->bitlen[0]);
    memcpy(&ctx->data[112], &be_high, 8);
    memcpy(&ctx->data[120], &be_low, 8);
    sha512_transform(ctx, ctx->data);
    for (i = 0; i < 8; ++i) {
        hash[i*8+0] = (ctx->state[i] >> 56) & 0xff; hash[i*8+1] = (ctx->state[i] >> 48) & 0xff;
        hash[i*8+2] = (ctx->state[i] >> 40) & 0xff; hash[i*8+3] = (ctx->state[i] >> 32) & 0xff;
        hash[i*8+4] = (ctx->state[i] >> 24) & 0xff; hash[i*8+5] = (ctx->state[i] >> 16) & 0xff;
        hash[i*8+6] = (ctx->state[i] >> 8)  & 0xff;  hash[i*8+7] = (ctx->state[i] >> 0) & 0xff;
    }
}

void sha512(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA512_CTX ctx; sha512_init(&ctx); sha512_update(&ctx, data, len); sha512_final(&ctx, hash);
}

void sha384_init(SHA384_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen[0] = 0; ctx->bitlen[1] = 0;
    ctx->state[0] = 0xcbbb9d5dc1059ed8; ctx->state[1] = 0x629a292a367cd507; ctx->state[2] = 0x9159015a3070dd17; ctx->state[3] = 0x152fecd8f70e5939;
    ctx->state[4] = 0x67332667ffc00b31; ctx->state[5] = 0x8eb44a8768581511; ctx->state[6] = 0xdb0c2e0d64f98fa7; ctx->state[7] = 0x47b5481dbefa4fa4;
}
void sha384_update(SHA384_CTX *ctx, const uint8_t data[], size_t len) { sha512_update(ctx, data, len); }
void sha384_final(SHA384_CTX *ctx, uint8_t hash[]) {
    uint8_t full_hash[SHA512_BLOCK_SIZE];
    sha512_final(ctx, full_hash);
    memcpy(hash, full_hash, SHA384_BLOCK_SIZE);
}
void sha384(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA384_CTX ctx; sha384_init(&ctx); sha384_update(&ctx, data, len); sha384_final(&ctx, hash);
}

/******************************************************************************
 *                             AVX2                               *
 ******************************************************************************/
#if defined(__AVX2__)

#include <immintrin.h>
#include <stdalign.h>

#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <strings.h>
#else
static inline void explicit_bzero(void *s, size_t n) { volatile unsigned char *p = s; while (n--) *p++ = 0; }
#endif

/*
 * ============================================================================
 *                         SHA-256 / SHA-224 (8-way AVX2)
 * ============================================================================
 */

// 內部結構定義
struct SHA256_x8_CTX_INTERNAL {
    alignas(64) __m256i state[8];
};

// --- 宏定義 ---
#define BSWAP_MASK_AVX _mm256_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203)
#define CH_AVX(x, y, z)  _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define MAJ_AVX(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_xor_si256(_mm256_and_si256(x, z), _mm256_and_si256(y, z)))
#define ROR_AVX(x, n) _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n))
#define SIGMA0_AVX(x) (_mm256_xor_si256(ROR_AVX(x, 2),  _mm256_xor_si256(ROR_AVX(x, 13), ROR_AVX(x, 22))))
#define SIGMA1_AVX(x) (_mm256_xor_si256(ROR_AVX(x, 6),  _mm256_xor_si256(ROR_AVX(x, 11), ROR_AVX(x, 25))))
#define sigma0_AVX(x) (_mm256_xor_si256(ROR_AVX(x, 7),  _mm256_xor_si256(ROR_AVX(x, 18), _mm256_srli_epi32(x, 3))))
#define sigma1_AVX(x) (_mm256_xor_si256(ROR_AVX(x, 17), _mm256_xor_si256(ROR_AVX(x, 19), _mm256_srli_epi32(x, 10))))

static inline void transpose8x8_epi32(__m256i *rows) {
    __m256i temp[8];
    temp[0] = _mm256_unpacklo_epi32(rows[0], rows[1]); temp[1] = _mm256_unpackhi_epi32(rows[0], rows[1]);
    temp[2] = _mm256_unpacklo_epi32(rows[2], rows[3]); temp[3] = _mm256_unpackhi_epi32(rows[2], rows[3]);
    temp[4] = _mm256_unpacklo_epi32(rows[4], rows[5]); temp[5] = _mm256_unpackhi_epi32(rows[4], rows[5]);
    temp[6] = _mm256_unpacklo_epi32(rows[6], rows[7]); temp[7] = _mm256_unpackhi_epi32(rows[6], rows[7]);
    rows[0] = _mm256_unpacklo_epi64(temp[0], temp[2]); rows[1] = _mm256_unpackhi_epi64(temp[0], temp[2]);
    rows[2] = _mm256_unpacklo_epi64(temp[1], temp[3]); rows[3] = _mm256_unpackhi_epi64(temp[1], temp[3]);
    rows[4] = _mm256_unpacklo_epi64(temp[4], temp[6]); rows[5] = _mm256_unpackhi_epi64(temp[4], temp[6]);
    rows[6] = _mm256_unpacklo_epi64(temp[5], temp[7]); rows[7] = _mm256_unpackhi_epi64(temp[5], temp[7]);
    temp[0] = _mm256_permute2x128_si256(rows[0], rows[4], 0x20); temp[1] = _mm256_permute2x128_si256(rows[1], rows[5], 0x20);
    temp[2] = _mm256_permute2x128_si256(rows[2], rows[6], 0x20); temp[3] = _mm256_permute2x128_si256(rows[3], rows[7], 0x20);
    temp[4] = _mm256_permute2x128_si256(rows[0], rows[4], 0x31); temp[5] = _mm256_permute2x128_si256(rows[1], rows[5], 0x31);
    temp[6] = _mm256_permute2x128_si256(rows[2], rows[6], 0x31); temp[7] = _mm256_permute2x128_si256(rows[3], rows[7], 0x31);
    memcpy(rows, temp, sizeof(temp));
}

static void sha256_x8_transform(struct SHA256_x8_CTX_INTERNAL *ctx, const uint8_t input_data_8blocks[8][64]) {
    alignas(64) __m256i W[64];
    const __m256i bswap_mask = BSWAP_MASK_AVX;
    
    __m256i block_data[8];
    for (int i = 0; i < 8; i++) {

        block_data[i] = _mm256_load_si256((const __m256i*)input_data_8blocks[i]);
        block_data[i] = _mm256_shuffle_epi8(block_data[i], bswap_mask);
    }
    transpose8x8_epi32(block_data);
    for (int i = 0; i < 8; i++) W[i] = block_data[i];
    
    for (int i = 0; i < 8; i++) {
        block_data[i] = _mm256_load_si256((const __m256i*)(input_data_8blocks[i] + 32));
        block_data[i] = _mm256_shuffle_epi8(block_data[i], bswap_mask);
    }
    transpose8x8_epi32(block_data);
    for (int i = 0; i < 8; i++) W[i + 8] = block_data[i];

    for (int i = 16; i < 64; ++i) {

        __m256i s1 = sigma1_AVX(W[i-2]);
        __m256i s0 = sigma0_AVX(W[i-15]);
        W[i] = _mm256_add_epi32(s1, _mm256_add_epi32(W[i-7], _mm256_add_epi32(W[i-16], s0)));
    }

    __m256i a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    __m256i e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    __m256i k0 = _mm256_set1_epi32(k256[0]);
    __m256i k1 = _mm256_set1_epi32(k256[1]);
    __m256i k2 = _mm256_set1_epi32(k256[2]);
    __m256i k3 = _mm256_set1_epi32(k256[3]);
   
    __m256i w0 = W[0];
    __m256i w1 = W[1];
    __m256i w2 = W[2];
    __m256i w3 = W[3];
    
    for (int i = 0; i < 64; i += 4) {

        __m256i t1_0 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1_AVX(e), _mm256_add_epi32(CH_AVX(e, f, g), _mm256_add_epi32(k0, w0))));
        __m256i t2_0 = _mm256_add_epi32(SIGMA0_AVX(a), MAJ_AVX(a, b, c));

        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_0); d = c; c = b; b = a; a = _mm256_add_epi32(t1_0, t2_0);

        if (i + 4 < 64) { k0 = _mm256_set1_epi32(k256[i+4]); w0 = W[i+4]; }
        
        __m256i t1_1 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1_AVX(e), _mm256_add_epi32(CH_AVX(e, f, g), _mm256_add_epi32(k1, w1))));
        __m256i t2_1 = _mm256_add_epi32(SIGMA0_AVX(a), MAJ_AVX(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_1); d = c; c = b; b = a; a = _mm256_add_epi32(t1_1, t2_1);
        if (i + 5 < 64) { k1 = _mm256_set1_epi32(k256[i+5]); w1 = W[i+5]; }
        
        __m256i t1_2 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1_AVX(e), _mm256_add_epi32(CH_AVX(e, f, g), _mm256_add_epi32(k2, w2))));
        __m256i t2_2 = _mm256_add_epi32(SIGMA0_AVX(a), MAJ_AVX(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_2); d = c; c = b; b = a; a = _mm256_add_epi32(t1_2, t2_2);
        if (i + 6 < 64) { k2 = _mm256_set1_epi32(k256[i+6]); w2 = W[i+6]; }
        
        __m256i t1_3 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1_AVX(e), _mm256_add_epi32(CH_AVX(e, f, g), _mm256_add_epi32(k3, w3))));
        __m256i t2_3 = _mm256_add_epi32(SIGMA0_AVX(a), MAJ_AVX(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_3); d = c; c = b; b = a; a = _mm256_add_epi32(t1_3, t2_3);
        if (i + 7 < 64) { k3 = _mm256_set1_epi32(k256[i+7]); w3 = W[i+7]; }
    }


    ctx->state[0] = _mm256_add_epi32(ctx->state[0], a); ctx->state[1] = _mm256_add_epi32(ctx->state[1], b);
    ctx->state[2] = _mm256_add_epi32(ctx->state[2], c); ctx->state[3] = _mm256_add_epi32(ctx->state[3], d);
    ctx->state[4] = _mm256_add_epi32(ctx->state[4], e); ctx->state[5] = _mm256_add_epi32(ctx->state[5], f);
    ctx->state[6] = _mm256_add_epi32(ctx->state[6], g); ctx->state[7] = _mm256_add_epi32(ctx->state[7], h);
}

// --- SHA-224 API ---
static void internal_sha224_init_ctx(struct SHA256_x8_CTX_INTERNAL *ctx) {
    ctx->state[0] = _mm256_set1_epi32(0xc1059ed8); ctx->state[1] = _mm256_set1_epi32(0x367cd507);
    ctx->state[2] = _mm256_set1_epi32(0x3070dd17); ctx->state[3] = _mm256_set1_epi32(0xf70e5939);
    ctx->state[4] = _mm256_set1_epi32(0xffc00b31); ctx->state[5] = _mm256_set1_epi32(0x68581511);
    ctx->state[6] = _mm256_set1_epi32(0x64f98fa7); ctx->state[7] = _mm256_set1_epi32(0xbefa4fa4);
}

SHA2_x8_CTX* sha224_x8_create() { return sha256_x8_create(); }
void sha224_x8_destroy(SHA2_x8_CTX* h) { sha256_x8_destroy(h); }
void sha224_x8_init(SHA2_x8_CTX* h) { if (h) internal_sha224_init_ctx((struct SHA256_x8_CTX_INTERNAL*)h); }
void sha224_x8_update(SHA2_x8_CTX* h, const uint8_t input[8][64]) { sha256_x8_update(h, input); }
void sha224_x8_final(SHA2_x8_CTX* h, uint8_t hashes_out[8][32]) {
    if (!h) return;
    alignas(64) uint8_t full_hashes[8][32];
    sha256_x8_final(h, full_hashes);
    for (int i = 0; i < 8; ++i) {
        memcpy(hashes_out[i], full_hashes[i], SHA224_BLOCK_SIZE);
    }
}


// --- SHA-256 API ---
static void internal_sha256_init_ctx(struct SHA256_x8_CTX_INTERNAL *ctx) {
    ctx->state[0] = _mm256_set1_epi32(0x6a09e667); ctx->state[1] = _mm256_set1_epi32(0xbb67ae85);
    ctx->state[2] = _mm256_set1_epi32(0x3c6ef372); ctx->state[3] = _mm256_set1_epi32(0xa54ff53a);
    ctx->state[4] = _mm256_set1_epi32(0x510e527f); ctx->state[5] = _mm256_set1_epi32(0x9b05688c);
    ctx->state[6] = _mm256_set1_epi32(0x1f83d9ab); ctx->state[7] = _mm256_set1_epi32(0x5be0cd19);
}

SHA2_x8_CTX* sha256_x8_create() { return (SHA2_x8_CTX*)platform_aligned_alloc(64, sizeof(struct SHA256_x8_CTX_INTERNAL)); }
void sha256_x8_destroy(SHA2_x8_CTX* h) { if (h) { explicit_bzero(h, sizeof(struct SHA256_x8_CTX_INTERNAL)); platform_aligned_free(h); } }
void sha256_x8_init(SHA2_x8_CTX* h) { if (h) internal_sha256_init_ctx((struct SHA256_x8_CTX_INTERNAL*)h); }
void sha256_x8_update(SHA2_x8_CTX* h, const uint8_t input[8][64]) { if (h) sha256_x8_transform((struct SHA256_x8_CTX_INTERNAL*)h, input); }
void sha256_x8_final(SHA2_x8_CTX* h, uint8_t hashes_out[8][32]) {
    if (!h) return;
    struct SHA256_x8_CTX_INTERNAL* ctx = (struct SHA256_x8_CTX_INTERNAL*)h;
    const __m256i mask = _mm256_setr_epi8(3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12, 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12);
    alignas(64) __m256i s[8]; memcpy(s, ctx->state, sizeof(s)); transpose8x8_epi32(s);
    for (int i=0; i<8; ++i) _mm256_storeu_si256((__m256i*)hashes_out[i], _mm256_shuffle_epi8(s[i], mask));
}

/*
 * ============================================================================
 *                         SHA-512 / SHA-384 (8-way AVX2)
 * ============================================================================
 */

typedef struct {
    alignas(32) __m256i state[8];
} SHA512_x4_CTX_INTERNAL;

typedef struct {
    SHA512_x4_CTX_INTERNAL a; // streams 0..3
    SHA512_x4_CTX_INTERNAL b; // streams 4..7
} SHA512_x8_CTX_INTERNAL;


#define ROR64_AVX(x,n) _mm256_or_si256(_mm256_srli_epi64((x),(n)), _mm256_slli_epi64((x),(64-(n))))
#define CH64_AVX(x,y,z)  _mm256_xor_si256(_mm256_and_si256(x,y), _mm256_andnot_si256(x,z))
#define MAJ64_AVX(x,y,z) _mm256_xor_si256(_mm256_xor_si256(_mm256_and_si256(x,y), _mm256_and_si256(x,z)), _mm256_and_si256(y,z))
#define EP0_64_AVX(x) _mm256_xor_si256(ROR64_AVX((x),28), _mm256_xor_si256(ROR64_AVX((x),34), ROR64_AVX((x),39)))
#define EP1_64_AVX(x) _mm256_xor_si256(ROR64_AVX((x),14), _mm256_xor_si256(ROR64_AVX((x),18), ROR64_AVX((x),41)))
#define SIG0_64_AVX(x) _mm256_xor_si256(ROR64_AVX((x),1), _mm256_xor_si256(ROR64_AVX((x),8), _mm256_srli_epi64((x),7)))
#define SIG1_64_AVX(x) _mm256_xor_si256(ROR64_AVX((x),19), _mm256_xor_si256(ROR64_AVX((x),61), _mm256_srli_epi64((x),6)))

static inline uint64_t be64_read(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void sha512_x4_transform(SHA512_x4_CTX_INTERNAL *ctx4, const uint8_t input_blocks[4][128]) {
    __m256i W[16];
    
    __m256i a = ctx4->state[0], b = ctx4->state[1], c = ctx4->state[2], d = ctx4->state[3];
    __m256i e = ctx4->state[4], f = ctx4->state[5], g = ctx4->state[6], h = ctx4->state[7];

    #define SHA512_ROUND(A, B, C, D, E, F, G, H, t) { \
        __m256i T1 = _mm256_add_epi64(H, _mm256_add_epi64(EP1_64_AVX(E), _mm256_add_epi64(CH64_AVX(E,F,G), _mm256_add_epi64(_mm256_set1_epi64x((long long)k512[t]), W[(t)%16])))); \
        __m256i T2 = _mm256_add_epi64(EP0_64_AVX(A), MAJ64_AVX(A,B,C)); \
        D = _mm256_add_epi64(D, T1); \
        H = _mm256_add_epi64(T1, T2); \
    }

    for (int t=0; t<80; t+=16) {

        
        for (int i=0; i<16; ++i) {
            if (t == 0) { 
                W[i] = _mm256_set_epi64x(
                    (long long)be64_read(input_blocks[3] + (i)*8), (long long)be64_read(input_blocks[2] + (i)*8),
                    (long long)be64_read(input_blocks[1] + (i)*8), (long long)be64_read(input_blocks[0] + (i)*8)
                );
            } else { 
                __m256i s0 = SIG0_64_AVX(W[(i-15)&15]);
                __m256i s1 = SIG1_64_AVX(W[(i-2)&15]);
                W[i&15] = _mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(W[(i-16)&15], s0), W[(i-7)&15]), s1);
            }
        }

        SHA512_ROUND(a, b, c, d, e, f, g, h, t+0);
        SHA512_ROUND(h, a, b, c, d, e, f, g, t+1);
        SHA512_ROUND(g, h, a, b, c, d, e, f, t+2);
        SHA512_ROUND(f, g, h, a, b, c, d, e, t+3);
        SHA512_ROUND(e, f, g, h, a, b, c, d, t+4);
        SHA512_ROUND(d, e, f, g, h, a, b, c, t+5);
        SHA512_ROUND(c, d, e, f, g, h, a, b, t+6);
        SHA512_ROUND(b, c, d, e, f, g, h, a, t+7);
        SHA512_ROUND(a, b, c, d, e, f, g, h, t+8);
        SHA512_ROUND(h, a, b, c, d, e, f, g, t+9);
        SHA512_ROUND(g, h, a, b, c, d, e, f, t+10);
        SHA512_ROUND(f, g, h, a, b, c, d, e, t+11);
        SHA512_ROUND(e, f, g, h, a, b, c, d, t+12);
        SHA512_ROUND(d, e, f, g, h, a, b, c, t+13);
        SHA512_ROUND(c, d, e, f, g, h, a, b, t+14);
        SHA512_ROUND(b, c, d, e, f, g, h, a, t+15);
    }

    #undef SHA512_ROUND

    ctx4->state[0] = _mm256_add_epi64(ctx4->state[0], a);
    ctx4->state[1] = _mm256_add_epi64(ctx4->state[1], b);
    ctx4->state[2] = _mm256_add_epi64(ctx4->state[2], c);
    ctx4->state[3] = _mm256_add_epi64(ctx4->state[3], d);
    ctx4->state[4] = _mm256_add_epi64(ctx4->state[4], e);
    ctx4->state[5] = _mm256_add_epi64(ctx4->state[5], f);
    ctx4->state[6] = _mm256_add_epi64(ctx4->state[6], g);
    ctx4->state[7] = _mm256_add_epi64(ctx4->state[7], h);
}

static inline void sha512_x4_internal_init(SHA512_x4_CTX_INTERNAL *c, const uint64_t iv[8]) {
    c->state[0] = _mm256_set1_epi64x((long long)iv[0]); c->state[1] = _mm256_set1_epi64x((long long)iv[1]);
    c->state[2] = _mm256_set1_epi64x((long long)iv[2]); c->state[3] = _mm256_set1_epi64x((long long)iv[3]);
    c->state[4] = _mm256_set1_epi64x((long long)iv[4]); c->state[5] = _mm256_set1_epi64x((long long)iv[5]);
    c->state[6] = _mm256_set1_epi64x((long long)iv[6]); c->state[7] = _mm256_set1_epi64x((long long)iv[7]);
}

// --- SHA-384 API ---
SHA2_x8_CTX* sha384_x8_create() { return sha512_x8_create(); }
void sha384_x8_destroy(SHA2_x8_CTX* h) { sha512_x8_destroy(h); }

void sha384_x8_init(SHA2_x8_CTX* h) {
    if (!h) return;
    SHA512_x8_CTX_INTERNAL* ctx = (SHA512_x8_CTX_INTERNAL*)h;
    static const uint64_t iv[8] = {
        0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL };
    sha512_x4_internal_init(&ctx->a, iv);
    sha512_x4_internal_init(&ctx->b, iv);
}

void sha384_x8_update(SHA2_x8_CTX* h, const uint8_t input_blocks[8][128]) { sha512_x8_update(h, input_blocks); }


void sha384_x8_final(SHA2_x8_CTX* h, uint8_t hashes_out[8][64]) {
    if (!h) return;
    alignas(64) uint8_t tmp[8][64];
    sha512_x8_final(h, tmp);
    for (int i=0; i<8; ++i) {
        memcpy(hashes_out[i], tmp[i], SHA384_BLOCK_SIZE);
    }
}

// --- SHA-512 API ---
SHA2_x8_CTX* sha512_x8_create() { return (SHA2_x8_CTX*)platform_aligned_alloc(64, sizeof(SHA512_x8_CTX_INTERNAL)); }
void sha512_x8_destroy(SHA2_x8_CTX* h) { if (h) { explicit_bzero(h, sizeof(SHA512_x8_CTX_INTERNAL)); platform_aligned_free(h); } }

void sha512_x8_init(SHA2_x8_CTX* h) {
    if (!h) return;
    SHA512_x8_CTX_INTERNAL* ctx = (SHA512_x8_CTX_INTERNAL*)h;
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL };
    sha512_x4_internal_init(&ctx->a, iv);
    sha512_x4_internal_init(&ctx->b, iv);
}

void sha512_x8_update(SHA2_x8_CTX* h, const uint8_t input_blocks[8][128]) {
    if (!h) return;
    SHA512_x8_CTX_INTERNAL* ctx = (SHA512_x8_CTX_INTERNAL*)h;
    sha512_x4_transform(&ctx->a, (const uint8_t (*)[128])input_blocks);
    sha512_x4_transform(&ctx->b, (const uint8_t (*)[128])(input_blocks + 4));
}

void sha512_x8_final(SHA2_x8_CTX* h, uint8_t hashes_out[8][64]) {
    if (!h) return;
    SHA512_x8_CTX_INTERNAL* ctx = (SHA512_x8_CTX_INTERNAL*)h;
    uint64_t tmp[4];
    for (int half = 0; half < 2; ++half) {
        SHA512_x4_CTX_INTERNAL *c = (half==0) ? &ctx->a : &ctx->b;
        int stream_base = half * 4;
        for (int word = 0; word < 8; ++word) {
            _mm256_storeu_si256((__m256i*)tmp, c->state[word]);
            for (int lane = 0; lane < 4; ++lane) {
                uint64_t be = __builtin_bswap64(tmp[lane]);
                memcpy(hashes_out[stream_base + lane] + word * 8, &be, 8);
            }
        }
    }
}


#endif // __AVX2__
