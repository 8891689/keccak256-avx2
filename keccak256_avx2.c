// keccak256_avx2.c
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

#include "keccak256_avx2.h"
#include <string.h>
#include <immintrin.h> 

// --- Constants (Aligned for cache lines) ---
const uint64_t keccakf_rndc[24] __attribute__((aligned(64))) = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

const int keccakf_rotc[24] __attribute__((aligned(64))) = { // Rotation constants for Rho
    1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8,
   25, 43, 62, 18, 39, 61, 20, 44
};

const int keccakf_piln[24] __attribute__((aligned(64))) = { // Permutation indices for Rho/Pi chain
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1
};

// --- Core Functions ---
void init_keccak_ctx_avx8(KECCAK_CTX_AVX8 *ctx) {
    __m256i zero = _mm256_setzero_si256();
    for (int i = 0; i < 24; i += 4) { 
        ctx->state_word_group1[i  ] = zero;
        ctx->state_word_group1[i+1] = zero;
        ctx->state_word_group1[i+2] = zero;
        ctx->state_word_group1[i+3] = zero;
        
        ctx->state_word_group2[i  ] = zero;
        ctx->state_word_group2[i+1] = zero;
        ctx->state_word_group2[i+2] = zero;
        ctx->state_word_group2[i+3] = zero;
    }
    ctx->state_word_group1[24] = zero; 
    ctx->state_word_group2[24] = zero;
}

__attribute__((target("avx2")))
void keccak_absorb_8blocks_avx8(KECCAK_CTX_AVX8 *ctx, const uint8_t input_data_8blocks[8][KECCAK_RATE_BYTES]) {
    _mm_prefetch((const char*)keccakf_rndc, _MM_HINT_T0);
    _mm_prefetch((const char*)keccakf_rotc, _MM_HINT_T0);
    _mm_prefetch((const char*)keccakf_piln, _MM_HINT_T0);

    for (int q_base = 0; q_base < 16; q_base += 4) {
        __m256i b0_g1 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[0] + q_base * 8));
        __m256i b1_g1 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[1] + q_base * 8));
        __m256i b2_g1 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[2] + q_base * 8));
        __m256i b3_g1 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[3] + q_base * 8));
        __m256i t0_g1 = _mm256_unpacklo_epi64(b0_g1, b1_g1);
        __m256i t1_g1 = _mm256_unpackhi_epi64(b0_g1, b1_g1);
        __m256i t2_g1 = _mm256_unpacklo_epi64(b2_g1, b3_g1);
        __m256i t3_g1 = _mm256_unpackhi_epi64(b2_g1, b3_g1);
        ctx->state_word_group1[q_base + 0] = _mm256_xor_si256(ctx->state_word_group1[q_base + 0], _mm256_permute2x128_si256(t0_g1, t2_g1, 0x20));
        ctx->state_word_group1[q_base + 1] = _mm256_xor_si256(ctx->state_word_group1[q_base + 1], _mm256_permute2x128_si256(t1_g1, t3_g1, 0x20));
        ctx->state_word_group1[q_base + 2] = _mm256_xor_si256(ctx->state_word_group1[q_base + 2], _mm256_permute2x128_si256(t0_g1, t2_g1, 0x31));
        ctx->state_word_group1[q_base + 3] = _mm256_xor_si256(ctx->state_word_group1[q_base + 3], _mm256_permute2x128_si256(t1_g1, t3_g1, 0x31));
        
        __m256i b0_g2 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[4] + q_base * 8));
        __m256i b1_g2 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[5] + q_base * 8));
        __m256i b2_g2 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[6] + q_base * 8));
        __m256i b3_g2 = _mm256_loadu_si256((__m256i const*)(input_data_8blocks[7] + q_base * 8));
        __m256i t0_g2 = _mm256_unpacklo_epi64(b0_g2, b1_g2);
        __m256i t1_g2 = _mm256_unpackhi_epi64(b0_g2, b1_g2);
        __m256i t2_g2 = _mm256_unpacklo_epi64(b2_g2, b3_g2);
        __m256i t3_g2 = _mm256_unpackhi_epi64(b2_g2, b3_g2);
        ctx->state_word_group2[q_base + 0] = _mm256_xor_si256(ctx->state_word_group2[q_base + 0], _mm256_permute2x128_si256(t0_g2, t2_g2, 0x20));
        ctx->state_word_group2[q_base + 1] = _mm256_xor_si256(ctx->state_word_group2[q_base + 1], _mm256_permute2x128_si256(t1_g2, t3_g2, 0x20));
        ctx->state_word_group2[q_base + 2] = _mm256_xor_si256(ctx->state_word_group2[q_base + 2], _mm256_permute2x128_si256(t0_g2, t2_g2, 0x31));
        ctx->state_word_group2[q_base + 3] = _mm256_xor_si256(ctx->state_word_group2[q_base + 3], _mm256_permute2x128_si256(t1_g2, t3_g2, 0x31));
    }
    const int k_last_qword_idx = 16; 
    ctx->state_word_group1[k_last_qword_idx] = _mm256_xor_si256(ctx->state_word_group1[k_last_qword_idx], _mm256_set_epi64x(((const uint64_t*)input_data_8blocks[3])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[2])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[1])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[0])[k_last_qword_idx]));
    ctx->state_word_group2[k_last_qword_idx] = _mm256_xor_si256(ctx->state_word_group2[k_last_qword_idx], _mm256_set_epi64x(((const uint64_t*)input_data_8blocks[7])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[6])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[5])[k_last_qword_idx], ((const uint64_t*)input_data_8blocks[4])[k_last_qword_idx]));
    keccakf_transform_avx8(ctx);
}

__attribute__((target("avx2")))
void keccak_extract_hash_8lanes_avx8(const KECCAK_CTX_AVX8 *ctx, uint8_t output_hashes_8lanes[8][KECCAK_HASH_BYTES]) {
    __m256i r0, r1, r2, r3; 
    __m256i t0, t1, t2, t3; 
    __m256i out0, out1, out2, out3;

    r0 = ctx->state_word_group1[0]; 
    r1 = ctx->state_word_group1[1]; 
    r2 = ctx->state_word_group1[2]; 
    r3 = ctx->state_word_group1[3]; 

    t0 = _mm256_unpacklo_epi64(r0, r1); 
    t1 = _mm256_unpacklo_epi64(r2, r3); 
    t2 = _mm256_unpackhi_epi64(r0, r1); 
    t3 = _mm256_unpackhi_epi64(r2, r3); 

    out0 = _mm256_permute2x128_si256(t0, t1, 0x20); 
    out1 = _mm256_permute2x128_si256(t2, t3, 0x20); 
    out2 = _mm256_permute2x128_si256(t0, t1, 0x31); 
    out3 = _mm256_permute2x128_si256(t2, t3, 0x31); 

    _mm256_store_si256((__m256i*)output_hashes_8lanes[0], out0);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[1], out1);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[2], out2);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[3], out3);

    r0 = ctx->state_word_group2[0];
    r1 = ctx->state_word_group2[1];
    r2 = ctx->state_word_group2[2];
    r3 = ctx->state_word_group2[3];

    t0 = _mm256_unpacklo_epi64(r0, r1);
    t1 = _mm256_unpacklo_epi64(r2, r3);
    t2 = _mm256_unpackhi_epi64(r0, r1);
    t3 = _mm256_unpackhi_epi64(r2, r3);

    out0 = _mm256_permute2x128_si256(t0, t1, 0x20); 
    out1 = _mm256_permute2x128_si256(t2, t3, 0x20); 
    out2 = _mm256_permute2x128_si256(t0, t1, 0x31); 
    out3 = _mm256_permute2x128_si256(t2, t3, 0x31); 

    _mm256_store_si256((__m256i*)output_hashes_8lanes[4], out0);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[5], out1);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[6], out2);
    _mm256_store_si256((__m256i*)output_hashes_8lanes[7], out3);
}

#define THETA_STEP_OPT(st, bc0, bc1, bc2, bc3, bc4, theta_d0, theta_d1) \
    bc0 = _mm256_xor_si256(st[0], st[5]);   bc0 = _mm256_xor_si256(bc0, st[10]); \
    bc0 = _mm256_xor_si256(bc0, st[15]);  bc0 = _mm256_xor_si256(bc0, st[20]); \
    bc1 = _mm256_xor_si256(st[1], st[6]);   bc1 = _mm256_xor_si256(bc1, st[11]); \
    bc1 = _mm256_xor_si256(bc1, st[16]);  bc1 = _mm256_xor_si256(bc1, st[21]); \
    bc2 = _mm256_xor_si256(st[2], st[7]);   bc2 = _mm256_xor_si256(bc2, st[12]); \
    bc2 = _mm256_xor_si256(bc2, st[17]);  bc2 = _mm256_xor_si256(bc2, st[22]); \
    bc3 = _mm256_xor_si256(st[3], st[8]);   bc3 = _mm256_xor_si256(bc3, st[13]); \
    bc3 = _mm256_xor_si256(bc3, st[18]);  bc3 = _mm256_xor_si256(bc3, st[23]); \
    bc4 = _mm256_xor_si256(st[4], st[9]);   bc4 = _mm256_xor_si256(bc4, st[14]); \
    bc4 = _mm256_xor_si256(bc4, st[19]);  bc4 = _mm256_xor_si256(bc4, st[24]); \
    \
    theta_d0 = _mm256_xor_si256(bc4, ROTL64_VEC(bc1, 1)); \
    theta_d1 = _mm256_xor_si256(bc0, ROTL64_VEC(bc2, 1)); \
    st[0] = _mm256_xor_si256(st[0], theta_d0);   st[5] = _mm256_xor_si256(st[5], theta_d0); \
    st[10]= _mm256_xor_si256(st[10],theta_d0);  st[15]= _mm256_xor_si256(st[15],theta_d0); \
    st[20]= _mm256_xor_si256(st[20],theta_d0); \
    \
    st[1] = _mm256_xor_si256(st[1], theta_d1);   st[6] = _mm256_xor_si256(st[6], theta_d1); \
    st[11]= _mm256_xor_si256(st[11],theta_d1);  st[16]= _mm256_xor_si256(st[16],theta_d1); \
    st[21]= _mm256_xor_si256(st[21],theta_d1); \
    \
    theta_d0 = _mm256_xor_si256(bc1, ROTL64_VEC(bc3, 1)); \
    st[2] = _mm256_xor_si256(st[2], theta_d0);   st[7] = _mm256_xor_si256(st[7], theta_d0); \
    st[12]= _mm256_xor_si256(st[12],theta_d0);  st[17]= _mm256_xor_si256(st[17],theta_d0); \
    st[22]= _mm256_xor_si256(st[22],theta_d0); \
    \
    theta_d1 = _mm256_xor_si256(bc2, ROTL64_VEC(bc4, 1)); \
    st[3] = _mm256_xor_si256(st[3], theta_d1);   st[8] = _mm256_xor_si256(st[8], theta_d1); \
    st[13]= _mm256_xor_si256(st[13],theta_d1);  st[18]= _mm256_xor_si256(st[18],theta_d1); \
    st[23]= _mm256_xor_si256(st[23],theta_d1); \
    \
    theta_d0 = _mm256_xor_si256(bc3, ROTL64_VEC(bc0, 1)); \
    st[4] = _mm256_xor_si256(st[4], theta_d0);   st[9] = _mm256_xor_si256(st[9], theta_d0); \
    st[14]= _mm256_xor_si256(st[14],theta_d0);  st[19]= _mm256_xor_si256(st[19],theta_d0); \
    st[24]= _mm256_xor_si256(st[24],theta_d0);

#define RHO_PI_STEP_CORRECT(st_array, current_val_rp, temp_val_rp) \
    current_val_rp = st_array[1]; \
    temp_val_rp = st_array[keccakf_piln[0]];  st_array[keccakf_piln[0]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[0]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[1]];  st_array[keccakf_piln[1]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[1]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[2]];  st_array[keccakf_piln[2]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[2]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[3]];  st_array[keccakf_piln[3]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[3]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[4]];  st_array[keccakf_piln[4]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[4]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[5]];  st_array[keccakf_piln[5]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[5]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[6]];  st_array[keccakf_piln[6]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[6]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[7]];  st_array[keccakf_piln[7]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[7]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[8]];  st_array[keccakf_piln[8]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[8]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[9]];  st_array[keccakf_piln[9]]  = ROTL64_VEC(current_val_rp, keccakf_rotc[9]);  current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[10]]; st_array[keccakf_piln[10]] = ROTL64_VEC(current_val_rp, keccakf_rotc[10]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[11]]; st_array[keccakf_piln[11]] = ROTL64_VEC(current_val_rp, keccakf_rotc[11]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[12]]; st_array[keccakf_piln[12]] = ROTL64_VEC(current_val_rp, keccakf_rotc[12]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[13]]; st_array[keccakf_piln[13]] = ROTL64_VEC(current_val_rp, keccakf_rotc[13]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[14]]; st_array[keccakf_piln[14]] = ROTL64_VEC(current_val_rp, keccakf_rotc[14]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[15]]; st_array[keccakf_piln[15]] = ROTL64_VEC(current_val_rp, keccakf_rotc[15]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[16]]; st_array[keccakf_piln[16]] = ROTL64_VEC(current_val_rp, keccakf_rotc[16]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[17]]; st_array[keccakf_piln[17]] = ROTL64_VEC(current_val_rp, keccakf_rotc[17]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[18]]; st_array[keccakf_piln[18]] = ROTL64_VEC(current_val_rp, keccakf_rotc[18]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[19]]; st_array[keccakf_piln[19]] = ROTL64_VEC(current_val_rp, keccakf_rotc[19]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[20]]; st_array[keccakf_piln[20]] = ROTL64_VEC(current_val_rp, keccakf_rotc[20]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[21]]; st_array[keccakf_piln[21]] = ROTL64_VEC(current_val_rp, keccakf_rotc[21]); current_val_rp = temp_val_rp; \
    temp_val_rp = st_array[keccakf_piln[22]]; st_array[keccakf_piln[22]] = ROTL64_VEC(current_val_rp, keccakf_rotc[22]); current_val_rp = temp_val_rp; \
    st_array[keccakf_piln[23]] = ROTL64_VEC(current_val_rp, keccakf_rotc[23]);

#define CHI_STEP_SPEED(st_array, s0_c, s1_c, s2_c, s3_c, s4_c) \
    s0_c = st_array[0]; s1_c = st_array[1]; s2_c = st_array[2]; s3_c = st_array[3]; s4_c = st_array[4]; \
    st_array[0] = _mm256_xor_si256(s0_c, _mm256_andnot_si256(s1_c, s2_c)); \
    st_array[1] = _mm256_xor_si256(s1_c, _mm256_andnot_si256(s2_c, s3_c)); \
    st_array[2] = _mm256_xor_si256(s2_c, _mm256_andnot_si256(s3_c, s4_c)); \
    st_array[3] = _mm256_xor_si256(s3_c, _mm256_andnot_si256(s4_c, s0_c)); \
    st_array[4] = _mm256_xor_si256(s4_c, _mm256_andnot_si256(s0_c, s1_c)); \
    s0_c = st_array[5]; s1_c = st_array[6]; s2_c = st_array[7]; s3_c = st_array[8]; s4_c = st_array[9]; \
    st_array[5] = _mm256_xor_si256(s0_c, _mm256_andnot_si256(s1_c, s2_c)); \
    st_array[6] = _mm256_xor_si256(s1_c, _mm256_andnot_si256(s2_c, s3_c)); \
    st_array[7] = _mm256_xor_si256(s2_c, _mm256_andnot_si256(s3_c, s4_c)); \
    st_array[8] = _mm256_xor_si256(s3_c, _mm256_andnot_si256(s4_c, s0_c)); \
    st_array[9] = _mm256_xor_si256(s4_c, _mm256_andnot_si256(s0_c, s1_c)); \
    s0_c = st_array[10]; s1_c = st_array[11]; s2_c = st_array[12]; s3_c = st_array[13]; s4_c = st_array[14]; \
    st_array[10] = _mm256_xor_si256(s0_c, _mm256_andnot_si256(s1_c, s2_c)); \
    st_array[11] = _mm256_xor_si256(s1_c, _mm256_andnot_si256(s2_c, s3_c)); \
    st_array[12] = _mm256_xor_si256(s2_c, _mm256_andnot_si256(s3_c, s4_c)); \
    st_array[13] = _mm256_xor_si256(s3_c, _mm256_andnot_si256(s4_c, s0_c)); \
    st_array[14] = _mm256_xor_si256(s4_c, _mm256_andnot_si256(s0_c, s1_c)); \
    s0_c = st_array[15]; s1_c = st_array[16]; s2_c = st_array[17]; s3_c = st_array[18]; s4_c = st_array[19]; \
    st_array[15] = _mm256_xor_si256(s0_c, _mm256_andnot_si256(s1_c, s2_c)); \
    st_array[16] = _mm256_xor_si256(s1_c, _mm256_andnot_si256(s2_c, s3_c)); \
    st_array[17] = _mm256_xor_si256(s2_c, _mm256_andnot_si256(s3_c, s4_c)); \
    st_array[18] = _mm256_xor_si256(s3_c, _mm256_andnot_si256(s4_c, s0_c)); \
    st_array[19] = _mm256_xor_si256(s4_c, _mm256_andnot_si256(s0_c, s1_c)); \
    s0_c = st_array[20]; s1_c = st_array[21]; s2_c = st_array[22]; s3_c = st_array[23]; s4_c = st_array[24]; \
    st_array[20] = _mm256_xor_si256(s0_c, _mm256_andnot_si256(s1_c, s2_c)); \
    st_array[21] = _mm256_xor_si256(s1_c, _mm256_andnot_si256(s2_c, s3_c)); \
    st_array[22] = _mm256_xor_si256(s2_c, _mm256_andnot_si256(s3_c, s4_c)); \
    st_array[23] = _mm256_xor_si256(s3_c, _mm256_andnot_si256(s4_c, s0_c)); \
    st_array[24] = _mm256_xor_si256(s4_c, _mm256_andnot_si256(s0_c, s1_c));

#define IOTA_STEP_SPEED(st_array, R_IDX) \
    st_array[0] = _mm256_xor_si256(st_array[0], _mm256_set1_epi64x(keccakf_rndc[R_IDX]));

#define KECCAK_ROUND_SPEED_FOCUS_REFINED(st_array, R_IDX, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c) \
    THETA_STEP_OPT(st_array, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1); \
    RHO_PI_STEP_CORRECT(st_array, current_val_rp,temp_val_rp); \
    CHI_STEP_SPEED(st_array, s0_c,s1_c,s2_c,s3_c,s4_c); \
    IOTA_STEP_SPEED(st_array, R_IDX);


__attribute__((always_inline))
static inline void keccakf_internal_avx8_speed_focus_macros(__m256i st[KECCAK_STATE_QWORDS]) {
    __m256i bc0, bc1, bc2, bc3, bc4;
    __m256i theta_d0, theta_d1; 
    __m256i current_val_rp, temp_val_rp; 
    __m256i s0_c, s1_c, s2_c, s3_c, s4_c;   

    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,0,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,1,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,2,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,3,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,4,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,5,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,6,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,7,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,8,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,9,  bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,10, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,11, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,12, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,13, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,14, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,15, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,16, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,17, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,18, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,19, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,20, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,21, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,22, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
    KECCAK_ROUND_SPEED_FOCUS_REFINED(st,23, bc0,bc1,bc2,bc3,bc4, theta_d0,theta_d1, current_val_rp,temp_val_rp, s0_c,s1_c,s2_c,s3_c,s4_c);
}

__attribute__((target("avx2")))
void keccakf_transform_avx8(KECCAK_CTX_AVX8 *ctx) {
    keccakf_internal_avx8_speed_focus_macros(ctx->state_word_group1);
    keccakf_internal_avx8_speed_focus_macros(ctx->state_word_group2);
}
