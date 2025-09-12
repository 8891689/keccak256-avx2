//author： https://github.com/8891689
/*
 * Copyright [2025] [8891689]
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
#include "ripemd160_avx2.h" 
#include <string.h>
#include <stdbool.h>
#include <stddef.h> 
#include <immintrin.h> 

// --- 靜態常量和輔助函數定義
static const uint32_t KL[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
static const uint32_t KR[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

static const uint8_t r_const[80] = { 
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
static const uint8_t rp_const[80] = { 
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
static const uint8_t s_val_arr[80] = { 
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
static const uint8_t sp_val_arr[80] = { 
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

// initialize_avx_constants 中初始化
static __m256i INIT_A;
static __m256i INIT_B;
static __m256i INIT_C;
static __m256i INIT_D;
static __m256i INIT_E;

#define XOR_NOT(x) _mm256_xor_si256((x), _mm256_set1_epi32(~0U))
#define ROL32C(x, n) _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32-(n)))
#define ROL32V(x, n_vec) _mm256_or_si256(_mm256_sllv_epi32((x), (n_vec)), _mm256_srlv_epi32((x), _mm256_sub_epi32(_mm256_set1_epi32(32), (n_vec))))

static inline __m256i F(__m256i x, __m256i y, __m256i z) { return _mm256_xor_si256(_mm256_xor_si256(x, y), z); }
static inline __m256i G(__m256i x, __m256i y, __m256i z) { return _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z)); }
static inline __m256i H(__m256i x, __m256i y, __m256i z) { return _mm256_xor_si256(_mm256_or_si256(x, XOR_NOT(y)), z); }
static inline __m256i I(__m256i x, __m256i y, __m256i z) { return _mm256_or_si256(_mm256_and_si256(x, z), _mm256_and_si256(y, XOR_NOT(z))); }
static inline __m256i J(__m256i x, __m256i y, __m256i z) { return _mm256_xor_si256(x, _mm256_or_si256(y, XOR_NOT(z))); }

// Global AVX constants, initialized once
static __m256i K_vals[5];
static __m256i KR_vals[5];
static __m256i s_avx_vals[80];
static __m256i sp_avx_vals[80]; 

static bool avx_constants_initialized = false;

static void initialize_avx_constants() {
    if (avx_constants_initialized) return;

    // 初始化 INIT_A 到 INIT_E
    INIT_A = _mm256_set1_epi32(0x67452301);
    INIT_B = _mm256_set1_epi32(0xEFCDAB89);
    INIT_C = _mm256_set1_epi32(0x98BADCFE);
    INIT_D = _mm256_set1_epi32(0x10325476);
    INIT_E = _mm256_set1_epi32(0xC3D2E1F0);

    for(int i=0; i<5; ++i) {
        K_vals[i] = _mm256_set1_epi32(KL[i]);
        KR_vals[i] = _mm256_set1_epi32(KR[i]);
    }
    for (int i = 0; i < 80; ++i) {
        s_avx_vals[i] = _mm256_set1_epi32(s_val_arr[i]);
        sp_avx_vals[i] = _mm256_set1_epi32(sp_val_arr[i]);
    }
    avx_constants_initialized = true;
}


//  schedule 函數
static void schedule(__m256i X[16], const uint8_t blocks[LANE_COUNT][BLOCK_SIZE]) {
    const int* base_addr = (const int*)blocks; 
    const int block_size_dwords = BLOCK_SIZE / sizeof(int); // 64 / 4 = 16

    for (int word_idx = 0; word_idx < 16; ++word_idx) {
        __m256i vindex = _mm256_set_epi32(
            (7 * block_size_dwords) + word_idx,
            (6 * block_size_dwords) + word_idx,
            (5 * block_size_dwords) + word_idx,
            (4 * block_size_dwords) + word_idx,
            (3 * block_size_dwords) + word_idx,
            (2 * block_size_dwords) + word_idx,
            (1 * block_size_dwords) + word_idx,
            (0 * block_size_dwords) + word_idx
        );
        X[word_idx] = _mm256_i32gather_epi32(base_addr, vindex, 4);
    }
}

static void compress(__m256i state[5], const __m256i X[16]) {
    initialize_avx_constants(); 

    __m256i H0 = state[0];
    __m256i H1 = state[1];
    __m256i H2 = state[2];
    __m256i H3 = state[3];
    __m256i H4 = state[4];

    __m256i A = H0, B = H1, C = H2, D = H3, E = H4;
    __m256i A1 = H0, B1 = H1, C1 = H2, D1 = H3, E1 = H4;

    #define PROCESS_4_ROUNDS(start_idx, func_l, func_r, K_arr_idx, KR_arr_idx) \
    for (int i = start_idx; i < start_idx+4; i++) { \
        __m256i T_l = _mm256_add_epi32( \
            ROL32V( \
                _mm256_add_epi32( \
                    _mm256_add_epi32(A, func_l(B, C, D)), \
                    _mm256_add_epi32(X[r_const[i]], K_vals[K_arr_idx]) \
                ), s_avx_vals[i] \
            ), E \
        ); \
        __m256i T_r = _mm256_add_epi32( \
            ROL32V( \
                _mm256_add_epi32( \
                    _mm256_add_epi32(A1, func_r(B1, C1, D1)), \
                    _mm256_add_epi32(X[rp_const[i]], KR_vals[KR_arr_idx]) \
                ), sp_avx_vals[i] \
            ), E1 \
        ); \
        __m256i prev_C = C; \
        A = E; \
        E = D; \
        D = ROL32C(prev_C, 10); \
        C = B; \
        B = T_l; \
        __m256i prev_C1 = C1; \
        A1 = E1; \
        E1 = D1; \
        D1 = ROL32C(prev_C1, 10); \
        C1 = B1; \
        B1 = T_r; \
    }

    for (int rnd = 0; rnd < 16; rnd += 4) PROCESS_4_ROUNDS(rnd, F, J, 0, 0);
    for (int rnd = 16; rnd < 32; rnd += 4) PROCESS_4_ROUNDS(rnd, G, I, 1, 1);
    for (int rnd = 32; rnd < 48; rnd += 4) PROCESS_4_ROUNDS(rnd, H, H, 2, 2);
    for (int rnd = 48; rnd < 64; rnd += 4) PROCESS_4_ROUNDS(rnd, I, G, 3, 3);
    for (int rnd = 64; rnd < 80; rnd += 4) PROCESS_4_ROUNDS(rnd, J, F, 4, 4);

    state[0] = _mm256_add_epi32(_mm256_add_epi32(H1, C), D1);
    state[1] = _mm256_add_epi32(_mm256_add_epi32(H2, D), E1);
    state[2] = _mm256_add_epi32(_mm256_add_epi32(H3, E), A1);
    state[3] = _mm256_add_epi32(_mm256_add_epi32(H4, A), B1);
    state[4] = _mm256_add_epi32(_mm256_add_epi32(H0, B), C1);
}

static void process_full_blocks(__m256i state[5], uint64_t total_bits[LANE_COUNT], const uint8_t blocks_to_process[LANE_COUNT][BLOCK_SIZE]) {
    CUSTOM_ALIGNAS(64) __m256i X[16];
    schedule(X, blocks_to_process);
    compress(state, X);

    if (total_bits != NULL) {
        for (int lane = 0; lane < LANE_COUNT; ++lane) {
            total_bits[lane] += (uint64_t)BLOCK_SIZE * 8;
        }
    }
}

static void append_length_to_padding(uint8_t* block, uint64_t message_len_bits) {
    for (int i = 0; i < 8; ++i) {
        block[BLOCK_SIZE - 8 + i] = (uint8_t)(message_len_bits >> (i * 8));
    }
}

// --- 公開接口函數 ---
void ripemd160_multi_init(RIPEMD160_MULTI_CTX* ctx) {
    initialize_avx_constants(); 
    ctx->state[0] = INIT_A;
    ctx->state[1] = INIT_B;
    ctx->state[2] = INIT_C;
    ctx->state[3] = INIT_D;
    ctx->state[4] = INIT_E;
    for (int i = 0; i < LANE_COUNT; ++i) {
        ctx->total_bits[i] = 0;
        ctx->buffer_len[i] = 0;
        memset(ctx->buffer[i], 0, BLOCK_SIZE);
    }
}

void ripemd160_multi_update_full_blocks(RIPEMD160_MULTI_CTX* ctx, const uint8_t data_blocks[LANE_COUNT][BLOCK_SIZE]) {
    process_full_blocks(ctx->state, ctx->total_bits, data_blocks);
}

void ripemd160_multi_final(RIPEMD160_MULTI_CTX* ctx, uint8_t digests[LANE_COUNT][DIGEST_SIZE]) {
    uint8_t final_padding_block[LANE_COUNT][BLOCK_SIZE];
    uint8_t second_padding_block[LANE_COUNT][BLOCK_SIZE];
    bool needs_second_block_for_padding[LANE_COUNT] = {false}; 

    memset(final_padding_block, 0, sizeof(final_padding_block));
    memset(second_padding_block, 0, sizeof(second_padding_block));

    for (int lane = 0; lane < LANE_COUNT; ++lane) {
        uint64_t message_len_bits = ctx->total_bits[lane] + (uint64_t)ctx->buffer_len[lane] * 8;
        memcpy(final_padding_block[lane], ctx->buffer[lane], ctx->buffer_len[lane]);
        final_padding_block[lane][ctx->buffer_len[lane]] = 0x80;

        if (ctx->buffer_len[lane] + 1 > BLOCK_SIZE - 8) {
            needs_second_block_for_padding[lane] = true;
            append_length_to_padding(second_padding_block[lane], message_len_bits);
        } else {
            append_length_to_padding(final_padding_block[lane], message_len_bits);
        }
    }

    process_full_blocks(ctx->state, NULL, final_padding_block); 

    bool any_lane_needs_second_block = false;
    for(int lane = 0; lane < LANE_COUNT; ++lane) {
        if (needs_second_block_for_padding[lane]) {
            any_lane_needs_second_block = true;
            break;
        }
    }

    if (any_lane_needs_second_block) {
        process_full_blocks(ctx->state, NULL, second_padding_block); 
    }


    CUSTOM_ALIGNAS(32) uint32_t state_lanes_buffer[5][LANE_COUNT];
    for(int i=0; i<5; ++i) {
        _mm256_store_si256((__m256i*)state_lanes_buffer[i], ctx->state[i]); 
    }

    for (int lane = 0; lane < LANE_COUNT; ++lane) {
        for(int word_idx = 0; word_idx < 5; ++word_idx) {
            uint32_t val = state_lanes_buffer[word_idx][lane];
            digests[lane][word_idx*4 + 0] = (val >> 0) & 0xFF;
            digests[lane][word_idx*4 + 1] = (val >> 8) & 0xFF;
            digests[lane][word_idx*4 + 2] = (val >> 16) & 0xFF;
            digests[lane][word_idx*4 + 3] = (val >> 24) & 0xFF;
        }
    }
}

/**
 * @brief New One-Shot function implementation for high-performance small message hashing.
 */
void ripemd160_multi_oneshot(const uint8_t *data[LANE_COUNT], const size_t lens[LANE_COUNT], uint8_t digests[LANE_COUNT][DIGEST_SIZE]) {
    // We can use a stack-allocated context for this one-shot operation.
    CUSTOM_ALIGNAS(64) RIPEMD160_MULTI_CTX ctx;
    
    // 1. Initialize context state and buffers
    ripemd160_multi_init(&ctx);

    // 2. Copy data into internal buffers. The ripemd160_multi_final function
    // is designed to work with these buffers, so this is the most direct way.
    for (int i = 0; i < LANE_COUNT; ++i) {
        // We assume lens[i] < 56, which is a precondition for this function.
        memcpy(ctx.buffer[i], data[i], lens[i]);
        ctx.buffer_len[i] = (uint32_t)lens[i];
    }
    
    // 3. Call the existing finalization function, which handles padding and compression.
    // It will correctly process the data we just put in the buffers.
    ripemd160_multi_final(&ctx, digests);
}
