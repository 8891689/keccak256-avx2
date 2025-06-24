//Author: 8891689
//https://github.com/8891689
#ifndef KECCAK256_AVX_H
#define KECCAK256_AVX_H

#include <stdint.h>
#include <immintrin.h> 

#define KECCAK_RATE_BYTES 136 // (1600 - 512) / 8 for Keccak-256
#define KECCAK_HASH_BYTES 32  // 256 / 8
#define KECCAK_STATE_QWORDS 25 // 1600 / 64

// 8 个并行 Keccak-256 计算的上下文
typedef struct {
    __m256i state_word_group1[KECCAK_STATE_QWORDS] __attribute__((aligned(32)));
    __m256i state_word_group2[KECCAK_STATE_QWORDS] __attribute__((aligned(32)));
} KECCAK_CTX_AVX8;

// Keccak-f[1600] 轮常量（声明为 extern）
extern const uint64_t keccakf_rndc[24];
// Rho 旋转偏移量（声明为 extern）
extern const int keccakf_rotc[24];
// π 置换索引（声明为 extern）
extern const int keccakf_piln[24];

// AVX2 矢量化左移 64 位元素
// y_const 对于 slli/srli 必须是立即数
#define ROTL64_VEC(x, y_const) \
    _mm256_or_si256(_mm256_slli_epi64(x, y_const), _mm256_srli_epi64(x, 64 - (y_const)))

// 函数原型
void init_keccak_ctx_avx8(KECCAK_CTX_AVX8 *ctx);
void keccak_absorb_8blocks_avx8(KECCAK_CTX_AVX8 *ctx, const uint8_t input_data_8blocks[8][KECCAK_RATE_BYTES]);
void keccakf_transform_avx8(KECCAK_CTX_AVX8 *ctx); // 8 个并行状态的核心排列
void keccak_extract_hash_8lanes_avx8(const KECCAK_CTX_AVX8 *ctx, uint8_t output_hashes_8lanes[8][KECCAK_HASH_BYTES]);

#endif // KECCAK256_AVX_H
