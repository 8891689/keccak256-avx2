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
#include "sha3_avx2.h"
#include <string.h>
#include <immintrin.h>
#include <x86intrin.h>
#include <stdio.h>
#include <stdlib.h>

// -------------------- Basic implementation --------------------

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

const uint64_t keccakf_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

const int keccakf_rotc[24] = {
    1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44
};

const int keccakf_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1
};

static void keccakf(uint64_t state[25]) {
    
    uint64_t s00 = state[0],  s01 = state[1],  s02 = state[2],  s03 = state[3],  s04 = state[4];
    uint64_t s10 = state[5],  s11 = state[6],  s12 = state[7],  s13 = state[8],  s14 = state[9];
    uint64_t s20 = state[10], s21 = state[11], s22 = state[12], s23 = state[13], s24 = state[14];
    uint64_t s30 = state[15], s31 = state[16], s32 = state[17], s33 = state[18], s34 = state[19];
    uint64_t s40 = state[20], s41 = state[21], s42 = state[22], s43 = state[23], s44 = state[24];
    
    uint64_t C0, C1, C2, C3, C4, D0, D1, D2, D3, D4;

    for (int round = 0; round < 24; ++round) {
        // --- Theta step ---
        C0 = s00 ^ s10 ^ s20 ^ s30 ^ s40;
        C1 = s01 ^ s11 ^ s21 ^ s31 ^ s41;
        C2 = s02 ^ s12 ^ s22 ^ s32 ^ s42;
        C3 = s03 ^ s13 ^ s23 ^ s33 ^ s43;
        C4 = s04 ^ s14 ^ s24 ^ s34 ^ s44;

        D0 = C4 ^ rotl64(C1, 1);
        D1 = C0 ^ rotl64(C2, 1);
        D2 = C1 ^ rotl64(C3, 1);
        D3 = C2 ^ rotl64(C4, 1);
        D4 = C3 ^ rotl64(C0, 1);

        s00 ^= D0; s10 ^= D0; s20 ^= D0; s30 ^= D0; s40 ^= D0;
        s01 ^= D1; s11 ^= D1; s21 ^= D1; s31 ^= D1; s41 ^= D1;
        s02 ^= D2; s12 ^= D2; s22 ^= D2; s32 ^= D2; s42 ^= D2;
        s03 ^= D3; s13 ^= D3; s23 ^= D3; s33 ^= D3; s43 ^= D3;
        s04 ^= D4; s14 ^= D4; s24 ^= D4; s34 ^= D4; s44 ^= D4;

        // --- Rho and Pi steps  ---
        {
            uint64_t ns01, ns02, ns03, ns04;
            uint64_t ns10, ns11, ns12, ns13, ns14;
            uint64_t ns20, ns21, ns22, ns23, ns24;
            uint64_t ns30, ns31, ns32, ns33, ns34;
            uint64_t ns40, ns41, ns42, ns43, ns44;
            uint64_t current = s01; 

            // keccakf_piln, keccakf_rotc 
            ns20 = rotl64(current, 1);  current = s20; //piln[0]=10, rotc[0]=1
            ns12 = rotl64(current, 3);  current = s12; //piln[1]=7,  rotc[1]=3
            ns21 = rotl64(current, 6);  current = s21; //piln[2]=11, rotc[2]=6
            ns32 = rotl64(current, 10); current = s32; //piln[3]=17, rotc[3]=10
            ns33 = rotl64(current, 15); current = s33; //piln[4]=18, rotc[4]=15
            ns03 = rotl64(current, 21); current = s03; //piln[5]=3,  rotc[5]=21
            ns10 = rotl64(current, 28); current = s10; //piln[6]=5,  rotc[6]=28
            ns31 = rotl64(current, 36); current = s31; //piln[7]=16, rotc[7]=36
            ns13 = rotl64(current, 45); current = s13; //piln[8]=8,  rotc[8]=45
            ns41 = rotl64(current, 55); current = s41; //piln[9]=21, rotc[9]=55
            ns44 = rotl64(current, 2);  current = s44; //piln[10]=24,rotc[10]=2
            ns04 = rotl64(current, 14); current = s04; //piln[11]=4, rotc[11]=14
            ns30 = rotl64(current, 27); current = s30; //piln[12]=15,rotc[12]=27
            ns43 = rotl64(current, 41); current = s43; //piln[13]=23,rotc[13]=41
            ns34 = rotl64(current, 56); current = s34; //piln[14]=19,rotc[14]=56
            ns23 = rotl64(current, 8);  current = s23; //piln[15]=13,rotc[15]=8
            ns22 = rotl64(current, 25); current = s22; //piln[16]=12,rotc[16]=25
            ns02 = rotl64(current, 43); current = s02; //piln[17]=2, rotc[17]=43
            ns40 = rotl64(current, 62); current = s40; //piln[18]=20,rotc[18]=62
            ns24 = rotl64(current, 18); current = s24; //piln[19]=14,rotc[19]=18
            ns42 = rotl64(current, 39); current = s42; //piln[20]=22,rotc[20]=39
            ns14 = rotl64(current, 61); current = s14; //piln[21]=9, rotc[21]=61
            ns11 = rotl64(current, 20); current = s11; //piln[22]=6, rotc[22]=20
            ns01 = rotl64(current, 44);               //piln[23]=1, rotc[23]=44

            // sXX variables 
            s01=ns01; s02=ns02; s03=ns03; s04=ns04; s10=ns10; s11=ns11; s12=ns12;
            s13=ns13; s14=ns14; s20=ns20; s21=ns21; s22=ns22; s23=ns23; s24=ns24;
            s30=ns30; s31=ns31; s32=ns32; s33=ns33; s34=ns34; s40=ns40; s41=ns41;
            s42=ns42; s43=ns43; s44=ns44;
        }

        // --- Chi step  ---
        C0=s00; C1=s01; s00^=~s01&s02; s01^=~s02&s03; s02^=~s03&s04; s03^=~s04&C0; s04^=~C0&C1;
        C0=s10; C1=s11; s10^=~s11&s12; s11^=~s12&s13; s12^=~s13&s14; s13^=~s14&C0; s14^=~C0&C1;
        C0=s20; C1=s21; s20^=~s21&s22; s21^=~s22&s23; s22^=~s23&s24; s23^=~s24&C0; s24^=~C0&C1;
        C0=s30; C1=s31; s30^=~s31&s32; s31^=~s32&s33; s32^=~s33&s34; s33^=~s34&C0; s34^=~C0&C1;
        C0=s40; C1=s41; s40^=~s41&s42; s41^=~s42&s43; s42^=~s43&s44; s43^=~s44&C0; s44^=~C0&C1;

        // --- Iota step ---
        s00 ^= keccakf_rc[round];
    }
    
    // Write the result back to the status array
    state[0] = s00;   state[1] = s01;   state[2] = s02;   state[3] = s03;   state[4] = s04;
    state[5] = s10;   state[6] = s11;   state[7] = s12;   state[8] = s13;   state[9] = s14;
    state[10] = s20;  state[11] = s21;  state[12] = s22;  state[13] = s23;  state[14] = s24;
    state[15] = s30;  state[16] = s31;  state[17] = s32;  state[18] = s33;  state[19] = s34;
    state[20] = s40;  state[21] = s41;  state[22] = s42;  state[23] = s43;  state[24] = s44;
}

void sha3_init(sha3_ctx *ctx, unsigned int output_length) {
    ctx->rate = 200 - (output_length * 2);
    ctx->output_length = output_length;
    ctx->pos = 0;
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static inline uint64_t load64_le(const unsigned char *p){
    uint64_t data; memcpy(&data, p, sizeof(data)); return data;
}

static inline void store64_le(unsigned char *p, uint64_t v){
    memcpy(p, &v, sizeof(v));
}

void sha3_update(sha3_ctx *ctx, const unsigned char *input, size_t inlen) {
    size_t i = 0;
    while (i < inlen) {
        if (ctx->pos == ctx->rate) {
            for (size_t j = 0; j < ctx->rate / 8; j++) {
                ctx->state[j] ^= load64_le(ctx->buffer + j * 8);
            }
            keccakf(ctx->state);
            ctx->pos = 0;
        }
        size_t to_copy = ctx->rate - ctx->pos;
        if (to_copy > inlen - i) to_copy = inlen - i;
        memcpy(ctx->buffer + ctx->pos, input + i, to_copy);
        ctx->pos += to_copy;
        i += to_copy;
    }
}

void sha3_final(sha3_ctx *ctx, unsigned char *output) {
    memset(ctx->buffer + ctx->pos, 0, ctx->rate - ctx->pos);
    ctx->buffer[ctx->pos] |= 0x06; 
    ctx->buffer[ctx->rate - 1] |= 0x80;
    for (size_t j = 0; j < ctx->rate / 8; j++) {
        ctx->state[j] ^= load64_le(ctx->buffer + j * 8);
    }
    keccakf(ctx->state);
    memcpy(output, ctx->state, ctx->output_length);
}

void sha3_224(const unsigned char *input, size_t inlen, unsigned char *output) {
    sha3_ctx ctx; sha3_init(&ctx, SHA3_224_DIGEST_LENGTH); sha3_update(&ctx, input, inlen); sha3_final(&ctx, output);
}
void sha3_256(const unsigned char *input, size_t inlen, unsigned char *output) {
    sha3_ctx ctx; sha3_init(&ctx, SHA3_256_DIGEST_LENGTH); sha3_update(&ctx, input, inlen); sha3_final(&ctx, output);
}
void sha3_384(const unsigned char *input, size_t inlen, unsigned char *output) {
    sha3_ctx ctx; sha3_init(&ctx, SHA3_384_DIGEST_LENGTH); sha3_update(&ctx, input, inlen); sha3_final(&ctx, output);
}
void sha3_512(const unsigned char *input, size_t inlen, unsigned char *output) {
    sha3_ctx ctx; sha3_init(&ctx, SHA3_512_DIGEST_LENGTH); sha3_update(&ctx, input, inlen); sha3_final(&ctx, output);
}

// -------------------- AVX2 implementation --------------------

static inline __m256i rotl64_4(__m256i x, int n){
    return _mm256_or_si256(_mm256_slli_epi64(x, n), _mm256_srli_epi64(x, 64 - n));
}

#define KECCAK_ROUND_AVX2_DEEP_UNROLL(A, round_index) \
    do { \
        __m256i C[5], D, a0, a1, a2, a3, a4; \
        C[0] = _mm256_xor_si256(_mm256_xor_si256(A[0], A[5]), _mm256_xor_si256(A[10], A[15])); C[0] = _mm256_xor_si256(C[0], A[20]); \
        C[1] = _mm256_xor_si256(_mm256_xor_si256(A[1], A[6]), _mm256_xor_si256(A[11], A[16])); C[1] = _mm256_xor_si256(C[1], A[21]); \
        C[2] = _mm256_xor_si256(_mm256_xor_si256(A[2], A[7]), _mm256_xor_si256(A[12], A[17])); C[2] = _mm256_xor_si256(C[2], A[22]); \
        C[3] = _mm256_xor_si256(_mm256_xor_si256(A[3], A[8]), _mm256_xor_si256(A[13], A[18])); C[3] = _mm256_xor_si256(C[3], A[23]); \
        C[4] = _mm256_xor_si256(_mm256_xor_si256(A[4], A[9]), _mm256_xor_si256(A[14], A[19])); C[4] = _mm256_xor_si256(C[4], A[24]); \
        D = _mm256_xor_si256(C[4], rotl64_4(C[1], 1)); A[0]=_mm256_xor_si256(A[0],D); A[5]=_mm256_xor_si256(A[5],D); A[10]=_mm256_xor_si256(A[10],D); A[15]=_mm256_xor_si256(A[15],D); A[20]=_mm256_xor_si256(A[20],D); \
        D = _mm256_xor_si256(C[0], rotl64_4(C[2], 1)); A[1]=_mm256_xor_si256(A[1],D); A[6]=_mm256_xor_si256(A[6],D); A[11]=_mm256_xor_si256(A[11],D); A[16]=_mm256_xor_si256(A[16],D); A[21]=_mm256_xor_si256(A[21],D); \
        D = _mm256_xor_si256(C[1], rotl64_4(C[3], 1)); A[2]=_mm256_xor_si256(A[2],D); A[7]=_mm256_xor_si256(A[7],D); A[12]=_mm256_xor_si256(A[12],D); A[17]=_mm256_xor_si256(A[17],D); A[22]=_mm256_xor_si256(A[22],D); \
        D = _mm256_xor_si256(C[2], rotl64_4(C[4], 1)); A[3]=_mm256_xor_si256(A[3],D); A[8]=_mm256_xor_si256(A[8],D); A[13]=_mm256_xor_si256(A[13],D); A[18]=_mm256_xor_si256(A[18],D); A[23]=_mm256_xor_si256(A[23],D); \
        D = _mm256_xor_si256(C[3], rotl64_4(C[0], 1)); A[4]=_mm256_xor_si256(A[4],D); A[9]=_mm256_xor_si256(A[9],D); A[14]=_mm256_xor_si256(A[14],D); A[19]=_mm256_xor_si256(A[19],D); A[24]=_mm256_xor_si256(A[24],D); \
        __m256i cur = A[1], t; \
        for (int i = 0; i < 24; i += 4) { \
            int j0=keccakf_piln[i];   t=A[j0]; A[j0]=rotl64_4(cur, keccakf_rotc[i]);   cur=t; \
            int j1=keccakf_piln[i+1]; t=A[j1]; A[j1]=rotl64_4(cur, keccakf_rotc[i+1]); cur=t; \
            int j2=keccakf_piln[i+2]; t=A[j2]; A[j2]=rotl64_4(cur, keccakf_rotc[i+2]); cur=t; \
            int j3=keccakf_piln[i+3]; t=A[j3]; A[j3]=rotl64_4(cur, keccakf_rotc[i+3]); cur=t; \
        } \
        a0=A[0]; a1=A[1]; a2=A[2]; a3=A[3]; a4=A[4]; A[0]=_mm256_xor_si256(a0,_mm256_andnot_si256(a1,a2)); A[1]=_mm256_xor_si256(a1,_mm256_andnot_si256(a2,a3)); A[2]=_mm256_xor_si256(a2,_mm256_andnot_si256(a3,a4)); A[3]=_mm256_xor_si256(a3,_mm256_andnot_si256(a4,a0)); A[4]=_mm256_xor_si256(a4,_mm256_andnot_si256(a0,a1)); \
        a0=A[5]; a1=A[6]; a2=A[7]; a3=A[8]; a4=A[9]; A[5]=_mm256_xor_si256(a0,_mm256_andnot_si256(a1,a2)); A[6]=_mm256_xor_si256(a1,_mm256_andnot_si256(a2,a3)); A[7]=_mm256_xor_si256(a2,_mm256_andnot_si256(a3,a4)); A[8]=_mm256_xor_si256(a3,_mm256_andnot_si256(a4,a0)); A[9]=_mm256_xor_si256(a4,_mm256_andnot_si256(a0,a1)); \
        a0=A[10];a1=A[11];a2=A[12];a3=A[13];a4=A[14];A[10]=_mm256_xor_si256(a0,_mm256_andnot_si256(a1,a2));A[11]=_mm256_xor_si256(a1,_mm256_andnot_si256(a2,a3));A[12]=_mm256_xor_si256(a2,_mm256_andnot_si256(a3,a4));A[13]=_mm256_xor_si256(a3,_mm256_andnot_si256(a4,a0));A[14]=_mm256_xor_si256(a4,_mm256_andnot_si256(a0,a1)); \
        a0=A[15];a1=A[16];a2=A[17];a3=A[18];a4=A[19];A[15]=_mm256_xor_si256(a0,_mm256_andnot_si256(a1,a2));A[16]=_mm256_xor_si256(a1,_mm256_andnot_si256(a2,a3));A[17]=_mm256_xor_si256(a2,_mm256_andnot_si256(a3,a4));A[18]=_mm256_xor_si256(a3,_mm256_andnot_si256(a4,a0));A[19]=_mm256_xor_si256(a4,_mm256_andnot_si256(a0,a1)); \
        a0=A[20];a1=A[21];a2=A[22];a3=A[23];a4=A[24];A[20]=_mm256_xor_si256(a0,_mm256_andnot_si256(a1,a2));A[21]=_mm256_xor_si256(a1,_mm256_andnot_si256(a2,a3));A[22]=_mm256_xor_si256(a2,_mm256_andnot_si256(a3,a4));A[23]=_mm256_xor_si256(a3,_mm256_andnot_si256(a4,a0));A[24]=_mm256_xor_si256(a4,_mm256_andnot_si256(a0,a1)); \
        A[0] = _mm256_xor_si256(A[0], _mm256_set1_epi64x(keccakf_rc[round_index])); \
    } while(0)

static void keccakf_4x(__m256i A[25]){
    for(int round=0; round<24; round+=4){
        KECCAK_ROUND_AVX2_DEEP_UNROLL(A, round);
        KECCAK_ROUND_AVX2_DEEP_UNROLL(A, round + 1);
        KECCAK_ROUND_AVX2_DEEP_UNROLL(A, round + 2);
        KECCAK_ROUND_AVX2_DEEP_UNROLL(A, round + 3);
    }
}

typedef struct {
    __m256i S[25]; unsigned rate; unsigned outlen;
    const unsigned char* in[4]; size_t inlen[4];
} sha3_4x_ctx;

static void sha3_4x_init(sha3_4x_ctx* ctx, unsigned outlen,
                         const unsigned char* in0, size_t len0, const unsigned char* in1, size_t len1,
                         const unsigned char* in2, size_t len2, const unsigned char* in3, size_t len3){
    ctx->rate = 200-(outlen*2); ctx->outlen=outlen;
    ctx->in[0]=in0; ctx->in[1]=in1; ctx->in[2]=in2; ctx->in[3]=in3;
    ctx->inlen[0]=len0; ctx->inlen[1]=len1; ctx->inlen[2]=len2; ctx->inlen[3]=len3;
    for(int i=0;i<25;i++) ctx->S[i]=_mm256_setzero_si256();
}

static inline void absorb_block_4(sha3_4x_ctx* ctx){
    const size_t rwords = ctx->rate >> 3;
    for(size_t i=0;i<rwords;i++){
        __m256i v = _mm256_set_epi64x(
            (long long)load64_le(ctx->in[3]+i*8),(long long)load64_le(ctx->in[2]+i*8),
            (long long)load64_le(ctx->in[1]+i*8),(long long)load64_le(ctx->in[0]+i*8));
        ctx->S[i] = _mm256_xor_si256(ctx->S[i], v);
    }
    for(int lane=0;lane<4;lane++){ctx->in[lane]+=ctx->rate;ctx->inlen[lane]-=ctx->rate;}
    keccakf_4x(ctx->S);
}

// Function prototype
static void sha3_4x_256(const unsigned char* in0, size_t len0, const unsigned char* in1, size_t len1,
                        const unsigned char* in2, size_t len2, const unsigned char* in3, size_t len3,
                        unsigned char* out0, unsigned char* out1, unsigned char* out2, unsigned char* out3);
static void sha3_4x_256_dispatch(const unsigned char** in, const size_t* len, unsigned char** out);


static void sha3_4x_256_dispatch(const unsigned char** in, const size_t* len, unsigned char** out){
    if(!(len[0]==len[1] && len[1]==len[2] && len[2]==len[3])){
        for(int i=0;i<4;i++) sha3_256(in[i], len[i], out[i]);
        return;
    }

    sha3_4x_ctx ctx;
    sha3_4x_init(&ctx, 32, in[0],len[0], in[1],len[1], in[2],len[2], in[3],len[3]);
    while(ctx.inlen[0] >= ctx.rate){ absorb_block_4(&ctx); }

    unsigned char last_block[4][200] __attribute__((aligned(32)));
    memset(last_block, 0, sizeof(last_block));
    
    size_t rem = ctx.inlen[0];
    for(int i=0; i<4; ++i) {
        if(rem) memcpy(last_block[i], ctx.in[i], rem);
        if (rem == ctx.rate - 1) {
            last_block[i][rem] = 0x06 | 0x80;
        } else {
            last_block[i][rem] |= 0x06;
            last_block[i][ctx.rate - 1] |= 0x80;
        }
    }

    const size_t rwords = ctx.rate >> 3;
    for(size_t i=0;i<rwords;i++){
        __m256i v = _mm256_set_epi64x(
            (long long)load64_le(last_block[3]+i*8),(long long)load64_le(last_block[2]+i*8),
            (long long)load64_le(last_block[1]+i*8),(long long)load64_le(last_block[0]+i*8));
        ctx.S[i] = _mm256_xor_si256(ctx.S[i], v);
    }
    keccakf_4x(ctx.S);

    store64_le(out[0]+0, (uint64_t)_mm256_extract_epi64(ctx.S[0], 0)); store64_le(out[0]+8, (uint64_t)_mm256_extract_epi64(ctx.S[1], 0)); store64_le(out[0]+16, (uint64_t)_mm256_extract_epi64(ctx.S[2], 0)); store64_le(out[0]+24, (uint64_t)_mm256_extract_epi64(ctx.S[3], 0));
    store64_le(out[1]+0, (uint64_t)_mm256_extract_epi64(ctx.S[0], 1)); store64_le(out[1]+8, (uint64_t)_mm256_extract_epi64(ctx.S[1], 1)); store64_le(out[1]+16, (uint64_t)_mm256_extract_epi64(ctx.S[2], 1)); store64_le(out[1]+24, (uint64_t)_mm256_extract_epi64(ctx.S[3], 1));
    store64_le(out[2]+0, (uint64_t)_mm256_extract_epi64(ctx.S[0], 2)); store64_le(out[2]+8, (uint64_t)_mm256_extract_epi64(ctx.S[1], 2)); store64_le(out[2]+16, (uint64_t)_mm256_extract_epi64(ctx.S[2], 2)); store64_le(out[2]+24, (uint64_t)_mm256_extract_epi64(ctx.S[3], 2));
    store64_le(out[3]+0, (uint64_t)_mm256_extract_epi64(ctx.S[0], 3)); store64_le(out[3]+8, (uint64_t)_mm256_extract_epi64(ctx.S[1], 3)); store64_le(out[3]+16, (uint64_t)_mm256_extract_epi64(ctx.S[2], 3)); store64_le(out[3]+24, (uint64_t)_mm256_extract_epi64(ctx.S[3], 3));
}

static void sha3_4x_256(const unsigned char* in0, size_t len0, const unsigned char* in1, size_t len1,
                        const unsigned char* in2, size_t len2, const unsigned char* in3, size_t len3,
                        unsigned char* out0, unsigned char* out1, unsigned char* out2, unsigned char* out3){
    const unsigned char* in[4]={in0,in1,in2,in3}; size_t lenv[4]={len0,len1,len2,len3};
    unsigned char* out[4]={out0,out1,out2,out3};
    sha3_4x_256_dispatch(in, lenv, out);
}


// ------------------------------------------------------------------
// Generic 4x dispatcher + 8x wrappers for different output lengths
// ------------------------------------------------------------------

static void sha3_4x_dispatch_generic(const unsigned char** in, const size_t* len, unsigned char** out, unsigned outlen){
    if (!(len[0]==len[1] && len[1]==len[2] && len[2]==len[3])) {
        for (int i = 0; i < 4; i++) {
            switch (outlen) {
                case SHA3_224_DIGEST_LENGTH: sha3_224(in[i], len[i], out[i]); break;
                case SHA3_256_DIGEST_LENGTH: sha3_256(in[i], len[i], out[i]); break;
                case SHA3_384_DIGEST_LENGTH: sha3_384(in[i], len[i], out[i]); break;
                case SHA3_512_DIGEST_LENGTH: sha3_512(in[i], len[i], out[i]); break;
                default: /*fallback*/ sha3_256(in[i], len[i], out[i]); break;
            }
        }
        return;
    }

    sha3_4x_ctx ctx;
    sha3_4x_init(&ctx, outlen,
                 in[0], len[0], in[1], len[1], in[2], len[2], in[3], len[3]);

    while (ctx.inlen[0] >= ctx.rate) { absorb_block_4(&ctx); }

    unsigned char last_block[4][200] __attribute__((aligned(32)));
    memset(last_block, 0, sizeof(last_block));
    size_t rem = ctx.inlen[0];
    for (int i = 0; i < 4; ++i) {
        if (rem) memcpy(last_block[i], ctx.in[i], rem);
        if (rem == ctx.rate - 1) {
            last_block[i][rem] = 0x06 | 0x80;
        } else {
            last_block[i][rem] |= 0x06;
            last_block[i][ctx.rate - 1] |= 0x80;
        }
    }

    const size_t rwords = ctx.rate >> 3;
    for (size_t i = 0; i < rwords; ++i) {
        __m256i v = _mm256_set_epi64x(
            (long long)load64_le(last_block[3] + i*8),
            (long long)load64_le(last_block[2] + i*8),
            (long long)load64_le(last_block[1] + i*8),
            (long long)load64_le(last_block[0] + i*8));
        ctx.S[i] = _mm256_xor_si256(ctx.S[i], v);
    }

    keccakf_4x(ctx.S);

    size_t full_words = outlen / 8;
    size_t rem_bytes = outlen % 8;

    for (int lane = 0; lane < 4; ++lane) {
        // Full 8-byte words
        for (size_t w = 0; w < full_words; ++w) {
            uint64_t val;
            switch (lane) {
                case 0: val = (uint64_t)_mm256_extract_epi64(ctx.S[w], 0); break;
                case 1: val = (uint64_t)_mm256_extract_epi64(ctx.S[w], 1); break;
                case 2: val = (uint64_t)_mm256_extract_epi64(ctx.S[w], 2); break;
                default: val = (uint64_t)_mm256_extract_epi64(ctx.S[w], 3); break;
            }
            store64_le(out[lane] + w*8, val);
        }
        // Less than 8 bytes left
        if (rem_bytes) {
            uint64_t val;
            switch (lane) {
                case 0: val = (uint64_t)_mm256_extract_epi64(ctx.S[full_words], 0); break;
                case 1: val = (uint64_t)_mm256_extract_epi64(ctx.S[full_words], 1); break;
                case 2: val = (uint64_t)_mm256_extract_epi64(ctx.S[full_words], 2); break;
                default: val = (uint64_t)_mm256_extract_epi64(ctx.S[full_words], 3); break;
            }
            memcpy(out[lane] + full_words*8, &val, rem_bytes);
        }
    }
}

// convenience wrapper taking 4 inputs/outputs and an outlen
static void sha3_4x_generic(const unsigned char* in0, size_t len0, const unsigned char* in1, size_t len1,
                            const unsigned char* in2, size_t len2, const unsigned char* in3, size_t len3,
                            unsigned char* out0, unsigned char* out1, unsigned char* out2, unsigned char* out3,
                            unsigned outlen) {
    const unsigned char* in[4] = { in0, in1, in2, in3 };
    size_t lens[4] = { len0, len1, len2, len3 };
    unsigned char* out[4] = { out0, out1, out2, out3 };
    sha3_4x_dispatch_generic(in, lens, out, outlen);
}

// ---------------- 8x wrappers ----------------

void sha3_8x_224(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs){
    sha3_4x_generic(inputs[0], inlens[0], inputs[1], inlens[1], inputs[2], inlens[2], inputs[3], inlens[3],
                    outputs[0], outputs[1], outputs[2], outputs[3], SHA3_224_DIGEST_LENGTH);
    sha3_4x_generic(inputs[4], inlens[4], inputs[5], inlens[5], inputs[6], inlens[6], inputs[7], inlens[7],
                    outputs[4], outputs[5], outputs[6], outputs[7], SHA3_224_DIGEST_LENGTH);
}

void sha3_8x_256(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs){

    sha3_4x_256(inputs[0],inlens[0],inputs[1],inlens[1],inputs[2],inlens[2],inputs[3],inlens[3],
                outputs[0],outputs[1],outputs[2],outputs[3]);
    
    sha3_4x_256(inputs[4],inlens[4],inputs[5],inlens[5],inputs[6],inlens[6],inputs[7],inlens[7],
                outputs[4],outputs[5],outputs[6],outputs[7]);
}

void sha3_8x_384(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs){
    sha3_4x_generic(inputs[0], inlens[0], inputs[1], inlens[1], inputs[2], inlens[2], inputs[3], inlens[3],
                    outputs[0], outputs[1], outputs[2], outputs[3], SHA3_384_DIGEST_LENGTH);
    sha3_4x_generic(inputs[4], inlens[4], inputs[5], inlens[5], inputs[6], inlens[6], inputs[7], inlens[7],
                    outputs[4], outputs[5], outputs[6], outputs[7], SHA3_384_DIGEST_LENGTH);
}

void sha3_8x_512(const unsigned char **inputs, const size_t* inlens, unsigned char **outputs){
    sha3_4x_generic(inputs[0], inlens[0], inputs[1], inlens[1], inputs[2], inlens[2], inputs[3], inlens[3],
                    outputs[0], outputs[1], outputs[2], outputs[3], SHA3_512_DIGEST_LENGTH);
    sha3_4x_generic(inputs[4], inlens[4], inputs[5], inlens[5], inputs[6], inlens[6], inputs[7], inlens[7],
                    outputs[4], outputs[5], outputs[6], outputs[7], SHA3_512_DIGEST_LENGTH);
}



void* aligned_malloc(size_t size, size_t alignment) {
    void *p;
#ifdef _MSC_VER
    p = _aligned_malloc(size, alignment);
#else
    if (posix_memalign(&p, alignment, size)) p = NULL;
#endif
    return p;
}

void aligned_free(void* p) {
#ifdef _MSC_VER
    _aligned_free(p);
#else
    free(p);
#endif
}
