/* sha1_avx2.c
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
#include "sha1_avx2.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// ==                                                                        ==
// ==                Basic version (SCALAR) implementation                   ==
// ==                                                                        ==
// ============================================================================
static inline uint32_t RotateLeft(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// Helper macros to simplify code
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define Parity(x, y, z) ((x) ^ (y) ^ (z))
#define Maj(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define BIG_ENDIAN_32(p) ( \
    ((uint32_t)((p)[0]) << 24) | \
    ((uint32_t)((p)[1]) << 16) | \
    ((uint32_t)((p)[2]) <<  8) | \
    ((uint32_t)((p)[3])      )   )

// Expanded SHA1 core conversion function
static void SHA1_Transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t a, b, c, d, e;
    uint32_t W[80];
    uint32_t temp;

    // --- 1. Message Schedule  ---
    W[ 0] = BIG_ENDIAN_32(block +  0);
    W[ 1] = BIG_ENDIAN_32(block +  4);
    W[ 2] = BIG_ENDIAN_32(block +  8);
    W[ 3] = BIG_ENDIAN_32(block + 12);
    W[ 4] = BIG_ENDIAN_32(block + 16);
    W[ 5] = BIG_ENDIAN_32(block + 20);
    W[ 6] = BIG_ENDIAN_32(block + 24);
    W[ 7] = BIG_ENDIAN_32(block + 28);
    W[ 8] = BIG_ENDIAN_32(block + 32);
    W[ 9] = BIG_ENDIAN_32(block + 36);
    W[10] = BIG_ENDIAN_32(block + 40);
    W[11] = BIG_ENDIAN_32(block + 44);
    W[12] = BIG_ENDIAN_32(block + 48);
    W[13] = BIG_ENDIAN_32(block + 52);
    W[14] = BIG_ENDIAN_32(block + 56);
    W[15] = BIG_ENDIAN_32(block + 60);

    W[16] = ROL(W[13] ^ W[8] ^ W[2] ^ W[0], 1);
    W[17] = ROL(W[14] ^ W[9] ^ W[3] ^ W[1], 1);
    W[18] = ROL(W[15] ^ W[10] ^ W[4] ^ W[2], 1);
    W[19] = ROL(W[16] ^ W[11] ^ W[5] ^ W[3], 1);
    W[20] = ROL(W[17] ^ W[12] ^ W[6] ^ W[4], 1);
    W[21] = ROL(W[18] ^ W[13] ^ W[7] ^ W[5], 1);
    W[22] = ROL(W[19] ^ W[14] ^ W[8] ^ W[6], 1);
    W[23] = ROL(W[20] ^ W[15] ^ W[9] ^ W[7], 1);
    W[24] = ROL(W[21] ^ W[16] ^ W[10] ^ W[8], 1);
    W[25] = ROL(W[22] ^ W[17] ^ W[11] ^ W[9], 1);
    W[26] = ROL(W[23] ^ W[18] ^ W[12] ^ W[10], 1);
    W[27] = ROL(W[24] ^ W[19] ^ W[13] ^ W[11], 1);
    W[28] = ROL(W[25] ^ W[20] ^ W[14] ^ W[12], 1);
    W[29] = ROL(W[26] ^ W[21] ^ W[15] ^ W[13], 1);
    W[30] = ROL(W[27] ^ W[22] ^ W[16] ^ W[14], 1);
    W[31] = ROL(W[28] ^ W[23] ^ W[17] ^ W[15], 1);
    W[32] = ROL(W[29] ^ W[24] ^ W[18] ^ W[16], 1);
    W[33] = ROL(W[30] ^ W[25] ^ W[19] ^ W[17], 1);
    W[34] = ROL(W[31] ^ W[26] ^ W[20] ^ W[18], 1);
    W[35] = ROL(W[32] ^ W[27] ^ W[21] ^ W[19], 1);
    W[36] = ROL(W[33] ^ W[28] ^ W[22] ^ W[20], 1);
    W[37] = ROL(W[34] ^ W[29] ^ W[23] ^ W[21], 1);
    W[38] = ROL(W[35] ^ W[30] ^ W[24] ^ W[22], 1);
    W[39] = ROL(W[36] ^ W[31] ^ W[25] ^ W[23], 1);
    W[40] = ROL(W[37] ^ W[32] ^ W[26] ^ W[24], 1);
    W[41] = ROL(W[38] ^ W[33] ^ W[27] ^ W[25], 1);
    W[42] = ROL(W[39] ^ W[34] ^ W[28] ^ W[26], 1);
    W[43] = ROL(W[40] ^ W[35] ^ W[29] ^ W[27], 1);
    W[44] = ROL(W[41] ^ W[36] ^ W[30] ^ W[28], 1);
    W[45] = ROL(W[42] ^ W[37] ^ W[31] ^ W[29], 1);
    W[46] = ROL(W[43] ^ W[38] ^ W[32] ^ W[30], 1);
    W[47] = ROL(W[44] ^ W[39] ^ W[33] ^ W[31], 1);
    W[48] = ROL(W[45] ^ W[40] ^ W[34] ^ W[32], 1);
    W[49] = ROL(W[46] ^ W[41] ^ W[35] ^ W[33], 1);
    W[50] = ROL(W[47] ^ W[42] ^ W[36] ^ W[34], 1);
    W[51] = ROL(W[48] ^ W[43] ^ W[37] ^ W[35], 1);
    W[52] = ROL(W[49] ^ W[44] ^ W[38] ^ W[36], 1);
    W[53] = ROL(W[50] ^ W[45] ^ W[39] ^ W[37], 1);
    W[54] = ROL(W[51] ^ W[46] ^ W[40] ^ W[38], 1);
    W[55] = ROL(W[52] ^ W[47] ^ W[41] ^ W[39], 1);
    W[56] = ROL(W[53] ^ W[48] ^ W[42] ^ W[40], 1);
    W[57] = ROL(W[54] ^ W[49] ^ W[43] ^ W[41], 1);
    W[58] = ROL(W[55] ^ W[50] ^ W[44] ^ W[42], 1);
    W[59] = ROL(W[56] ^ W[51] ^ W[45] ^ W[43], 1);
    W[60] = ROL(W[57] ^ W[52] ^ W[46] ^ W[44], 1);
    W[61] = ROL(W[58] ^ W[53] ^ W[47] ^ W[45], 1);
    W[62] = ROL(W[59] ^ W[54] ^ W[48] ^ W[46], 1);
    W[63] = ROL(W[60] ^ W[55] ^ W[49] ^ W[47], 1);
    W[64] = ROL(W[61] ^ W[56] ^ W[50] ^ W[48], 1);
    W[65] = ROL(W[62] ^ W[57] ^ W[51] ^ W[49], 1);
    W[66] = ROL(W[63] ^ W[58] ^ W[52] ^ W[50], 1);
    W[67] = ROL(W[64] ^ W[59] ^ W[53] ^ W[51], 1);
    W[68] = ROL(W[65] ^ W[60] ^ W[54] ^ W[52], 1);
    W[69] = ROL(W[66] ^ W[61] ^ W[55] ^ W[53], 1);
    W[70] = ROL(W[67] ^ W[62] ^ W[56] ^ W[54], 1);
    W[71] = ROL(W[68] ^ W[63] ^ W[57] ^ W[55], 1);
    W[72] = ROL(W[69] ^ W[64] ^ W[58] ^ W[56], 1);
    W[73] = ROL(W[70] ^ W[65] ^ W[59] ^ W[57], 1);
    W[74] = ROL(W[71] ^ W[66] ^ W[60] ^ W[58], 1);
    W[75] = ROL(W[72] ^ W[67] ^ W[61] ^ W[59], 1);
    W[76] = ROL(W[73] ^ W[68] ^ W[62] ^ W[60], 1);
    W[77] = ROL(W[74] ^ W[69] ^ W[63] ^ W[61], 1);
    W[78] = ROL(W[75] ^ W[70] ^ W[64] ^ W[62], 1);
    W[79] = ROL(W[76] ^ W[71] ^ W[65] ^ W[63], 1);

    // Copy the initial state
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    // --- 2. 80 rounds of calculation ---

    // 回合 0-19
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 0] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 1] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 2] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 3] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 4] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 5] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 6] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 7] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 8] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[ 9] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[10] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[11] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[12] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[13] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[14] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[15] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[16] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[17] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[18] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Ch(b, c, d) + e + W[19] + 0x5A827999; e = d; d = c; c = ROL(b, 30); b = a; a = temp;

    // Rounds 20-39
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[20] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[21] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[22] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[23] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[24] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[25] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[26] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[27] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[28] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[29] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[30] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[31] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[32] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[33] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[34] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[35] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[36] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[37] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[38] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[39] + 0x6ED9EBA1; e = d; d = c; c = ROL(b, 30); b = a; a = temp;

    // Rounds 40-59
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[40] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[41] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[42] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[43] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[44] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[45] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[46] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[47] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[48] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[49] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[50] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[51] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[52] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[53] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[54] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[55] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[56] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[57] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[58] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Maj(b, c, d) + e + W[59] + 0x8F1BBCDC; e = d; d = c; c = ROL(b, 30); b = a; a = temp;

    // Rounds 60-79
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[60] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[61] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[62] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[63] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[64] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[65] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[66] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[67] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[68] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[69] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[70] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[71] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[72] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[73] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[74] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[75] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[76] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[77] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[78] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    temp = ROL(a, 5) + Parity(b, c, d) + e + W[79] + 0xCA62C1D6; e = d; d = c; c = ROL(b, 30); b = a; a = temp;

    // --- 3. Update final status ---
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}


void SHA1_Init(SHA1_CTX *ctx) {
    ctx->bit_count = 0;
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void SHA1_Update(SHA1_CTX *ctx, const uint8_t *input, size_t len) {
    if (len == 0) return;
    size_t left = (ctx->bit_count >> 3) & 0x3F;
    size_t fill = 64 - left;
    ctx->bit_count += (uint64_t)len << 3;
    if (left > 0 && len >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        SHA1_Transform(ctx->state, ctx->buffer);
        input += fill; 
        len   -= fill; 
        left = 0;
    }
    while (len >= 64) {
        SHA1_Transform(ctx->state, input);
        input += 64;
        len   -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buffer + left, input, len);
    }
}

void SHA1_Final(SHA1_CTX *ctx, uint8_t digest[20]) {
    uint8_t bits[8]; uint64_t bit_count = ctx->bit_count;
    for (int i = 0; i < 8; i++) { bits[7 - i] = (uint8_t)(bit_count >> (i * 8)); }
    size_t index = (size_t)((ctx->bit_count >> 3) & 0x3F);
    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        while (index < 64) { ctx->buffer[index++] = 0; }
        SHA1_Transform(ctx->state, ctx->buffer);
        index = 0;
    }
    while (index < 56) { ctx->buffer[index++] = 0; }
    memcpy(&ctx->buffer[56], bits, 8);
    SHA1_Transform(ctx->state, ctx->buffer);
    for (int i = 0; i < 5; i++) {
        digest[i*4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        digest[i*4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
    memset(ctx, 0, sizeof(SHA1_CTX));
}
void PrintSHA1(const uint8_t hash[20]) {
    for (int i = 0; i < 20; i++) { printf("%02x", hash[i]); }
}

// ============================================================================
// ==                   AVX2 batch implementation                            ==
// ============================================================================

static const uint8_t BSWAP_MASK_DATA[32] __attribute__((aligned(32))) = {
    3, 2, 1, 0,   7, 6, 5, 4,   11, 10, 9, 8,   15, 14, 13, 12,
    3, 2, 1, 0,   7, 6, 5, 4,   11, 10, 9, 8,   15, 14, 13, 12
};

typedef union { uint32_t c[8]; __m256i v; } m256i_const_t;
#define K_INIT(val) { {val, val, val, val, val, val, val, val} }

static const m256i_const_t KVec[4] __attribute__((aligned(32))) = {
    K_INIT(0x5A827999), K_INIT(0x6ED9EBA1), K_INIT(0x8F1BBCDC), K_INIT(0xCA62C1D6)
};

// AVX2 helper functions and macros
#define Ch_avx2(x, y, z) _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define Maj_avx2(x, y, z) _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x,y), _mm256_and_si256(x,z)), _mm256_and_si256(y,z))
#define Parity_avx2(x, y, z) _mm256_xor_si256(x, _mm256_xor_si256(y, z))

static inline __m256i RotateLeft_avx2(__m256i x, const int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

// Split nested addition into sequential addition
#define F_00_19(a, b, c, d, e, i) \
{ \
    __m256i temp = RotateLeft_avx2(a, 5); \
    temp = _mm256_add_epi32(temp, Ch_avx2(b, c, d)); \
    temp = _mm256_add_epi32(temp, W[i&15]); \
    temp = _mm256_add_epi32(temp, KVec[0].v); \
    e = _mm256_add_epi32(e, temp); \
    b = RotateLeft_avx2(b, 30); \
}

// Rounds 16-19 still use the Ch function
#define F_16_19(a, b, c, d, e, i) \
{ \
    W[i&15] = RotateLeft_avx2(_mm256_xor_si256(_mm256_xor_si256(W[(i-3)&15], W[(i-8)&15]), _mm256_xor_si256(W[(i-14)&15], W[(i-16)&15])), 1); \
    __m256i temp = RotateLeft_avx2(a, 5); \
    temp = _mm256_add_epi32(temp, Ch_avx2(b, c, d)); \
    temp = _mm256_add_epi32(temp, W[i&15]); \
    temp = _mm256_add_epi32(temp, KVec[0].v); \
    e = _mm256_add_epi32(e, temp); \
    b = RotateLeft_avx2(b, 30); \
}

#define F_20_39(a, b, c, d, e, i) \
{ \
    W[i&15] = RotateLeft_avx2(_mm256_xor_si256(_mm256_xor_si256(W[(i-3)&15], W[(i-8)&15]), _mm256_xor_si256(W[(i-14)&15], W[(i-16)&15])), 1); \
    __m256i temp = RotateLeft_avx2(a, 5); \
    temp = _mm256_add_epi32(temp, Parity_avx2(b, c, d)); \
    temp = _mm256_add_epi32(temp, W[i&15]); \
    temp = _mm256_add_epi32(temp, KVec[1].v); \
    e = _mm256_add_epi32(e, temp); \
    b = RotateLeft_avx2(b, 30); \
}

#define F_40_59(a, b, c, d, e, i) \
{ \
    W[i&15] = RotateLeft_avx2(_mm256_xor_si256(_mm256_xor_si256(W[(i-3)&15], W[(i-8)&15]), _mm256_xor_si256(W[(i-14)&15], W[(i-16)&15])), 1); \
    __m256i temp = RotateLeft_avx2(a, 5); \
    temp = _mm256_add_epi32(temp, Maj_avx2(b, c, d)); \
    temp = _mm256_add_epi32(temp, W[i&15]); \
    temp = _mm256_add_epi32(temp, KVec[2].v); \
    e = _mm256_add_epi32(e, temp); \
    b = RotateLeft_avx2(b, 30); \
}

#define F_60_79(a, b, c, d, e, i) \
{ \
    W[i&15] = RotateLeft_avx2(_mm256_xor_si256(_mm256_xor_si256(W[(i-3)&15], W[(i-8)&15]), _mm256_xor_si256(W[(i-14)&15], W[(i-16)&15])), 1); \
    __m256i temp = RotateLeft_avx2(a, 5); \
    temp = _mm256_add_epi32(temp, Parity_avx2(b, c, d)); \
    temp = _mm256_add_epi32(temp, W[i&15]); \
    temp = _mm256_add_epi32(temp, KVec[3].v); \
    e = _mm256_add_epi32(e, temp); \
    b = RotateLeft_avx2(b, 30); \
}

//  AVX2 core conversion functions
static void Transform_avx2(__m256i state[5], const uint8_t blocks[SHA1_AVX2_LANES][64]) {
    const __m256i BSWAP_MASK = _mm256_load_si256((const __m256i*)BSWAP_MASK_DATA);
    
    __m256i h[5];
    h[0] = state[0]; h[1] = state[1]; h[2] = state[2]; h[3] = state[3]; h[4] = state[4];

    __m256i a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    __m256i W[16] __attribute__((aligned(32)));

    // Preprocessing W[0-14]
    for (int i = 0; i < 15; ++i) {
        __m256i M = _mm256_set_epi32(
            *(const uint32_t*)&blocks[7][i*4], *(const uint32_t*)&blocks[6][i*4],
            *(const uint32_t*)&blocks[5][i*4], *(const uint32_t*)&blocks[4][i*4],
            *(const uint32_t*)&blocks[3][i*4], *(const uint32_t*)&blocks[2][i*4],
            *(const uint32_t*)&blocks[1][i*4], *(const uint32_t*)&blocks[0][i*4]
        );
        W[i] = _mm256_shuffle_epi8(M, BSWAP_MASK);
    }
    
    // Individual treatment W[15] Loading
    __m256i M15 = _mm256_set_epi32(
            *(const uint32_t*)&blocks[7][15*4], *(const uint32_t*)&blocks[6][15*4],
            *(const uint32_t*)&blocks[5][15*4], *(const uint32_t*)&blocks[4][15*4],
            *(const uint32_t*)&blocks[3][15*4], *(const uint32_t*)&blocks[2][15*4],
            *(const uint32_t*)&blocks[1][15*4], *(const uint32_t*)&blocks[0][15*4]
    );
    W[15] = _mm256_shuffle_epi8(M15, BSWAP_MASK);


    // 80 rounds of pipelined 
    F_00_19(a, b, c, d, e,  0); F_00_19(e, a, b, c, d,  1); F_00_19(d, e, a, b, c,  2); F_00_19(c, d, e, a, b,  3); F_00_19(b, c, d, e, a,  4);
    F_00_19(a, b, c, d, e,  5); F_00_19(e, a, b, c, d,  6); F_00_19(d, e, a, b, c,  7); F_00_19(c, d, e, a, b,  8); F_00_19(b, c, d, e, a,  9);
    F_00_19(a, b, c, d, e, 10); F_00_19(e, a, b, c, d, 11); F_00_19(d, e, a, b, c, 12); F_00_19(c, d, e, a, b, 13); F_00_19(b, c, d, e, a, 14);
    F_00_19(a, b, c, d, e, 15);

    F_16_19(e, a, b, c, d, 16); F_16_19(d, e, a, b, c, 17); F_16_19(c, d, e, a, b, 18); F_16_19(b, c, d, e, a, 19);

    F_20_39(a, b, c, d, e, 20); F_20_39(e, a, b, c, d, 21); F_20_39(d, e, a, b, c, 22); F_20_39(c, d, e, a, b, 23); F_20_39(b, c, d, e, a, 24);
    F_20_39(a, b, c, d, e, 25); F_20_39(e, a, b, c, d, 26); F_20_39(d, e, a, b, c, 27); F_20_39(c, d, e, a, b, 28); F_20_39(b, c, d, e, a, 29);
    F_20_39(a, b, c, d, e, 30); F_20_39(e, a, b, c, d, 31); F_20_39(d, e, a, b, c, 32); F_20_39(c, d, e, a, b, 33); F_20_39(b, c, d, e, a, 34);
    F_20_39(a, b, c, d, e, 35); F_20_39(e, a, b, c, d, 36); F_20_39(d, e, a, b, c, 37); F_20_39(c, d, e, a, b, 38); F_20_39(b, c, d, e, a, 39);

    F_40_59(a, b, c, d, e, 40); F_40_59(e, a, b, c, d, 41); F_40_59(d, e, a, b, c, 42); F_40_59(c, d, e, a, b, 43); F_40_59(b, c, d, e, a, 44);
    F_40_59(a, b, c, d, e, 45); F_40_59(e, a, b, c, d, 46); F_40_59(d, e, a, b, c, 47); F_40_59(c, d, e, a, b, 48); F_40_59(b, c, d, e, a, 49);
    F_40_59(a, b, c, d, e, 50); F_40_59(e, a, b, c, d, 51); F_40_59(d, e, a, b, c, 52); F_40_59(c, d, e, a, b, 53); F_40_59(b, c, d, e, a, 54);
    F_40_59(a, b, c, d, e, 55); F_40_59(e, a, b, c, d, 56); F_40_59(d, e, a, b, c, 57); F_40_59(c, d, e, a, b, 58); F_40_59(b, c, d, e, a, 59);

    F_60_79(a, b, c, d, e, 60); F_60_79(e, a, b, c, d, 61); F_60_79(d, e, a, b, c, 62); F_60_79(c, d, e, a, b, 63); F_60_79(b, c, d, e, a, 64);
    F_60_79(a, b, c, d, e, 65); F_60_79(e, a, b, c, d, 66); F_60_79(d, e, a, b, c, 67); F_60_79(c, d, e, a, b, 68); F_60_79(b, c, d, e, a, 69);
    F_60_79(a, b, c, d, e, 70); F_60_79(e, a, b, c, d, 71); F_60_79(d, e, a, b, c, 72); F_60_79(c, d, e, a, b, 73); F_60_79(b, c, d, e, a, 74);
    F_60_79(a, b, c, d, e, 75); F_60_79(e, a, b, c, d, 76); F_60_79(d, e, a, b, c, 77); F_60_79(c, d, e, a, b, 78); F_60_79(b, c, d, e, a, 79);

    state[0] = _mm256_add_epi32(h[0], a);
    state[1] = _mm256_add_epi32(h[1], b);
    state[2] = _mm256_add_epi32(h[2], c);
    state[3] = _mm256_add_epi32(h[3], d);
    state[4] = _mm256_add_epi32(h[4], e);
}


void SHA1BatchInit(SHA1_CTX_AVX2 *ctx) {
    ctx->state[0] = _mm256_set1_epi32(0x67452301);
    ctx->state[1] = _mm256_set1_epi32(0xefcdab89);
    ctx->state[2] = _mm256_set1_epi32(0x98badcfe);
    ctx->state[3] = _mm256_set1_epi32(0x10325476);
    ctx->state[4] = _mm256_set1_epi32(0xC3D2E1F0);
    ctx->active_mask = 0;
    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        ctx->bit_count[i] = 0;
        ctx->buffer_len[i] = 0;
    }
}


void SHA1BatchUpdate(SHA1_CTX_AVX2 *ctx, const uint8_t *data[], const size_t lens[]) {
    size_t data_pos[SHA1_AVX2_LANES] = {0};
    uint8_t current_batch[SHA1_AVX2_LANES][64] __attribute__((aligned(32)));

    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        if (data[i] != NULL) {
            ctx->active_mask |= (1 << i);
            if (lens[i] > 0) { 
                ctx->bit_count[i] += (uint64_t)lens[i] << 3;
            }
        }
    }

    while (1) {
        int can_form_batch = 0;
        for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
            if (!((ctx->active_mask >> i) & 1)) continue;
            if (ctx->buffer_len[i] + (lens[i] - data_pos[i]) >= 64) {
                can_form_batch = 1; break;
            }
        }
        if (!can_form_batch) break;

        uint8_t transform_mask = 0;
        for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
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

        __m256i old_state[5];
        if (transform_mask != 0xFF) {
            for(int i=0; i<5; ++i) old_state[i] = ctx->state[i];
        }

        Transform_avx2(ctx->state, (const uint8_t(*)[64])current_batch);

        if (transform_mask != 0xFF) {
             __m256i mask = _mm256_cmpeq_epi32(
                 _mm256_set_epi32(
                     (transform_mask >> 7) & 1 ? -1 : 0, (transform_mask >> 6) & 1 ? -1 : 0,
                     (transform_mask >> 5) & 1 ? -1 : 0, (transform_mask >> 4) & 1 ? -1 : 0,
                     (transform_mask >> 3) & 1 ? -1 : 0, (transform_mask >> 2) & 1 ? -1 : 0,
                     (transform_mask >> 1) & 1 ? -1 : 0, (transform_mask >> 0) & 1 ? -1 : 0
                 ),_mm256_set1_epi32(-1));
            for(int i=0; i<5; ++i) {
                ctx->state[i] = _mm256_blendv_epi8(old_state[i], ctx->state[i], mask);
            }
        }
    }

    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        if (!((ctx->active_mask >> i) & 1)) continue;
        size_t remaining = lens[i] - data_pos[i];
        if (remaining > 0) {
            memcpy(ctx->buffer[i] + ctx->buffer_len[i], data[i] + data_pos[i], remaining);
            ctx->buffer_len[i] += remaining;
        }
    }
}

void SHA1BatchFinal(SHA1_CTX_AVX2 *ctx, uint8_t digests[SHA1_AVX2_LANES][20]) {
    uint32_t scalar_states[SHA1_AVX2_LANES][5];
    for (int i = 0; i < 5; ++i) {
        uint32_t t[8] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i*)t, ctx->state[i]);
        for (int j = 0; j < SHA1_AVX2_LANES; ++j) {
            scalar_states[j][i] = t[j];
        }
    }

    for (int i = 0; i < SHA1_AVX2_LANES; ++i) {
        if (!((ctx->active_mask >> i) & 1)) {
            memset(digests[i], 0, 20); continue;
        }
        SHA1_CTX s_ctx;
        SHA1_Init(&s_ctx);
        memcpy(s_ctx.state, scalar_states[i], 20); 
        s_ctx.bit_count = ctx->bit_count[i] - (ctx->buffer_len[i] << 3);
        
        SHA1_Update(&s_ctx, ctx->buffer[i], ctx->buffer_len[i]);
        SHA1_Final(&s_ctx, digests[i]);
    }
}
