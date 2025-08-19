// gcc -O3 -march=native -mavx2 -flto -funroll-loops -fomit-frame-pointer -fopenmp keccak_avx2.c keccak_avx2_test.c -o keccak_avx2_test
// gcc -O3 -mavx2 keccak_avx2.c keccak_avx2_test.c -o keccak_avx2_test
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "keccak_avx2.h"

#define NTEST 3

static const char *msgs[NTEST] = {"", "abc", "200 x 0xA3"};
static unsigned char *inputs[NTEST];
static size_t inlens[NTEST];

static void init_test_vectors() {
    // "" (empty)
    inputs[0] = (unsigned char*)"";
    inlens[0] = 0;

    // "abc"
    inputs[1] = (unsigned char*)"abc";
    inlens[1] = 3;

    // 200 * 0xA3
    inputs[2] = (unsigned char*)malloc(200); 
    memset(inputs[2], 0xA3, 200);
    inlens[2] = 200;
}

static void free_test_vectors() {
    free(inputs[2]); // only the malloc one
}

static void test_single(const char *name, void (*fn)(const unsigned char*, size_t, unsigned char*), size_t outlen) {
    unsigned char out[64]; // up to 512 bits
    printf("%s correctness:\n", name);
    for (int i = 0; i < NTEST; i++) {
        fn(inputs[i], inlens[i], out);
        printf("  %-12s : ", msgs[i]);
        for (size_t j = 0; j < outlen; j++) printf("%02x", out[j]);
        printf("\n");
    }
    // throughput
    size_t msglen = 1024*1024; // 1MB
    unsigned char *bigmsg = (unsigned char*)malloc(msglen); 
    memset(bigmsg, 0xA5, msglen);
    clock_t t0 = clock();
    for (int i = 0; i < 50; i++) fn(bigmsg, msglen, out);
    clock_t t1 = clock();
    double sec = (double)(t1 - t0) / CLOCKS_PER_SEC;
    double mbps = (50.0 * msglen) / (1024*1024) / sec;
    printf("  throughput: %.2f MB/s\n\n", mbps);
    free(bigmsg);
}

static void test_8x(const char *name, void (*fn)(const unsigned char**, const size_t*, unsigned char**), size_t outlen) {
    unsigned char outs[8][64];
    const unsigned char *in8[8];
    size_t lens8[8];
    unsigned char *out8[8];

    printf("%s correctness:\n", name);
    for (int j = 0; j < NTEST; j++) {
        for (int i = 0; i < 8; i++) {
            in8[i] = inputs[j];
            lens8[i] = inlens[j];
            out8[i] = outs[i];
        }
        fn(in8, lens8, out8);
        int ok = 1;
        for (int i = 1; i < 8; i++) {
            if (memcmp(outs[0], outs[i], outlen) != 0) { ok = 0; break; }
        }
        printf("  %-12s : %s\n", msgs[j], ok ? "OK" : "FAIL");
    }
    // throughput
    size_t msglen = 1024*1024;
    unsigned char *bigmsg = (unsigned char*)malloc(msglen); 
    memset(bigmsg, 0xA5, msglen);
    for (int i = 0; i < 8; i++) { in8[i] = bigmsg; lens8[i] = msglen; out8[i] = outs[i]; }
    clock_t t0 = clock();
    for (int i = 0; i < 50; i++) fn(in8, lens8, out8);
    clock_t t1 = clock();
    double sec = (double)(t1 - t0) / CLOCKS_PER_SEC;
    double mbps = (50.0 * msglen * 8) / (1024*1024) / sec;
    printf("  throughput: %.2f MB/s (8 msgs)\n\n", mbps);
    free(bigmsg);
}

int main() {
    init_test_vectors();

    printf("==== Single keccak ====\n");
    test_single("keccak-224", keccak_224, KECCAK_224_DIGEST_LENGTH);
    test_single("keccak-256", keccak_256, KECCAK_256_DIGEST_LENGTH);
    test_single("keccak-384", keccak_384, KECCAK_384_DIGEST_LENGTH);
    test_single("keccak-512", keccak_512, KECCAK_512_DIGEST_LENGTH);

    printf("==== AVX2 8x keccak ====\n");
    test_8x("keccak-224 8x", keccak_8x_224, KECCAK_224_DIGEST_LENGTH);
    test_8x("keccak-256 8x", keccak_8x_256, KECCAK_256_DIGEST_LENGTH);
    test_8x("keccak-384 8x", keccak_8x_384, KECCAK_384_DIGEST_LENGTH);
    test_8x("keccak-512 8x", keccak_8x_512, KECCAK_512_DIGEST_LENGTH);

    free_test_vectors();
    return 0;
}
