# C/C++ High-performance sha3,224,256,384,512,Keccak-256,md5,sha1 AVX2 implementations

This is a sha3,224,256,384,512,Keccak-256,md5,sha1 hashing library written in C (compatible with C++), designed for extremely fast computations. It is deeply optimized to take advantage of the AVX2 instruction set in modern CPUs.

## Core Advantages

* **Extreme Speed**: Utilizes AVX2 (Advanced Vector Extensions 2.0) technology to significantly accelerate hashing operations.
* **8-Way Parallelism**: The core design supports simultaneous processing of eight different sets of input data, significantly improving the throughput of batch hashing operations.
* **Deep Optimization**: Combines multiple optimization strategies, such as full loop unrolling and instruction-level parallelism, to maximize execution efficiency.
* **Keccak Standard**: Implements the original Keccak padding rule (compatible with the `keccak256` function used by projects such as Ethereum). Please note that this differs slightly from the FIPS 202 SHA3-256 standard; they are different algorithms.

## Applicable Scenarios

* Applications requiring extremely fast SHA3 224, 256, 384, 512, and Keccak-256,md5,sha1 hash calculation speeds.
* Scenarios requiring efficient processing of large numbers of parallel hashing tasks, such as blockchain technology, data verification, and high-performance computing.
* SHA3 224,256,384,512 and md5,sha1 have built-in basic implementations and AVX2-optimized versions, and function interfaces have been left, which can be linked as needed.

## Compilation

```

gcc -O3 -mavx2 -mfma -march=native sha3_avx2.c sha3_avx2_test.c -o sha3_avx2_test

gcc -O3 -mavx2 -mfma -march=native keccak_avx_test.c keccak256_avx.c -o keccak_avx_test

gcc -o md5_avx2_test md5_test_avx2.c md5_avx2.c -O3 -march=native -Wall -mavx2 -flto -fno-trapping-math -fno-math-errno

gcc -o sha1_avx2_test sha1_test_avx2.c sha1_avx2.c -O3 -march=native -Wall -mavx2 -flto -fno-trapping-math -fno-math-errno

```

Testing and Verification

Based on Intel® Xeon® E5-2697 v4 2.30 GHz single-threaded environment

*****************************************************************************************************************************
```
./sha3_avx2_test
==== Single SHA3 ====
SHA3-224 correctness:
               : 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
  abc          : e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf
  200 x 0xA3   : 9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0
  throughput: 123.51 MB/s

SHA3-256 correctness:
               : a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
  abc          : 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
  200 x 0xA3   : 79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787
  throughput: 112.14 MB/s

SHA3-384 correctness:
               : 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
  abc          : ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25
  200 x 0xA3   : 1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f
  throughput: 88.53 MB/s

SHA3-512 correctness:
               : a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
  abc          : b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
  200 x 0xA3   : e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00
  throughput: 84.30 MB/s

==== AVX2 8x SHA3 ====
SHA3-224 8x correctness:
               : OK
  abc          : OK
  200 x 0xA3   : OK
  throughput: 701.93 MB/s (8 msgs)

SHA3-256 8x correctness:
               : OK
  abc          : OK
  200 x 0xA3   : OK
  throughput: 691.61 MB/s (8 msgs)

SHA3-384 8x correctness:
               : OK
  abc          : OK
  200 x 0xA3   : OK
  throughput: 604.68 MB/s (8 msgs)

SHA3-512 8x correctness:
               : OK
  abc          : OK
  200 x 0xA3   : OK
  throughput: 381.07 MB/s (8 msgs)
```
*****************************************************************************************************************************

```
./keccak_avx_test
Calculating Keccak256 of "abc" for all 8 lanes:
Expected Keccak256("abc"): 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 0: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 1: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 2: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 3: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 4: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 5: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 6: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
Lane 7: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
======================================

Starting benchmark for approximately 5.0 seconds...
Each operation processes 136 bytes per lane (1088 bytes total per 8-lane op).

Benchmark finished.
--------------------------------------
Total 8-lane operations:  2962000
Total individual hashes (streams processed): 23696000
Actual wall time taken:   5.0006 seconds
Individual Hashes/sec (streams): 4738608.00
Total data processed:              3073.36 MB
Data processing rate:              614.60 MB/s
======================================
Sample hash from benchmark (Lane 0) after 2962000 operations:
Lane 0: ac0fee99c81a5afe757cd8b1e962a3fe866b29dfbfec586d97feaaf964a202a9
```

*****************************************************************************************************************************

```
./md5_avx2_test

=== MD5 AVX2 High-Performance Benchmark ===
Configuration: 8 independent data streams, each 128.00 MB
Total data size: 1024.00 MB
Number of test iterations: 5

Initializing data streams...Done

Performing warm-up run...Done

=== Scalar Benchmark ===
Average time: 1.9990 seconds
Average throughput: 512.27 MB/s
Throughput per iteration: [512.14, 512.29, 512.24, 512.34, 512.32] MB/s

=== AVX2 Batch Processing Benchmark ===
Average time: 0.5715 seconds
Average throughput: 1791.77 MB/s
Throughput per iteration: [1791.57, 1791.66, 1792.10, 1790.99, 1792.55] MB/s

=== Verification and Comparison ===
✓ Verification successful! All 8 digests match
Speedup: 3.50x

Benchmark finished

```

*****************************************************************************************************************************
```
./sha1_avx2_test
--- Running Correctness Tests ---

--- [Section 1: Scalar Implementation] ---
  Test: Scalar 'abc'
    Result:   a9993e364706816aba3e25717850c26c9cd0d89d
    Expected: a9993e364706816aba3e25717850c26c9cd0d89d
    Status: [PASS]

--- [Section 2: Basic AVX2 Batch] ---
  Test: AVX2 Lane 0 ('abc...')
    Result:   a9993e364706816aba3e25717850c26c9cd0d89d
    Expected: a9993e364706816aba3e25717850c26c9cd0d89d
    Status: [PASS]

  Test: AVX2 Lane 1 ('...')
    Result:   da39a3ee5e6b4b0d3255bfef95601890afd80709
    Expected: da39a3ee5e6b4b0d3255bfef95601890afd80709
    Status: [PASS]

  Test: AVX2 Lane 2 ('abcdbcdecd...')
    Result:   84983e441c3bd26ebaae4aa1f95129e5e54670f1
    Expected: 84983e441c3bd26ebaae4aa1f95129e5e54670f1
    Status: [PASS]

  Test: AVX2 Lane 3 ('This is a ...')
    Result:   3532499280b4e2f32f6417e556901a526d69143c
    Expected: 3532499280b4e2f32f6417e556901a526d69143c
    Status: [PASS]

  Test: AVX2 Lane 4 ('AVX2 imple...')
    Result:   0d11fa540ff1aa4796cdd2a91fcb63205bac4cfa
    Expected: 0d11fa540ff1aa4796cdd2a91fcb63205bac4cfa
    Status: [PASS]

  Test: AVX2 Lane 5 ('A slightly...')
    Result:   ef19a54dc106616b6296d175d68a20ef457016d8
    Expected: ef19a54dc106616b6296d175d68a20ef457016d8
    Status: [PASS]

  Test: AVX2 Lane 6 ('12345...')
    Result:   8cb2237d0679ca88db6464eac60da96345513964
    Expected: 8cb2237d0679ca88db6464eac60da96345513964
    Status: [PASS]

  Test: AVX2 Lane 7 ('Another te...')
    Result:   52adbb608a63ba56f12bcd9e56465ee0f6a31780
    Expected: 52adbb608a63ba56f12bcd9e56465ee0f6a31780
    Status: [PASS]

--- [Section 3: AVX2 Edge Cases (Padding)] ---
  Test: AVX2 Edge Case (len=55)
    Result:   c1c8bbdc22796e28c0e15163d20899b65621d65a
    Expected: c1c8bbdc22796e28c0e15163d20899b65621d65a
    Status: [PASS]

  Test: AVX2 Edge Case (len=56)
    Result:   049adea016c8a8e3b7a9054aeeaa8643453bebd9
    Expected: 049adea016c8a8e3b7a9054aeeaa8643453bebd9
    Status: [PASS]

  Test: AVX2 Edge Case (len=63)
    Result:   3f85dc2655c3426a4937d49028c01a066c535ce0
    Expected: 3f85dc2655c3426a4937d49028c01a066c535ce0
    Status: [PASS]

  Test: AVX2 Edge Case (len=64)
    Result:   7d4f9b6d084894fb8640dc55aab16ad0e021e4c8
    Expected: 7d4f9b6d084894fb8640dc55aab16ad0e021e4c8
    Status: [PASS]

  Test: AVX2 Edge Case (len=65)
    Result:   00c26b97f0dceca9387928bffdc36d303e31d536
    Expected: 00c26b97f0dceca9387928bffdc36d303e31d536
    Status: [PASS]

--- [Section 4: AVX2 Multiple Updates (Streaming)] ---
  Test: AVX2 Streaming Test
    Result:   913a4ec9683a2a0caf9709fbf64bca37d28f0812
    Expected: 913a4ec9683a2a0caf9709fbf64bca37d28f0812
    Status: [PASS]

--- Correctness Tests Finished ---
Result: All tests passed.

--- Running Throughput Performance Tests ---
Buffer size: 16 MB/lane, Test duration: ~3 seconds

Testing Scalar throughput...
  Result: 0.40 GB/s

Testing AVX2 Batch throughput...
  Result: 1.49 GB/s

--- Performance Summary ---
Improvement: 3.74x

```

### Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# thank

Assist in creation ：Gemini DeepSeek ChatGPT .

### 📜 Disclaimer
⚠️ This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.
