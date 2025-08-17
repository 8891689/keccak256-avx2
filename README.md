# C/C++ High-performance sha3 224 256 384 512 and Keccak-256 AVX2 implementations

This is a sha3 224 256 384 512 and Keccak-256 hashing library written in C (compatible with C++), designed for extremely fast computations. It is deeply optimized to take advantage of the AVX2 instruction set in modern CPUs.

## Core Advantages

* **Extreme Speed**: Utilizes AVX2 (Advanced Vector Extensions 2.0) technology to significantly accelerate hashing operations.
* **8-Way Parallelism**: The core design supports simultaneous processing of eight different sets of input data, significantly improving the throughput of batch hashing operations.
* **Deep Optimization**: Combines multiple optimization strategies, such as full loop unrolling and instruction-level parallelism, to maximize execution efficiency.
* **Keccak Standard**: Implements the original Keccak padding rule (compatible with the `keccak256` function used by projects such as Ethereum). Please note that this differs slightly from the FIPS 202 SHA3-256 standard; they are different algorithms.

## Applicable Scenarios

* Applications requiring extremely fast SHA3 224, 256, 384, 512, and Keccak-256 hash calculation speeds.
* Scenarios requiring efficient processing of large numbers of parallel hashing tasks, such as blockchain technology, data verification, and high-performance computing.
* SHA3 224, 256, 384, and 512 have built-in basic implementations and AVX2-optimized versions, and function interfaces have been left, which can be linked as needed.
## Compilation

```

gcc -O3 -mavx2 -mfma -march=native sha3_avx2.c sha3_avx2_test.c -o sha3_avx2_test

gcc -O3 -mavx2 -mfma -march=native keccak_avx_test.c keccak256_avx.c -o keccak_avx_test


Testing and Verification

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
