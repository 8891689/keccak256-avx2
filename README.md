# C/C++ GHigh-Performance Keccak-256 AVX2 Implementation

This is a Keccak-256 hash library written in C (compatible with C++). specifically designed for achieving extreme computational speed. It has been deeply optimized by leveraging the AVX2 instruction set found in modern CPUs.

## Core Advantages

*   **Extreme Speed**: Significantly accelerates hash computations by utilizing AVX2 (Advanced Vector Extensions 2) technology.
*   **8-Way Parallelism**: The core design supports processing 8 different sets of input data simultaneously, greatly enhancing throughput for bulk hashing operations.
*   **Deeply Optimized**: Incorporates various optimization strategies, such as full loop unrolling and adjustments for instruction-level parallelism, to maximize execution efficiency.
*   **Keccak Standard**: Implements the original Keccak padding rules (compatible with the `keccak256` function used in projects like Ethereum). Please note its slight difference from the FIPS 202 SHA3-256 standard.

## Suitable For

*   Applications with demanding speed requirements for Keccak-256 hash calculations.
*   Scenarios that require efficient processing of a large number of parallel hash tasks, such as blockchain technology, data verification, and high-performance computing.

## How to Integrate

Include the `keccak256_avx.c` and `keccak256_avx.h` files in your C project. AVX2 support needs to be enabled during compilation (e.g., using the `-mavx2` flag with GCC/Clang). For detailed API usage, please refer to the function declarations in the header file.


```
Compilation

gcc -O3 -mavx2 -mfma -march=native keccak_avx_test.c keccak256_avx.c -o keccak_avx_test

Testing and Verification

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

Assist in creation ：GEmini DeepSeek.

### 📜 Disclaimer
⚠️ This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.

