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
