### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
   Compiling rtc-stun v0.8.2 (/Users/yuliu/Projects/rtc/rtc-stun)
    Finished `bench` profile [optimized] target(s) in 2.20s
     Running benches/bench.rs (target/release/deps/bench-6291adbc690698b7)
Gnuplot not found, using plotters backend
BenchmarkMappedAddress_AddTo
                        time:   [49.132 ns 50.714 ns 52.791 ns]
                        change: [−19.251% −13.050% −6.4990%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  4 (4.00%) high mild
  7 (7.00%) high severe

BenchmarkAlternateServer_AddTo
                        time:   [46.627 ns 46.652 ns 46.689 ns]
                        change: [−0.1982% −0.0227% +0.1427%] (p = 0.81 > 0.05)
                        No change in performance detected.
Found 18 outliers among 100 measurements (18.00%)
  2 (2.00%) high mild
  16 (16.00%) high severe

BenchmarkMessage_GetNotFound
                        time:   [2.1234 ns 2.1325 ns 2.1436 ns]
                        change: [−0.1552% +0.1406% +0.4524%] (p = 0.39 > 0.05)
                        No change in performance detected.
Found 21 outliers among 100 measurements (21.00%)
  2 (2.00%) high mild
  19 (19.00%) high severe

BenchmarkMessage_Get    time:   [16.988 ns 17.163 ns 17.331 ns]
                        change: [−2.9385% −2.0911% −1.2559%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 13 outliers among 100 measurements (13.00%)
  13 (13.00%) high mild

BenchmarkErrorCode_AddTo
                        time:   [79.011 ns 79.529 ns 80.027 ns]
                        change: [−3.2833% −2.4085% −1.5684%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

BenchmarkErrorCodeAttribute_AddTo
                        time:   [60.111 ns 60.374 ns 60.673 ns]
                        change: [−5.3278% −2.2604% +0.0757%] (p = 0.11 > 0.05)
                        No change in performance detected.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

BenchmarkErrorCodeAttribute_GetFrom
                        time:   [29.452 ns 29.525 ns 29.625 ns]
                        change: [−1.4975% −0.9059% −0.3743%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 18 outliers among 100 measurements (18.00%)
  10 (10.00%) high mild
  8 (8.00%) high severe

BenchmarkFingerprint_AddTo
                        time:   [542.17 ns 543.87 ns 546.05 ns]
                        change: [−0.2136% +0.1987% +0.5850%] (p = 0.35 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

BenchmarkFingerprint_Check
                        time:   [531.74 ns 532.79 ns 534.05 ns]
                        change: [−0.5976% +0.4036% +1.9935%] (p = 0.59 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

BenchmarkBuildOverhead/Build
                        time:   [779.94 ns 785.25 ns 792.42 ns]
                        change: [+0.9762% +1.7983% +2.6424%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
  2 (2.00%) high mild
  4 (4.00%) high severe

BenchmarkBuildOverhead/Raw
                        time:   [686.73 ns 694.83 ns 704.68 ns]
                        change: [−1.1190% +0.2174% +1.4968%] (p = 0.75 > 0.05)
                        No change in performance detected.
Found 14 outliers among 100 measurements (14.00%)
  5 (5.00%) high mild
  9 (9.00%) high severe

BenchmarkMessageIntegrity_AddTo
                        time:   [488.85 ns 506.69 ns 526.48 ns]
                        change: [+3.5469% +6.6033% +9.8224%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  1 (1.00%) high mild
  4 (4.00%) high severe

BenchmarkMessageIntegrity_Check
                        time:   [470.72 ns 485.60 ns 505.34 ns]
                        change: [+2.5986% +5.2295% +8.1944%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 13 outliers among 100 measurements (13.00%)
  8 (8.00%) high mild
  5 (5.00%) high severe

BenchmarkMessage_Write  time:   [44.181 ns 44.841 ns 45.671 ns]
                        change: [−3.4854% +1.2647% +5.7775%] (p = 0.60 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  9 (9.00%) high mild
  3 (3.00%) high severe

BenchmarkMessageType_Value
                        time:   [272.73 ps 277.36 ps 282.99 ps]
                        change: [−5.4205% −2.6991% −0.3562%] (p = 0.04 < 0.05)
                        Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
  2 (2.00%) high mild
  4 (4.00%) high severe

BenchmarkMessage_WriteTo
                        time:   [4.1259 ns 4.1302 ns 4.1362 ns]
Found 21 outliers among 100 measurements (21.00%)
  2 (2.00%) high mild
  19 (19.00%) high severe

BenchmarkMessage_ReadFrom
                        time:   [39.646 ns 39.765 ns 39.904 ns]
Found 17 outliers among 100 measurements (17.00%)
  5 (5.00%) high mild
  12 (12.00%) high severe

BenchmarkMessage_ReadBytes
                        time:   [13.749 ns 13.907 ns 14.134 ns]
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) low severe
  1 (1.00%) low mild
  1 (1.00%) high severe

BenchmarkIsMessage      time:   [796.78 ps 799.97 ps 803.44 ps]
Found 19 outliers among 100 measurements (19.00%)
  4 (4.00%) high mild
  15 (15.00%) high severe

BenchmarkMessage_NewTransactionID
                        time:   [16.322 ns 16.350 ns 16.382 ns]
Found 18 outliers among 100 measurements (18.00%)
  4 (4.00%) high mild
  14 (14.00%) high severe

BenchmarkMessageFull    time:   [763.66 ns 767.03 ns 771.11 ns]
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe

BenchmarkMessageFullHardcore
                        time:   [71.773 ns 73.467 ns 75.382 ns]
Found 8 outliers among 100 measurements (8.00%)
  2 (2.00%) high mild
  6 (6.00%) high severe

BenchmarkMessage_WriteHeader
                        time:   [1.6215 ns 1.6370 ns 1.6592 ns]
Found 15 outliers among 100 measurements (15.00%)
  4 (4.00%) high mild
  11 (11.00%) high severe

BenchmarkMessage_CloneTo
                        time:   [63.133 ns 63.807 ns 64.623 ns]
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) high mild
  3 (3.00%) high severe

BenchmarkMessage_AddTo  time:   [1.0660 ns 1.1079 ns 1.1589 ns]
Found 7 outliers among 100 measurements (7.00%)
  7 (7.00%) high severe

BenchmarkDecode         time:   [40.599 ns 41.752 ns 43.016 ns]
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe

BenchmarkUsername_AddTo time:   [26.856 ns 27.459 ns 28.168 ns]
Found 8 outliers among 100 measurements (8.00%)
  2 (2.00%) high mild
  6 (6.00%) high severe

BenchmarkUsername_GetFrom
                        time:   [21.262 ns 21.777 ns 22.384 ns]
Found 10 outliers among 100 measurements (10.00%)
  6 (6.00%) high mild
  4 (4.00%) high severe

BenchmarkNonce_AddTo    time:   [34.977 ns 35.871 ns 36.859 ns]
Found 7 outliers among 100 measurements (7.00%)
  2 (2.00%) high mild
  5 (5.00%) high severe

BenchmarkNonce_AddTo_BadLength
                        time:   [3.0317 ns 3.1045 ns 3.1854 ns]
Found 10 outliers among 100 measurements (10.00%)
  4 (4.00%) high mild
  6 (6.00%) high severe

BenchmarkNonce_GetFrom  time:   [21.865 ns 22.875 ns 24.179 ns]
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) high mild
  5 (5.00%) high severe

BenchmarkUnknownAttributes/AddTo
                        time:   [39.579 ns 39.814 ns 40.097 ns]
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) high mild
  1 (1.00%) high severe

BenchmarkUnknownAttributes/GetFrom
                        time:   [18.693 ns 19.133 ns 19.650 ns]
Found 8 outliers among 100 measurements (8.00%)
  3 (3.00%) high mild
  5 (5.00%) high severe

BenchmarkXOR            time:   [13.322 ns 13.486 ns 13.704 ns]
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) high mild
  2 (2.00%) high severe

BenchmarkXORMappedAddress_AddTo
                        time:   [46.378 ns 46.828 ns 47.379 ns]
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe

BenchmarkXORMappedAddress_GetFrom
                        time:   [28.461 ns 28.842 ns 29.446 ns]
Found 9 outliers among 100 measurements (9.00%)
  4 (4.00%) high mild
  5 (5.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.15s
     Running benches/bench.rs (target/release/deps/bench-6291adbc690698b7)
Gnuplot not found, using plotters backend
BenchmarkMappedAddress_AddTo
                        time:   [47.634 ns 48.108 ns 48.656 ns]
                        change: [−6.7586% −3.8423% −1.4285%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe

BenchmarkAlternateServer_AddTo
                        time:   [46.668 ns 46.727 ns 46.806 ns]
                        change: [+0.2804% +0.6092% +0.9882%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 19 outliers among 100 measurements (19.00%)
  4 (4.00%) high mild
  15 (15.00%) high severe

BenchmarkMessage_GetNotFound
                        time:   [2.1183 ns 2.1191 ns 2.1201 ns]
                        change: [−0.6022% −0.2908% −0.0321%] (p = 0.05 < 0.05)
                        Change within noise threshold.
Found 18 outliers among 100 measurements (18.00%)
  2 (2.00%) high mild
  16 (16.00%) high severe

BenchmarkMessage_Get    time:   [16.876 ns 16.968 ns 17.062 ns]
                        change: [−1.1068% −0.3949% +0.2924%] (p = 0.29 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

BenchmarkErrorCode_AddTo
                        time:   [79.157 ns 79.652 ns 80.249 ns]
                        change: [+1.7284% +2.7555% +4.1462%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 4 outliers among 100 measurements (4.00%)
  3 (3.00%) high mild
  1 (1.00%) high severe

BenchmarkErrorCodeAttribute_AddTo
                        time:   [58.718 ns 58.849 ns 58.991 ns]
                        change: [−4.8008% −3.8924% −3.0693%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) high mild
  9 (9.00%) high severe

BenchmarkErrorCodeAttribute_GetFrom
                        time:   [29.441 ns 29.510 ns 29.596 ns]
                        change: [−0.2617% +0.2373% +0.7854%] (p = 0.37 > 0.05)
                        No change in performance detected.
Found 19 outliers among 100 measurements (19.00%)
  6 (6.00%) high mild
  13 (13.00%) high severe

BenchmarkFingerprint_AddTo
                        time:   [540.30 ns 541.40 ns 542.91 ns]
                        change: [−0.6754% −0.3463% −0.0647%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  3 (3.00%) high mild
  10 (10.00%) high severe

BenchmarkFingerprint_Check
                        time:   [530.96 ns 531.25 ns 531.60 ns]
                        change: [−2.7791% −1.4466% −0.5569%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 15 outliers among 100 measurements (15.00%)
  3 (3.00%) high mild
  12 (12.00%) high severe

BenchmarkBuildOverhead/Build
                        time:   [765.32 ns 766.30 ns 767.38 ns]
                        change: [−3.1281% −2.2260% −1.4786%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 8 outliers among 100 measurements (8.00%)
  3 (3.00%) high mild
  5 (5.00%) high severe

BenchmarkBuildOverhead/Raw
                        time:   [670.40 ns 670.84 ns 671.26 ns]
                        change: [−3.1030% −2.2576% −1.5366%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) high mild
  3 (3.00%) high severe

BenchmarkMessageIntegrity_AddTo
                        time:   [460.00 ns 473.75 ns 488.13 ns]
                        change: [−9.6476% −6.7331% −3.8766%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 9 outliers among 100 measurements (9.00%)
  9 (9.00%) high severe

BenchmarkMessageIntegrity_Check
                        time:   [450.12 ns 450.66 ns 451.30 ns]
                        change: [−10.019% −7.6641% −5.6178%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 18 outliers among 100 measurements (18.00%)
  1 (1.00%) high mild
  17 (17.00%) high severe

BenchmarkMessage_Write  time:   [43.089 ns 43.129 ns 43.176 ns]
                        change: [−9.7620% −7.7553% −5.8321%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

BenchmarkMessageType_Value
                        time:   [246.80 ps 247.09 ps 247.49 ps]
                        change: [−10.420% −9.2751% −8.2898%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 18 outliers among 100 measurements (18.00%)
  5 (5.00%) high mild
  13 (13.00%) high severe

BenchmarkMessage_WriteTo
                        time:   [4.1344 ns 4.1419 ns 4.1512 ns]
                        change: [+0.1766% +0.4563% +0.7309%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

BenchmarkMessage_ReadFrom
                        time:   [39.552 ns 39.613 ns 39.691 ns]
                        change: [−0.6023% −0.2983% −0.0107%] (p = 0.05 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  3 (3.00%) high mild
  8 (8.00%) high severe

BenchmarkMessage_ReadBytes
                        time:   [13.864 ns 14.007 ns 14.130 ns]
                        change: [−5.1588% −3.4461% −1.8633%] (p = 0.00 < 0.05)
                        Performance has improved.

BenchmarkIsMessage      time:   [793.94 ps 794.26 ps 794.55 ps]
                        change: [−0.5462% −0.3116% −0.0927%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
  2 (2.00%) low severe
  3 (3.00%) high mild
  7 (7.00%) high severe

BenchmarkMessage_NewTransactionID
                        time:   [16.296 ns 16.306 ns 16.320 ns]
                        change: [−0.4960% −0.1740% +0.1355%] (p = 0.29 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) high mild
  9 (9.00%) high severe

BenchmarkMessageFull    time:   [752.68 ns 753.23 ns 753.91 ns]
                        change: [−3.4573% −2.4187% −1.6440%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 13 outliers among 100 measurements (13.00%)
  3 (3.00%) high mild
  10 (10.00%) high severe

BenchmarkMessageFullHardcore
                        time:   [69.709 ns 69.909 ns 70.170 ns]
                        change: [−3.6926% −2.2807% −1.0499%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 40 outliers among 100 measurements (40.00%)
  23 (23.00%) low mild
  7 (7.00%) high mild
  10 (10.00%) high severe

BenchmarkMessage_WriteHeader
                        time:   [1.5894 ns 1.5906 ns 1.5921 ns]
                        change: [−21.645% −16.488% −11.337%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 12 outliers among 100 measurements (12.00%)
  5 (5.00%) high mild
  7 (7.00%) high severe

BenchmarkMessage_CloneTo
                        time:   [59.760 ns 59.799 ns 59.850 ns]
                        change: [−9.4509% −8.0074% −6.7516%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) high mild
  1 (1.00%) high severe

BenchmarkMessage_AddTo  time:   [1.0093 ns 1.0149 ns 1.0191 ns]
                        change: [−10.295% −7.9795% −5.9997%] (p = 0.00 < 0.05)
                        Performance has improved.

BenchmarkDecode         time:   [37.862 ns 37.913 ns 37.979 ns]
                        change: [−10.047% −8.0310% −6.2453%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 7 outliers among 100 measurements (7.00%)
  5 (5.00%) high mild
  2 (2.00%) high severe

BenchmarkUsername_AddTo time:   [26.276 ns 26.309 ns 26.345 ns]
                        change: [−3.6168% −1.9808% −0.6085%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 29 outliers among 100 measurements (29.00%)
  9 (9.00%) low severe
  8 (8.00%) low mild
  4 (4.00%) high mild
  8 (8.00%) high severe

BenchmarkUsername_GetFrom
                        time:   [20.616 ns 20.685 ns 20.751 ns]
                        change: [−5.3885% −3.3864% −1.7255%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) low mild
  3 (3.00%) high mild
  2 (2.00%) high severe

BenchmarkNonce_AddTo    time:   [33.042 ns 33.091 ns 33.137 ns]
                        change: [−6.6597% −5.1330% −3.7655%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) high mild
  3 (3.00%) high severe

BenchmarkNonce_AddTo_BadLength
                        time:   [2.9125 ns 2.9143 ns 2.9168 ns]
                        change: [−9.1226% −6.1625% −3.9494%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 12 outliers among 100 measurements (12.00%)
  3 (3.00%) high mild
  9 (9.00%) high severe

BenchmarkNonce_GetFrom  time:   [21.232 ns 21.276 ns 21.316 ns]
                        change: [−6.2217% −3.6717% −1.6373%] (p = 0.00 < 0.05)
                        Performance has improved.

BenchmarkUnknownAttributes/AddTo
                        time:   [39.305 ns 39.608 ns 39.961 ns]
                        change: [−0.7663% +0.3091% +1.3807%] (p = 0.59 > 0.05)
                        No change in performance detected.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

BenchmarkUnknownAttributes/GetFrom
                        time:   [18.154 ns 18.191 ns 18.236 ns]
                        change: [−3.2824% −1.9364% −0.6983%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

BenchmarkXOR            time:   [12.974 ns 12.990 ns 13.013 ns]
                        change: [−3.6469% −2.8163% −2.1188%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 18 outliers among 100 measurements (18.00%)
  4 (4.00%) high mild
  14 (14.00%) high severe

BenchmarkXORMappedAddress_AddTo
                        time:   [45.450 ns 45.660 ns 45.931 ns]
                        change: [−2.9717% −1.8368% −0.8809%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 16 outliers among 100 measurements (16.00%)
  2 (2.00%) high mild
  14 (14.00%) high severe

BenchmarkXORMappedAddress_GetFrom
                        time:   [28.186 ns 28.220 ns 28.264 ns]
                        change: [−6.7040% −4.3572% −2.6057%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 13 outliers among 100 measurements (13.00%)
  2 (2.00%) high mild
  11 (11.00%) high severe

```

```

```