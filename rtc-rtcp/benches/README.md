### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-rtcp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.20s
     Running benches/bench.rs (target/release/deps/bench-635f8b473323d6fc)
Gnuplot not found, using plotters backend
SenderReport MarshalTo  time:   [6.5035 ns 6.5770 ns 6.7104 ns]
                        change: [−0.0449% +0.5708% +1.5796%] (p = 0.27 > 0.05)
                        No change in performance detected.
Found 18 outliers among 100 measurements (18.00%)
  5 (5.00%) high mild
  13 (13.00%) high severe

SenderReport Marshal    time:   [23.582 ns 23.613 ns 23.652 ns]
                        change: [−1.6965% −0.8395% −0.1715%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 17 outliers among 100 measurements (17.00%)
  1 (1.00%) low severe
  2 (2.00%) high mild
  14 (14.00%) high severe

SenderReport Unmarshal  time:   [100.75 ns 101.13 ns 101.52 ns]
                        change: [−1.1225% −0.8008% −0.4424%] (p = 0.00 < 0.05)
                        Change within noise threshold.

ReceiverReport MarshalTo
                        time:   [5.8321 ns 5.8351 ns 5.8395 ns]
                        change: [−7.3220% −4.6103% −2.3031%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 12 outliers among 100 measurements (12.00%)
  3 (3.00%) high mild
  9 (9.00%) high severe

ReceiverReport Marshal  time:   [25.853 ns 25.883 ns 25.925 ns]
                        change: [−0.5693% −0.3308% −0.1092%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 14 outliers among 100 measurements (14.00%)
  1 (1.00%) high mild
  13 (13.00%) high severe

ReceiverReport Unmarshal
                        time:   [92.702 ns 92.842 ns 93.068 ns]
                        change: [−3.5092% −3.2364% −2.9402%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) high mild
  8 (8.00%) high severe

PictureLossIndication MarshalTo
                        time:   [1.0620 ns 1.0642 ns 1.0673 ns]
                        change: [−0.5781% +0.0938% +0.7808%] (p = 0.79 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high severe

PictureLossIndication Marshal
                        time:   [17.696 ns 17.740 ns 17.791 ns]
                        change: [+0.8383% +1.2648% +1.6738%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

PictureLossIndication Unmarshal
                        time:   [23.267 ns 23.284 ns 23.306 ns]
                        change: [−0.7723% −0.5252% −0.2792%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 14 outliers among 100 measurements (14.00%)
  14 (14.00%) high severe

TransportLayerNack MarshalTo
                        time:   [4.4651 ns 4.5386 ns 4.6199 ns]
                        change: [−4.2246% −2.6483% −0.9952%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

TransportLayerNack Marshal
                        time:   [22.738 ns 22.757 ns 22.781 ns]
                        change: [−1.7070% −1.0002% −0.4030%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 15 outliers among 100 measurements (15.00%)
  5 (5.00%) high mild
  10 (10.00%) high severe

TransportLayerNack Unmarshal
                        time:   [52.190 ns 52.259 ns 52.363 ns]
                        change: [−0.7690% −0.3590% +0.0469%] (p = 0.09 > 0.05)
                        No change in performance detected.
Found 14 outliers among 100 measurements (14.00%)
  1 (1.00%) high mild
  13 (13.00%) high severe

Goodbye MarshalTo       time:   [9.3961 ns 9.4386 ns 9.5011 ns]
                        change: [−0.1410% +0.1426% +0.4667%] (p = 0.39 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) high mild
  5 (5.00%) high severe

Goodbye Marshal         time:   [29.022 ns 29.045 ns 29.075 ns]
                        change: [−5.0871% −3.1159% −1.5482%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 13 outliers among 100 measurements (13.00%)
  2 (2.00%) high mild
  11 (11.00%) high severe

Goodbye Unmarshal       time:   [64.092 ns 64.261 ns 64.467 ns]
                        change: [−0.0831% +0.4238% +1.0025%] (p = 0.14 > 0.05)
                        No change in performance detected.
Found 19 outliers among 100 measurements (19.00%)
  3 (3.00%) low mild
  3 (3.00%) high mild
  13 (13.00%) high severe

SourceDescription MarshalTo
                        time:   [42.131 ns 42.409 ns 42.767 ns]
                        change: [−1.2064% −0.4367% +0.2290%] (p = 0.26 > 0.05)
                        No change in performance detected.
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe

SourceDescription Marshal
                        time:   [63.863 ns 64.121 ns 64.421 ns]
                        change: [+1.4336% +1.8915% +2.4150%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  7 (7.00%) high mild
  1 (1.00%) high severe

SourceDescription Unmarshal
                        time:   [126.93 ns 127.83 ns 128.98 ns]
                        change: [−0.4257% +0.0007% +0.4908%] (p = 1.00 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  3 (3.00%) high mild
  7 (7.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.20s
     Running benches/bench.rs (target/release/deps/bench-635f8b473323d6fc)
Gnuplot not found, using plotters backend
SenderReport MarshalTo  time:   [6.5181 ns 6.7492 ns 7.1055 ns]
                        change: [−0.8119% +1.1548% +3.5337%] (p = 0.37 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe

SenderReport Marshal    time:   [23.586 ns 23.609 ns 23.641 ns]
                        change: [−0.2598% −0.0509% +0.1720%] (p = 0.65 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  2 (2.00%) high mild
  10 (10.00%) high severe

SenderReport Unmarshal  time:   [101.06 ns 101.26 ns 101.51 ns]
                        change: [+1.0749% +1.5117% +1.9087%] (p = 0.00 < 0.05)
                        Performance has regressed.

ReceiverReport MarshalTo
                        time:   [5.8383 ns 5.8580 ns 5.8977 ns]
                        change: [−0.0150% +0.2255% +0.6072%] (p = 0.15 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  3 (3.00%) high mild
  5 (5.00%) high severe

ReceiverReport Marshal  time:   [25.866 ns 25.887 ns 25.913 ns]
                        change: [−0.1551% +0.0535% +0.2313%] (p = 0.61 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  1 (1.00%) high mild
  11 (11.00%) high severe

ReceiverReport Unmarshal
                        time:   [93.340 ns 93.568 ns 93.850 ns]
                        change: [+0.5577% +0.8807% +1.2924%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  12 (12.00%) high mild
  1 (1.00%) high severe

PictureLossIndication MarshalTo
                        time:   [1.0600 ns 1.0605 ns 1.0611 ns]
                        change: [−1.3731% −0.9217% −0.5516%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) high mild
  9 (9.00%) high severe

PictureLossIndication Marshal
                        time:   [17.445 ns 17.471 ns 17.502 ns]
                        change: [−1.8891% −1.5591% −1.2159%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 6 outliers among 100 measurements (6.00%)
  6 (6.00%) high mild

PictureLossIndication Unmarshal
                        time:   [23.304 ns 23.327 ns 23.354 ns]
                        change: [−0.0053% +0.1600% +0.3582%] (p = 0.08 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) high mild
  5 (5.00%) high severe

TransportLayerNack MarshalTo
                        time:   [4.4827 ns 4.5468 ns 4.6132 ns]
                        change: [−4.4971% −3.1019% −1.6617%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 13 outliers among 100 measurements (13.00%)
  4 (4.00%) low mild
  9 (9.00%) high mild

TransportLayerNack Marshal
                        time:   [22.945 ns 22.995 ns 23.044 ns]
                        change: [+0.0508% +0.3549% +0.6297%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

TransportLayerNack Unmarshal
                        time:   [52.698 ns 52.941 ns 53.224 ns]
                        change: [+0.1725% +0.5944% +1.0051%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) high mild
  1 (1.00%) high severe

Goodbye MarshalTo       time:   [9.4085 ns 9.4364 ns 9.4691 ns]
                        change: [−0.2353% +0.1158% +0.4591%] (p = 0.53 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe

Goodbye Marshal         time:   [29.014 ns 29.050 ns 29.096 ns]
                        change: [−0.1546% +0.0360% +0.2716%] (p = 0.75 > 0.05)
                        No change in performance detected.
Found 20 outliers among 100 measurements (20.00%)
  5 (5.00%) low mild
  4 (4.00%) high mild
  11 (11.00%) high severe

Goodbye Unmarshal       time:   [63.082 ns 63.130 ns 63.185 ns]
                        change: [−2.2024% −1.6352% −1.1340%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 26 outliers among 100 measurements (26.00%)
  10 (10.00%) low severe
  2 (2.00%) low mild
  2 (2.00%) high mild
  12 (12.00%) high severe

SourceDescription MarshalTo
                        time:   [41.970 ns 42.013 ns 42.070 ns]
                        change: [−1.1698% −0.7807% −0.4578%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) low mild
  1 (1.00%) high mild
  8 (8.00%) high severe

SourceDescription Marshal
                        time:   [63.217 ns 63.321 ns 63.462 ns]
                        change: [−2.1872% −1.6805% −1.1777%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 9 outliers among 100 measurements (9.00%)
  4 (4.00%) high mild
  5 (5.00%) high severe

SourceDescription Unmarshal
                        time:   [126.78 ns 127.04 ns 127.32 ns]
                        change: [−0.6421% −0.1426% +0.2952%] (p = 0.57 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

```

```
    Finished `bench` profile [optimized] target(s) in 0.23s
     Running benches/bench.rs (target/release/deps/bench-635f8b473323d6fc)
Gnuplot not found, using plotters backend
SenderReport MarshalTo  time:   [6.4980 ns 6.5031 ns 6.5099 ns]
                        change: [−3.5908% −1.3416% +0.1627%] (p = 0.21 > 0.05)
                        No change in performance detected.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

SenderReport Marshal    time:   [23.624 ns 23.664 ns 23.717 ns]
                        change: [−0.0408% +0.2090% +0.4794%] (p = 0.11 > 0.05)
                        No change in performance detected.
Found 7 outliers among 100 measurements (7.00%)
  2 (2.00%) high mild
  5 (5.00%) high severe

SenderReport Unmarshal  time:   [100.19 ns 100.36 ns 100.57 ns]
                        change: [−1.8287% −1.4948% −1.1289%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

ReceiverReport MarshalTo
                        time:   [5.8340 ns 5.8360 ns 5.8385 ns]
                        change: [−0.5687% −0.2146% +0.0281%] (p = 0.18 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  5 (5.00%) high mild
  5 (5.00%) high severe

ReceiverReport Marshal  time:   [25.895 ns 25.931 ns 25.976 ns]
                        change: [−0.0394% +0.2110% +0.4848%] (p = 0.11 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  3 (3.00%) high mild
  6 (6.00%) high severe

ReceiverReport Unmarshal
                        time:   [94.602 ns 95.177 ns 95.969 ns]
                        change: [+0.4562% +0.8927% +1.3697%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 17 outliers among 100 measurements (17.00%)
  6 (6.00%) high mild
  11 (11.00%) high severe

PictureLossIndication MarshalTo
                        time:   [1.0694 ns 1.0780 ns 1.0901 ns]
                        change: [+0.4389% +0.8775% +1.4690%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 9 outliers among 100 measurements (9.00%)
  6 (6.00%) high mild
  3 (3.00%) high severe

PictureLossIndication Marshal
                        time:   [17.682 ns 17.749 ns 17.825 ns]
                        change: [+0.8633% +1.2625% +1.6547%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe

PictureLossIndication Unmarshal
                        time:   [23.386 ns 23.428 ns 23.472 ns]
                        change: [+0.1539% +0.3795% +0.6024%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

TransportLayerNack MarshalTo
                        time:   [4.5997 ns 4.6698 ns 4.7370 ns]
                        change: [+3.0419% +4.5957% +6.0964%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 14 outliers among 100 measurements (14.00%)
  12 (12.00%) low mild
  2 (2.00%) high mild

TransportLayerNack Marshal
                        time:   [22.780 ns 22.806 ns 22.837 ns]
                        change: [−0.6166% −0.4159% −0.2068%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
  4 (4.00%) high mild
  8 (8.00%) high severe

TransportLayerNack Unmarshal
                        time:   [53.358 ns 54.423 ns 55.894 ns]
                        change: [+1.1375% +2.8090% +5.6142%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) high mild
  5 (5.00%) high severe

Goodbye MarshalTo       time:   [9.5563 ns 9.6596 ns 9.7938 ns]
                        change: [+0.7187% +1.6073% +2.8885%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe

Goodbye Marshal         time:   [29.078 ns 29.123 ns 29.180 ns]
                        change: [+0.0503% +1.5577% +5.2403%] (p = 0.21 > 0.05)
                        No change in performance detected.
Found 15 outliers among 100 measurements (15.00%)
  3 (3.00%) high mild
  12 (12.00%) high severe

Goodbye Unmarshal       time:   [63.202 ns 63.270 ns 63.363 ns]
                        change: [+0.5105% +1.0241% +1.6898%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 15 outliers among 100 measurements (15.00%)
  4 (4.00%) high mild
  11 (11.00%) high severe

SourceDescription MarshalTo
                        time:   [42.368 ns 42.429 ns 42.499 ns]
                        change: [+0.6293% +0.8418% +1.0864%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 31 outliers among 100 measurements (31.00%)
  6 (6.00%) low severe
  13 (13.00%) low mild
  4 (4.00%) high mild
  8 (8.00%) high severe

SourceDescription Marshal
                        time:   [63.666 ns 63.889 ns 64.129 ns]
                        change: [+0.4457% +0.8573% +1.2831%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) high mild
  1 (1.00%) high severe

SourceDescription Unmarshal
                        time:   [126.40 ns 126.60 ns 126.85 ns]
                        change: [+0.2212% +0.5776% +0.9702%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild

```