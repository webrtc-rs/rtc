### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-srtp --bench bench
Gnuplot not found, using plotters backend
SRTP/Encrypt/RTP        time:   [5.6858 µs 5.7234 µs 5.7694 µs]
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high severe
SRTP/Decrypt/RTP        time:   [5.6254 µs 5.6385 µs 5.6549 µs]
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) high mild
  1 (1.00%) high severe
SRTP/Encrypt/RTCP       time:   [641.42 ns 643.53 ns 645.92 ns]
Found 7 outliers among 100 measurements (7.00%)
  3 (3.00%) high mild
  4 (4.00%) high severe
SRTP/Decrypt/RTCP       time:   [631.40 ns 633.15 ns 635.43 ns]
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe
```

```
    Finished `bench` profile [optimized] target(s) in 0.12s
     Running benches/bench.rs (target/release/deps/bench-5824b5a56534ac1c)
Gnuplot not found, using plotters backend
SRTP/Encrypt/RTP        time:   [5.6013 µs 5.6042 µs 5.6073 µs]
                        change: [−1.5372% −1.1158% −0.7427%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 13 outliers among 100 measurements (13.00%)
  5 (5.00%) low severe
  3 (3.00%) high mild
  5 (5.00%) high severe
SRTP/Decrypt/RTP        time:   [5.5840 µs 5.5879 µs 5.5937 µs]
                        change: [−1.8765% −1.4457% −1.0644%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) high mild
  2 (2.00%) high severe
SRTP/Encrypt/RTCP       time:   [635.38 ns 638.62 ns 644.16 ns]
                        change: [−1.3894% −0.8625% −0.2766%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) high mild
  3 (3.00%) high severe
SRTP/Decrypt/RTCP       time:   [627.27 ns 627.68 ns 628.08 ns]
                        change: [−1.6764% −1.3366% −1.0230%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.13s
     Running benches/bench.rs (target/release/deps/bench-5824b5a56534ac1c)
Gnuplot not found, using plotters backend
SRTP/Encrypt/RTP        time:   [5.6134 µs 5.6378 µs 5.6736 µs]
                        change: [+0.8457% +3.4526% +7.1365%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 15 outliers among 100 measurements (15.00%)
  1 (1.00%) low severe
  1 (1.00%) low mild
  2 (2.00%) high mild
  11 (11.00%) high severe
SRTP/Decrypt/RTP        time:   [5.5814 µs 5.5867 µs 5.5940 µs]
                        change: [−0.2377% −0.1258% +0.0067%] (p = 0.04 < 0.05)
                        Change within noise threshold.
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) low mild
  2 (2.00%) high mild
  4 (4.00%) high severe
SRTP/Encrypt/RTCP       time:   [639.54 ns 642.79 ns 646.92 ns]
                        change: [−0.1150% +0.4636% +0.9981%] (p = 0.11 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  1 (1.00%) high mild
  7 (7.00%) high severe
SRTP/Decrypt/RTCP       time:   [629.80 ns 630.61 ns 631.60 ns]
                        change: [+0.5928% +1.5843% +3.3894%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) high mild
  6 (6.00%) high severe

```