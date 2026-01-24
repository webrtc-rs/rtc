### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-rtp --bench bench
Gnuplot not found, using plotters backend
Benchmark MarshalTo     time:   [17.738 ns 17.833 ns 17.933 ns]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

Benchmark Marshal       time:   [42.081 ns 42.268 ns 42.473 ns]
                        change: [−96.828% −96.787% −96.749%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 7 outliers among 100 measurements (7.00%)
  6 (6.00%) high mild
  1 (1.00%) high severe

Benchmark Unmarshal     time:   [106.67 ns 106.83 ns 107.02 ns]
                        change: [−97.190% −97.182% −97.174%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
```

```
cargo bench --package rtc-rtp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.12s
     Running benches/bench.rs (target/release/deps/bench-b94f3d075c0f6e69)
Gnuplot not found, using plotters backend
Benchmark MarshalTo     time:   [17.483 ns 17.486 ns 17.489 ns]
                        change: [−1.6405% −1.1945% −0.7882%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 19 outliers among 100 measurements (19.00%)
  19 (19.00%) high severe

Benchmark Marshal       time:   [41.562 ns 41.706 ns 41.865 ns]
                        change: [−1.0820% −0.6153% −0.1593%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild

Benchmark Unmarshal     time:   [106.76 ns 106.98 ns 107.24 ns]
                        change: [−0.1772% +0.6457% +1.6283%] (p = 0.17 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  5 (5.00%) high mild
  5 (5.00%) high severe
```

```
cargo bench --package rtc-rtp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.08s
     Running benches/bench.rs (target/release/deps/bench-b94f3d075c0f6e69)
Gnuplot not found, using plotters backend
Benchmark MarshalTo     time:   [17.476 ns 17.480 ns 17.486 ns]
                        change: [−0.4983% −0.2945% −0.0982%] (p = 0.01 < 0.05)
                        Change within noise threshold.
Found 10 outliers among 100 measurements (10.00%)
  2 (2.00%) high mild
  8 (8.00%) high severe

Benchmark Marshal       time:   [41.726 ns 41.818 ns 41.896 ns]
                        change: [−0.3431% +0.1868% +0.7296%] (p = 0.50 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  7 (7.00%) high mild
  2 (2.00%) high severe

Benchmark Unmarshal     time:   [106.99 ns 107.24 ns 107.52 ns]
                        change: [−1.3232% −0.3096% +0.5103%] (p = 0.54 > 0.05)
                        No change in performance detected.
```