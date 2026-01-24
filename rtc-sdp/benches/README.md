### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-sdp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.18s
     Running benches/bench.rs (target/release/deps/bench-15f62fb2785e68ea)
Gnuplot not found, using plotters backend
Benchmark Marshal       time:   [1.2093 µs 1.2291 µs 1.2569 µs]
                        change: [−47.910% −45.432% −42.979%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 14 outliers among 100 measurements (14.00%)
  6 (6.00%) high mild
  8 (8.00%) high severe

Benchmark Unmarshal     time:   [4.0022 µs 4.0169 µs 4.0325 µs]
                        change: [−32.544% −28.957% −25.061%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild
```

```
cargo bench --package rtc-sdp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.12s
     Running benches/bench.rs (target/release/deps/bench-15f62fb2785e68ea)
Gnuplot not found, using plotters backend
Benchmark Marshal       time:   [1.2394 µs 1.2690 µs 1.3116 µs]
                        change: [−0.5015% +1.2855% +3.3710%] (p = 0.22 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe

Benchmark Unmarshal     time:   [3.9323 µs 3.9504 µs 3.9703 µs]
                        change: [−2.3206% −1.8512% −1.3180%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe
```

```
cargo bench --package rtc-sdp --bench bench
    Finished `bench` profile [optimized] target(s) in 0.13s
     Running benches/bench.rs (target/release/deps/bench-15f62fb2785e68ea)
Gnuplot not found, using plotters backend
Benchmark Marshal       time:   [1.2979 µs 1.3190 µs 1.3413 µs]
                        change: [+3.8729% +6.1442% +8.1207%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 100 measurements (10.00%)
  10 (10.00%) high mild

Benchmark Unmarshal     time:   [3.8133 µs 3.8215 µs 3.8313 µs]
                        change: [−3.9443% −3.5412% −3.1677%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  3 (3.00%) high mild
  8 (8.00%) high severe
```