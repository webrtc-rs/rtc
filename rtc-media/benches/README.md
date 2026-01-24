### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-media --bench bench

     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [163.04 µs 164.17 µs 165.51 µs]
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [173.43 µs 173.54 µs 173.68 µs]
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.38s
     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [165.07 µs 166.93 µs 169.17 µs]
                        change: [−0.7800% +0.5789% +1.9084%] (p = 0.39 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  9 (9.00%) high mild
  3 (3.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [185.39 µs 193.68 µs 204.31 µs]
                        change: [+9.4776% +13.570% +18.775%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 16 outliers among 100 measurements (16.00%)
  4 (4.00%) high mild
  12 (12.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.17s
     Running benches/bench.rs (target/release/deps/bench-7400f2f028293f09)
Gnuplot not found, using plotters backend
Media/Buffer/Interleaved to Deinterleaved
                        time:   [160.14 µs 160.28 µs 160.45 µs]
                        change: [−4.2455% −3.2315% −2.2214%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 14 outliers among 100 measurements (14.00%)
  3 (3.00%) high mild
  11 (11.00%) high severe
Media/Buffer/Deinterleaved to Interleaved
                        time:   [173.40 µs 173.46 µs 173.52 µs]
                        change: [−15.667% −12.005% −8.5621%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  1 (1.00%) high mild
  4 (4.00%) high severe

```