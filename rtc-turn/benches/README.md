### Benchmark Results

MacBook Air M3 24 GB MacOS 26.2

```
cargo bench --package rtc-turn --bench bench

     Running benches/bench.rs (target/release/deps/bench-f0b55587bb6974f5)
Gnuplot not found, using plotters backend
BenchmarkIsChannelData  time:   [1.3314 ns 1.3425 ns 1.3606 ns]
Found 12 outliers among 100 measurements (12.00%)
  6 (6.00%) high mild
  6 (6.00%) high severe

BenchmarkChannelData_Encode
                        time:   [2.6582 ns 2.6727 ns 2.6918 ns]
Found 17 outliers among 100 measurements (17.00%)
  3 (3.00%) high mild
  14 (14.00%) high severe

BenchmarkChannelData_Decode
                        time:   [29.238 ns 29.260 ns 29.289 ns]
Found 7 outliers among 100 measurements (7.00%)
  7 (7.00%) high severe

BenchmarkChannelNumber/AddTo
                        time:   [36.605 ns 36.714 ns 36.838 ns]
Found 19 outliers among 100 measurements (19.00%)
  8 (8.00%) low mild
  2 (2.00%) high mild
  9 (9.00%) high severe

BenchmarkChannelNumber/GetFrom
                        time:   [16.636 ns 16.712 ns 16.815 ns]
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) high mild
  9 (9.00%) high severe

BenchmarkData/AddTo     time:   [25.776 ns 25.828 ns 25.891 ns]
Found 19 outliers among 100 measurements (19.00%)
  3 (3.00%) high mild
  16 (16.00%) high severe

BenchmarkData/AddToRaw  time:   [25.966 ns 26.088 ns 26.204 ns]
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe

BenchmarkLifetime/AddTo time:   [37.087 ns 37.153 ns 37.230 ns]
Found 15 outliers among 100 measurements (15.00%)
  13 (13.00%) high mild
  2 (2.00%) high severe

BenchmarkLifetime/GetFrom
                        time:   [16.364 ns 16.384 ns 16.407 ns]
Found 15 outliers among 100 measurements (15.00%)
  8 (8.00%) high mild
  7 (7.00%) high severe

```

```
    Finished `bench` profile [optimized] target(s) in 0.27s
     Running benches/bench.rs (target/release/deps/bench-f0b55587bb6974f5)
Gnuplot not found, using plotters backend
BenchmarkIsChannelData  time:   [1.2485 ns 1.2559 ns 1.2657 ns]
                        change: [−7.2706% −6.4213% −5.6675%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 12 outliers among 100 measurements (12.00%)
  5 (5.00%) high mild
  7 (7.00%) high severe

BenchmarkChannelData_Encode
                        time:   [2.6583 ns 2.6631 ns 2.6688 ns]
                        change: [−0.5815% −0.0494% +0.4529%] (p = 0.85 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  1 (1.00%) low mild
  7 (7.00%) high mild
  8 (8.00%) high severe

BenchmarkChannelData_Decode
                        time:   [29.633 ns 29.653 ns 29.678 ns]
                        change: [+0.6590% +1.0927% +1.4690%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 37 outliers among 100 measurements (37.00%)
  17 (17.00%) low severe
  2 (2.00%) low mild
  18 (18.00%) high severe

BenchmarkChannelNumber/AddTo
                        time:   [36.531 ns 36.662 ns 36.811 ns]
                        change: [−0.5255% −0.2245% +0.0845%] (p = 0.16 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) low severe
  2 (2.00%) high mild
  6 (6.00%) high severe

BenchmarkChannelNumber/GetFrom
                        time:   [17.840 ns 18.227 ns 18.694 ns]
                        change: [+3.3041% +4.9524% +7.3607%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe

BenchmarkData/AddTo     time:   [26.865 ns 27.342 ns 27.904 ns]
                        change: [+5.8419% +8.4213% +11.545%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 9 outliers among 100 measurements (9.00%)
  3 (3.00%) high mild
  6 (6.00%) high severe

BenchmarkData/AddToRaw  time:   [26.502 ns 26.994 ns 27.616 ns]
                        change: [+2.2390% +3.8693% +5.7122%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe

BenchmarkLifetime/AddTo time:   [40.324 ns 41.531 ns 43.005 ns]
                        change: [+7.2175% +11.565% +17.975%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 13 outliers among 100 measurements (13.00%)
  2 (2.00%) high mild
  11 (11.00%) high severe

BenchmarkLifetime/GetFrom
                        time:   [16.557 ns 16.615 ns 16.676 ns]
                        change: [+2.3231% +3.1213% +3.9808%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
```

```
    Finished `bench` profile [optimized] target(s) in 0.25s
     Running benches/bench.rs (target/release/deps/bench-f0b55587bb6974f5)
Gnuplot not found, using plotters backend
BenchmarkIsChannelData  time:   [1.2526 ns 1.2611 ns 1.2716 ns]
                        change: [+1.7377% +3.6625% +5.9090%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  3 (3.00%) high mild
  3 (3.00%) high severe

BenchmarkChannelData_Encode
                        time:   [2.6831 ns 2.7086 ns 2.7427 ns]
                        change: [+0.5156% +1.3428% +2.5390%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe

BenchmarkChannelData_Decode
                        time:   [29.297 ns 29.407 ns 29.524 ns]
                        change: [−0.9260% −0.5419% −0.1954%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild

BenchmarkChannelNumber/AddTo
                        time:   [37.785 ns 37.913 ns 38.056 ns]
                        change: [+3.6197% +4.0835% +4.5478%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

BenchmarkChannelNumber/GetFrom
                        time:   [16.579 ns 16.600 ns 16.631 ns]
                        change: [−6.9895% −5.1022% −3.5130%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 17 outliers among 100 measurements (17.00%)
  3 (3.00%) high mild
  14 (14.00%) high severe

BenchmarkData/AddTo     time:   [26.284 ns 26.564 ns 26.881 ns]
                        change: [−8.7193% −6.2341% −3.8866%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 7 outliers among 100 measurements (7.00%)
  4 (4.00%) high mild
  3 (3.00%) high severe

BenchmarkData/AddToRaw  time:   [25.374 ns 25.431 ns 25.497 ns]
                        change: [−6.2383% −4.5269% −2.9971%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  4 (4.00%) high mild
  6 (6.00%) high severe

BenchmarkLifetime/AddTo time:   [40.364 ns 42.422 ns 44.620 ns]
                        change: [−9.2185% −3.9022% +1.1160%] (p = 0.16 > 0.05)
                        No change in performance detected.
Found 15 outliers among 100 measurements (15.00%)
  3 (3.00%) high mild
  12 (12.00%) high severe

BenchmarkLifetime/GetFrom
                        time:   [20.553 ns 22.113 ns 23.744 ns]
                        change: [+13.904% +19.532% +25.584%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

```