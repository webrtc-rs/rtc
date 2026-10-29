# pion/sdp oracle

`tests/pion_golden.rs` replays inputs through this crate and compares with what pion/sdp
(v3.0.20) did with the same input. The golden file `tests/data/pion_sdp_golden.jsonl` was
produced like this:

1. Instrument a copy of `github.com/pion/sdp/v3@v3.0.20`: rename `SessionDescription.UnmarshalString`
   and wrap it to append every input pion's own tests feed it to `$ORACLE_OUT` (JSONL, base64).
   Run `go test ./...` there.
2. `python3 corpus.py <dir> <count> <max-seed-bytes>` mutates those seeds deterministically
   (dropped/duplicated/swapped lines, garbage tokens, truncation, LF-only endings, ...).
3. `go run ./tests/oracle < corpus.jsonl > golden.jsonl` records pion's verdict and re-marshalled text.

For a large sweep: `PION_SDP_GOLDEN=big.jsonl PION_SDP_REPORT=report.jsonl cargo test --test pion_golden`.
Intended divergences from pion are listed in `pion_golden.rs`.
