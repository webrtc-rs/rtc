#!/bin/bash -eu
#
# OSS-Fuzz build script for webrtc-rs-rtc
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
#
# This script is run inside the OSS-Fuzz Docker container.
# $OUT is the output directory for fuzz target binaries.
# $LIB_FUZZING_ENGINE is the fuzzing engine flags.
# $CFLAGS / $CXXFLAGS / $RUSTFLAGS are set by the base image.

cd "$SRC/webrtc-rs-rtc"

# Build all fuzz targets for each crate.
# cargo-fuzz compiles with --release and links libFuzzer automatically
# when RUSTFLAGS contains the libfuzzer flags provided by oss-fuzz.

FUZZ_CRATES=(
    rtc-dtls
    rtc-sctp
    rtc-rtcp
    rtc-sdp
    rtc-stun
    rtc-rtp
)

for CRATE in "${FUZZ_CRATES[@]}"; do
    pushd "$CRATE/fuzz"

    # List all fuzz targets for this crate
    TARGETS=$(cargo fuzz list 2>/dev/null || true)

    for TARGET in $TARGETS; do
        cargo fuzz build \
            --fuzz-dir . \
            --release \
            -O \
            "$TARGET" \
            -- \
            $LIB_FUZZING_ENGINE \
            $RUSTFLAGS

        # Copy the compiled binary to $OUT
        cp "target/x86_64-unknown-linux-gnu/release/$TARGET" "$OUT/${CRATE//-/_}_$TARGET" || \
        cp "target/release/fuzzing/$TARGET" "$OUT/${CRATE//-/_}_$TARGET" || true
    done

    popd
done

echo "OSS-Fuzz build complete. Targets in $OUT:"
ls "$OUT/" | grep -v '\.options$' || true
