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

    # List all fuzz targets for this crate (fail build if cargo-fuzz is broken)
    TARGETS=$(cargo fuzz list)
    if [ -z "$TARGETS" ]; then
        echo "ERROR: No fuzz targets found for $CRATE" >&2
        exit 1
    fi

    for TARGET in $TARGETS; do
        cargo fuzz build \
            --fuzz-dir . \
            --release \
            "$TARGET"

        # Copy the compiled binary to $OUT
        OUTPUT_PATH="$OUT/${CRATE//-/_}_$TARGET"
        if [ -f "target/x86_64-unknown-linux-gnu/release/$TARGET" ]; then
            cp "target/x86_64-unknown-linux-gnu/release/$TARGET" "$OUTPUT_PATH"
        elif [ -f "target/release/fuzzing/$TARGET" ]; then
            cp "target/release/fuzzing/$TARGET" "$OUTPUT_PATH"
        else
            echo "ERROR: Failed to locate built fuzz target binary for $CRATE/$TARGET" >&2
            exit 1
        fi
    done

    popd
done

echo "OSS-Fuzz build complete. Targets in $OUT:"
ls "$OUT/" | grep -v '\.options$' || true
