FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/webrtc-rs-rtc
COPY oss-fuzz/build.sh $SRC/build.sh
WORKDIR $SRC/webrtc-rs-rtc
