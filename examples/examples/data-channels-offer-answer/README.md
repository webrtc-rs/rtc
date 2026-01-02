# data-channels-offer-answer

data-channels-offer-answer is an example of two webrtc-rs instances communicating directly!

The SDP offer and answer are exchanged automatically over HTTP.
The `data-channels-answer` side acts like a HTTP server and should therefore be ran first.

## Instructions

First run `data-channels-answer`:

```shell
cargo build --example data-channels-answer
./target/debug/examples/data-channels-answer
```

Next, run `data-channels-offer`:

```shell
cargo build --example data-channels-offer
./target/debug/examples/data-channels-offer
```

You should see them connect and start to exchange messages.
