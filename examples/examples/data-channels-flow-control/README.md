# data-channels-flow-control

This example demonstrates how to use the following property / methods.

* pub fn set_buffered_amount_low_threshold(&self, th: usize)
* pub fn buffered_amount_low_threshold(&self) -> usize
* pub fn on_buffered_amount_low(&self, f: OnBufferedAmountLowFn)
* pub fn set_buffered_amount_high_threshold(&self, th: usize)
* pub fn buffered_amount_high_threshold(&self) -> usize
* pub fn on_buffered_amount_high(&self, f: OnBufferedAmountHighFn)

These methods are equivalent to that of JavaScript WebRTC API.
See <https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel> for more details.

## When do we need it?

send or send_text methods are called on DataChannel to send data to the connected peer.
The methods return immediately, but it does not mean the data was actually sent onto
the wire. Instead, it is queued in a buffer until it actually gets sent out to the wire.

When you have a large amount of data to send, it is an application's responsibility to
control the buffered amount in order not to indefinitely grow the buffer size to eventually
exhaust the memory.

The rate you wish to send data might be much higher than the rate the data channel can
actually send to the peer over the Internet. The above properties/methods help your
application to pace the amount of data to be pushed into the data channel.

## How to run the example code

The demo code implements two endpoints (requester and responder) in it.

```plain
                        signaling messages
           +----------------------------------------+
           |                                        |
           v                                        v
   +---------------+                        +---------------+
   |               |          data          |               |
   |   requester   |----------------------->|   responder   |
   |:PeerConnection|                        |:PeerConnection|
   +---------------+                        +---------------+
```

First requester and responder will exchange signaling message to establish a peer-to-peer
connection, and data channel (label: "data").

Once the data channel is successfully opened, requester will start sending a series of
1024-byte packets to responder, until you kill the process by Ctrl+С.

Here's how to run the code:

```shell
/cargo run --release --example data-channels-flow-control
    Finished `release` profile [optimized] target(s) in 0.11s
     Running `target/release/examples/data-channels-flow-control`
Press Ctrl-C to stop
Responder listening on 127.0.0.1:64124
Requester listening on 127.0.0.1:57338
Responder: Data channel opened
Requester: Data channel opened
Throughput is about 116.599 Mbps
Throughput is about 233.999 Mbps
Throughput is about 232.550 Mbps
Throughput is about 231.028 Mbps
Throughput is about 229.491 Mbps
Throughput is about 227.874 Mbps
Throughput is about 226.476 Mbps
Throughput is about 224.842 Mbps
Throughput is about 223.859 Mbps
Throughput is about 222.279 Mbps
...
```
