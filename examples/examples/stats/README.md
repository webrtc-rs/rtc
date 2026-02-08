# stats

stats demonstrates how to use the [webrtc-stats](https://www.w3.org/TR/webrtc-stats/) implementation provided by
WebRTC-rs.

This API gives you access to the statistical information about a PeerConnection. This can help you understand what is
happening
during a session and why.

## Instructions

### Open stats example page

[jsfiddle.net](https://jsfiddle.net/s179hacu/) you should see your Webcam, two text-areas and two buttons:
`Copy browser SDP to clipboard`, `Start Session`.

### Run stats, with your browsers SessionDescription as stdin

In the jsfiddle the top textarea is your browser's Session Description. Press `Copy browser SDP to clipboard` or copy
the base64 string manually.
We will use this value in the next step.

#### Linux/macOS

Run `echo $BROWSER_SDP | cargo run --example stats`

#### Windows

1. Paste the SessionDescription into a file.
1. Run `cargo run --example stats < my_file`

### Input stats' SessionDescription into your browser

Copy the text that `stats` just emitted and copy into second text area

### Hit 'Start Session' in jsfiddle

The `stats` program will now print WebRTC statistics every 5 seconds, including InboundRTPStreamStats for each incoming stream and Remote IP+Ports.
You will see the following in your console:

```
=== WebRTC Stats ===
Peer Connection Stats:
  Data channels opened: 0
  Data channels closed: 0

Inbound RTP Stats for: video/vp8
  SSRC: 1234567890
  Packets Received: 1255
  Bytes Received: 1361125
  Packets Lost: 0
  Jitter: 588.9559641717999

Inbound RTP Stats for: audio/opus
  SSRC: 987654321
  Packets Received: 2450
  Bytes Received: 245000
  Packets Lost: 0
  Jitter: 12.5

Remote Candidate: IP(192.168.1.93) Port(59239)
====================
```

## What it demonstrates

This example demonstrates:
1. How to use `peer_connection.get_stats()` API to retrieve WebRTC statistics
2. How to access different types of stats from the stats report:
   - Peer connection stats via `report.peer_connection()`
   - Inbound RTP stream stats via `report.inbound_rtp_streams()`
   - ICE candidate stats via `report.iter_by_type()`
3. How to integrate stats collection into the event loop pattern
4. Periodic stats reporting at regular intervals (every 5 seconds)

Congrats, you have used WebRTC-rs! Now start building something cool
