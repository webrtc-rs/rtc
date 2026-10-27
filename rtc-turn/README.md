<h1 align="center">
 <a href="https://webrtc.rs"><img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc.png" alt="WebRTC.rs"></a>
 <br>
</h1>
<p align="center">
 <a href="https://github.com/webrtc-rs/rtc/actions">
  <img src="https://github.com/webrtc-rs/rtc/workflows/cargo/badge.svg">
 </a>
 <a href="https://codecov.io/gh/webrtc-rs/rtc">
  <img src="https://codecov.io/gh/webrtc-rs/rtc/branch/main/graph/badge.svg">
 </a>
 <a href="https://deps.rs/repo/github/webrtc-rs/rtc">
  <img src="https://deps.rs/repo/github/webrtc-rs/rtc/status.svg">
 </a>
 <a href="https://crates.io/crates/rtc-turn">
  <img src="https://img.shields.io/crates/v/rtc-turn.svg">
 </a>
 <a href="https://docs.rs/rtc-turn">
  <img src="https://docs.rs/rtc-turn/badge.svg">
 </a>
 <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
 </a>
 <a href="https://discord.gg/4Ju8UHdXMs">
  <img src="https://img.shields.io/discord/800204819540869120?logo=discord" alt="Discord">
 </a>
</p>
<p align="center">
 RTC TURN Protocol in Rust With Sans-IO
</p>

## Server

`rtc_turn::server::Server` is a TURN server without sockets or a clock: feed it datagrams (from the
listening socket and from each relay socket), time, and the result of binding relay sockets, and
send what it produces. See `examples/turn_server_udp.rs` for a complete tokio server and
`examples/turn_echo_check.rs` for a client that checks a relay end to end; `interop/run-turn.sh`
runs both against pion's TURN server and client.

### TCP allocations (RFC 6062)

A client that asks for a TCP allocation (`Client::allocate_tcp`) gets a relay that speaks TCP to its
peers. The server asks the application to listen on the relay address (`BindRelayTcp`), to connect to
a peer from it (`ConnectPeer`), and to splice a client's second connection to a peer connection
(`BindData`), and is told how it went (`peer_connected`, `peer_connect_failed`, `peer_accepted`).
`examples/turn_server_tcp.rs` is a complete tokio host; `interop/run-turn.sh` runs pion's
`AllocateTCP` client against it: outbound connections, a peer connecting in, and data both ways.
