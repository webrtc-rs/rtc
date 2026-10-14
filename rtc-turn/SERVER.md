# Sans-I/O UDP TURN server

The `server` module provides a TURN server state machine without sockets, background tasks,
runtime dependencies or ambient clock reads. It reuses `rtc-stun` and `rtc-turn::proto` codecs.
Every protocol deadline is driven by the host's monotonic `Instant`.

## Hosting

1. Create `Server` with a `ServerConfig`, an application-owned `Authenticator`, an explicit
   `RTCCryptoProvider`, and the host's initial time. Credential callbacks must use local
   snapshots; do not block the protocol loop on storage or HTTP.
2. Pass UDP control traffic to `handle_datagram(now, transport, bytes)`.
3. Drain `poll_event()` until empty. `AllocateRelay` asks the host to bind a UDP relay socket
   of the requested family. Report its advertised address with `complete_allocate`; relay
   port selection, NAT mappings and firewall rules are host responsibilities.
4. Send `SendToClient` through the specified control listener, and `SendToPeer` from the
   specified allocation's relay socket. Forward incoming relay traffic to `handle_peer_data`.
5. Schedule `poll_timeout()` and call `handle_timeout(now)` when it expires. Never move the
   supplied clock backwards. Drain actions after every input and timeout.
6. Close/cancel sockets on `ReleaseRelay`. On shutdown, call `close` and drain all releases.
   On an unrecoverable relay socket failure, call `close_allocation` and drain its release;
   the other allocations remain active. Endpoint errors from UDP ICMP feedback (such as
   Windows `WSAECONNRESET`) do not imply a failed socket. Yield before receiving again
   to avoid tight error retry loops; unrecoverable control listener errors remain fatal.
   A late bind completion rejected as unknown/expired remains host-owned and must be closed.

The server also implements `sansio::Protocol<TaggedBytesMut, (), HostEvent>`. Control input
uses `handle_read`; host bind completions and relay input use `handle_event`. All network
actions, including writes, are delivered in order by `poll_event`, rather than separate
output queues. Hosts may instead use the direct methods above.

The core retains authenticated Allocate success responses for the life of the allocation,
and all other authenticated responses, including errors, for at least 40 seconds. Exact retransmissions
replay the original bytes without renewing allocations, permissions or channels. A changed
request reusing a cached transaction ID is discarded. Duplicate pending Allocate requests
do not create additional sockets. Pending binds reserve replay slots; when the cache is full,
new authenticated requests are discarded without a terminal response rather than emitting
an error that could become a success on retransmission. Unauthenticated challenges remain stateless.

## Supported profile

- UDP control and UDP relay; IPv4 or IPv6 relay selected with REQUESTED-ADDRESS-FAMILY.
- Anonymous STUN Binding and RFC 5766 long-term authentication (MD5 credential key,
  HMAC-SHA1 MESSAGE-INTEGRITY). The caller prepares username/password text before deriving
  keys. Nonces are stateless HMAC-SHA256 tokens bound to the control five-tuple and server
  instance, with a configurable lifetime at most one hour.
- Allocate, Refresh (including explicit lifetime-zero release), CreatePermission, ChannelBind,
  Send/Data indications and ChannelData. Permissions last 300 seconds, bindings 600 seconds.
- RFC 8656's channel range `0x4000..=0x4fff`. ChannelData from client to peer uses the binding;
  peer-to-client traffic always requires an IP permission. Data traffic does not renew either.
- Allocation ownership, per-user/global capacity limits, bounded permission/channel tables,
  replay cache, pending binds and output queue. Expiry reserves release delivery even when
  regular output admission is full; at most `max_allocations` releases can be added.

EVEN-PORT/RESERVATION-TOKEN, DONT-FRAGMENT, dual allocations, TCP/TLS/DTLS control, RFC 6062
TCP relay and RFC 8489 password-algorithm negotiation are follow-up work. Unsupported required
attributes receive 420; unsupported relay transports receive 442. This implementation does
not claim complete RFC 8656 compliance and does not fully resolve rtc issue #37.

## Authentication and deployment policy

The authenticator returns the long-term key for the exact configured realm. Unknown or revoked
users return `None`. An established allocation retains its original key during credential
rotation, so the allocation's identity cannot be silently reassigned. Revoke requests by
returning `None`, and revoke data access with `allow_peer`; allocation expiry/closure is separate.

The default peer policy denies private, loopback, link-local, multicast, unspecified and
broadcast destinations. A deployment may explicitly override it. CreatePermission is an IP
permission: its wire port is ignored, and policy evaluation uses port 1. Port-specific policy
is applied again to channel binding and actual data traffic. The core rejects the control
listener and an allocation's own relay endpoint; other allocations may be peers when both
endpoints use one TURN server. The host must block its listener aliases and
apply deployment-specific network restrictions. UDP Send and ChannelData have no per-packet
integrity, as defined by TURN: the authorized control five-tuple selects the allocation.

Before exposing a host publicly, configure packet rate limits, bandwidth/account quotas,
listener/relay firewall rules, credential provisioning and observability. `ServerConfig`
provides protocol memory/admission bounds, not an operating-system security boundary.

## Example

```sh
cargo run -p rtc-turn --example turn_server_udp -- \
  --listen 127.0.0.1:3478 --public-ip 127.0.0.1 \
  --user alice=password --allow-private-peers
```

The example is a nonblocking `std::net::UdpSocket` driver with a bounded work budget, explicit
relay port range, static ASCII credentials and Ctrl-C cleanup. It uses a simple polling loop;
production hosts should use readiness I/O and the reported protocol deadline. Loopback/private
peer access is opt-in. For public deployment, specify real listener/advertised addresses.
