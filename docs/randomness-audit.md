# ICE and SCTP randomness audit

## Scope

`RTCRandom` is the workspace boundary for cryptographically secure randomness when a component naturally owns an `RTCCryptoProvider`. It is not a replacement for every random-looking value in the workspace. Standalone crates may retain a direct CSPRNG when adding provider ownership would distort their public API, while deterministic protocol fields and test fixtures should remain deterministic.

## ICE

| Value | Security role | Source and decision |
| --- | --- | --- |
| Local username fragment | Short-term ICE credential | `Agent` generates it through `RTCCryptoProvider::random()`. The standalone compatibility helper retains `rand`'s thread-local CSPRNG. An application-supplied value remains unchanged. |
| Local password | Short-term ICE credential | `Agent` generates it through `RTCCryptoProvider::random()`. The standalone compatibility helper retains `rand`'s thread-local CSPRNG. An application-supplied value remains unchanged. |
| Controlling/controlled tie breaker | Unpredictable role-conflict input | Generated through `RTCCryptoProvider::random()` because `Agent` already owns the provider. |
| STUN transaction ID | Request correlation with an unpredictability requirement | `rtc-stun` retains its documented direct CSPRNG path because a `Message` can be constructed without provider ownership. This is separate from STUN integrity and fingerprint operations, which use the configured provider. |
| Candidate ID | Local uniqueness and diagnostics | Retains the direct CSPRNG helper. It is neither a credential nor a cryptographic identity, and passing a provider solely for this field would add unnecessary coupling. |
| Candidate foundation | Candidate grouping and redundancy elimination | Deterministic CRC32C over candidate properties. It is intentionally not random or secret. |
| mDNS host name | Privacy-preserving local alias | Retains UUID v4 generation through the UUID crate's secure random source. The mDNS subsystem does not naturally own the provider. |
| Explicit configuration and test values | Application policy and deterministic fixtures | Preserved exactly as supplied. Tests may use deterministic `RTCRandom` implementations to verify provider routing and error propagation. |

## SCTP

| Value | Security role | Source and decision |
| --- | --- | --- |
| Verification tag / association ID | Unpredictable nonzero SCTP verification tag | Generated with `rand`'s thread-local CSPRNG and rejected if zero. `rtc-sctp` remains independently usable and does not otherwise need an RTC crypto provider. |
| Initial TSN | Unpredictable starting sequence number | Generated with `rand`'s thread-local CSPRNG and adjusted to be nonzero. Provider propagation would add ownership solely for this field. |
| State-cookie bytes | Unpredictable 256-bit challenge echoed by the peer | Generated with `rand`'s thread-local CSPRNG. Received cookies are compared in constant time. The current in-memory cookie design does not encrypt, authenticate, or serialize server state into the value. |
| Retransmission counters, sequence arithmetic, and timers | Derived protocol state | Deterministic values derived from negotiated state and elapsed time; no random source is appropriate. |
| `ParamRandom` | Peer-provided extension negotiation input | Parsed from the peer rather than generated locally. It is not an application randomness boundary. |
| Unit-test packets and fixtures | Reproducible protocol inputs | Fixed constants remain intentional. Tests for generated values check invariants rather than depending on exact output. |

## Provider boundary decision

ICE already owns `Arc<dyn RTCCryptoProvider>` for STUN operations, so routing credential and tie-breaker generation through the same provider is a natural extension of that ownership. SCTP has no cryptographic operation requiring `RTCCrypto`, and its few security-sensitive random values are safely served by its existing direct CSPRNG. Therefore this phase does not add an `rtc-crypto` dependency or provider parameter to `rtc-sctp`.
