/// `ICE-CONTROLLING` and `ICE-CONTROLLED`, which resolve role conflicts.
pub mod control;
/// `DTLS-IN-STUN` and `DTLS-IN-STUN-ACKNOWLEDGEMENT`, which carry DTLS inside connectivity checks.
pub mod dtls_in_stun;
/// The nomination attribute of draft-thatcher-ice-renomination.
pub mod nomination;
/// The `PRIORITY` attribute carried in connectivity checks.
pub mod priority;
/// The `USE-CANDIDATE` flag, by which the controlling agent nominates a pair.
pub mod use_candidate;
