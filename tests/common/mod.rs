//! Shared helpers for the interop tests.

/// Installs a process-wide rustls `CryptoProvider` if one is not already installed.
///
/// The interop tests drive the published `webrtc` crate alongside this one, and its `dtls 0.13`
/// dependency asks rustls to infer the provider from crate features. That inference only works
/// when exactly one of rustls' `ring`/`aws-lc-rs` features is enabled — but in a test build both
/// are: `dtls 0.13` turns on `rustls/ring` while `rtc` turns on whichever its own feature selects.
/// Cargo unifies the two, rustls finds an ambiguity, and the old crate panics.
///
/// Naming a provider here resolves it for that crate. `rtc` itself no longer consults this
/// default — it passes its provider explicitly (see `rtc_dtls::config`) — so which one we install
/// only has to satisfy the old code. `ring` is always available in a test build: either `rtc`
/// selected it, or `dtls 0.13` pulled it in.
///
/// Idempotent, and safe to call from every test: `install_default` returns `Err` once a provider
/// is set, which is ignored here, so the first caller wins and an application that installed its
/// own is unaffected.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Whether this machine delivers an IPv4 multicast datagram to a listener on the loopback
/// interface, which is what multicast DNS needs to resolve a peer running on the same host.
///
/// Virtualised CI hosts (notably macOS runners) can send multicast without ever delivering it back;
/// a test of mDNS there would time out for a reason that has nothing to do with the code under test.
/// Tests that need it call this first and say so when they skip.
#[allow(dead_code)]
pub fn multicast_loopback_works() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, SocketAddr};
    let group = Ipv4Addr::new(224, 0, 0, 251);
    // Exactly what multicast DNS does: the well-known port, shared with whoever else listens on it,
    // joined on the loopback interface.
    let probe = || -> std::io::Result<bool> {
        let rx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        rx.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        rx.set_reuse_port(true)?;
        rx.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5353)).into())?;
        rx.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)?;
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

        let tx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        tx.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        tx.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
        tx.set_multicast_loop_v4(true)?;
        tx.send_to(b"probe", &SocketAddr::from((group, 5353)).into())?;

        // Anything else listening on 5353 may be heard too; only our own datagram counts.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 512];
        while std::time::Instant::now() < deadline {
            match rx.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let got: Vec<u8> = buf[..n]
                        .iter()
                        .map(|b| unsafe { b.assume_init() })
                        .collect();
                    if got == b"probe" {
                        return Ok(true);
                    }
                }
                Err(_) => return Ok(false),
            }
        }
        Ok(false)
    };
    probe().unwrap_or(false)
}
