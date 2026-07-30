#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use self::windows::ifaces;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use self::unix::ifaces;

/// Enumerates local network interfaces.
///
/// This is the fallback for platforms that are neither Windows nor Unix: it always returns
/// [`ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported). ICE gathering treats that as
/// "no host candidates from interface enumeration" and falls back to the addresses the caller
/// supplied explicitly.
///
/// # Errors
///
/// Always fails on such platforms.
#[cfg(not(any(target_family = "windows", target_family = "unix")))]
pub fn ifaces() -> Result<Vec<super::Interface>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ifaces is not supported on this platform",
    ))
}
