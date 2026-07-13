#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use self::windows::ifaces;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use self::unix::ifaces;

#[cfg(not(any(target_family = "windows", target_family = "unix")))]
pub fn ifaces() -> Result<Vec<super::Interface>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ifaces is not supported on this platform",
    ))
}
