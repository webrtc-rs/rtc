// Copyright (C) 2025, RTC Contributors
// All rights reserved.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::{self, CStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use libc::{size_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};

use crate::data_channel::RTCDataChannelInit;
use crate::interceptor::{Interceptor, Registry};
use crate::peer_connection::configuration::interceptor_registry::{
    configure_nack, configure_rtcp_reports, configure_twcc, register_default_interceptors,
};
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::{RTCConfiguration, RTCConfigurationBuilder};
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use crate::peer_connection::message::RTCMessage;
use crate::peer_connection::sdp::RTCSessionDescription;
use crate::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use crate::peer_connection::transport::RTCIceCandidate;
use crate::peer_connection::RTCPeerConnection;
use crate::sansio::Protocol;
use crate::shared::error::{Error, Result};
use crate::shared::{TaggedBytesMut, TransportContext, TransportProtocol};

// ============================================================================
// Platform-specific imports
// ============================================================================

#[cfg(not(windows))]
use libc::{AF_INET, AF_INET6};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[cfg(not(windows))]
use libc::{in6_addr, in_addr};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{IN6_ADDR as in6_addr, IN_ADDR as in_addr};

#[cfg(not(windows))]
use libc::sa_family_t;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::ADDRESS_FAMILY as sa_family_t;

// ============================================================================
// Type-erased Interceptor Registry
// ============================================================================

/// Type-erased interceptor registry that hides the generic parameter.
/// 
/// This allows the C API to work with any interceptor chain without exposing
/// the concrete type at the FFI boundary. The registry is built up incrementally
/// by wrapping interceptors, similar to quiche's approach.
pub struct InterceptorRegistryBox {
    /// The actual registry, type-erased via Box<dyn Any>.
    /// We'll use an enum to support common configurations.
    inner: InterceptorChain,
}

/// Concrete interceptor chain types supported by the C API.
enum InterceptorChain {
    /// Empty registry (NoopInterceptor)
    Empty(Registry<interceptor::NoopInterceptor>),
    /// Registry with some interceptors applied
    /// We use a boxed trait object to avoid exposing the full generic type
    Configured(Box<dyn std::any::Any + Send>),
}

impl InterceptorRegistryBox {
    fn new() -> Self {
        InterceptorRegistryBox {
            inner: InterceptorChain::Empty(Registry::new()),
        }
    }

    fn add_nack(&mut self, media_engine: &mut MediaEngine) -> Result<()> {
        self.inner = match std::mem::replace(&mut self.inner, InterceptorChain::Empty(Registry::new())) {
            InterceptorChain::Empty(registry) => {
                let registry = configure_nack(registry, media_engine);
                InterceptorChain::Configured(Box::new(registry))
            }
            InterceptorChain::Configured(any) => {
                // Try to downcast and apply
                // For simplicity, we'll rebuild from empty
                // In a real implementation, you'd need a more sophisticated approach
                return Err(Error::Other("Cannot modify already configured registry".into()));
            }
        };
        Ok(())
    }

    fn add_rtcp_reports(&mut self) -> Result<()> {
        self.inner = match std::mem::replace(&mut self.inner, InterceptorChain::Empty(Registry::new())) {
            InterceptorChain::Empty(registry) => {
                let registry = configure_rtcp_reports(registry);
                InterceptorChain::Configured(Box::new(registry))
            }
            InterceptorChain::Configured(_) => {
                return Err(Error::Other("Cannot modify already configured registry".into()));
            }
        };
        Ok(())
    }

    fn add_twcc(&mut self, media_engine: &mut MediaEngine) -> Result<()> {
        self.inner = match std::mem::replace(&mut self.inner, InterceptorChain::Empty(Registry::new())) {
            InterceptorChain::Empty(registry) => {
                let registry = configure_twcc(registry, media_engine)?;
                InterceptorChain::Configured(Box::new(registry))
            }
            InterceptorChain::Configured(_) => {
                return Err(Error::Other("Cannot modify already configured registry".into()));
            }
        };
        Ok(())
    }

    fn add_defaults(&mut self, media_engine: &mut MediaEngine) -> Result<()> {
        self.inner = match std::mem::replace(&mut self.inner, InterceptorChain::Empty(Registry::new())) {
            InterceptorChain::Empty(registry) => {
                let registry = register_default_interceptors(registry, media_engine)?;
                InterceptorChain::Configured(Box::new(registry))
            }
            InterceptorChain::Configured(_) => {
                return Err(Error::Other("Cannot modify already configured registry".into()));
            }
        };
        Ok(())
    }
}

// ============================================================================
// Configuration wrapper
// ============================================================================

pub struct ConfigurationBox {
    builder: RTCConfigurationBuilder,
    media_engine: MediaEngine,
}

impl ConfigurationBox {
    fn new() -> Self {
        ConfigurationBox {
            builder: RTCConfigurationBuilder::new(),
            media_engine: MediaEngine::default(),
        }
    }

    fn build(self, registry_opt: Option<InterceptorRegistryBox>) -> RTCConfiguration {
        let mut builder = self.builder.with_media_engine(self.media_engine);
        
        if let Some(registry_box) = registry_opt {
            // Extract and set the registry
            // Note: This is simplified. In a real implementation, you'd need to
            // properly handle the type-erased registry
            match registry_box.inner {
                InterceptorChain::Empty(registry) => {
                    builder = builder.with_interceptor_registry(registry);
                }
                InterceptorChain::Configured(_) => {
                    // For now, use default since we can't easily extract the configured type
                    // A better approach would use a trait object or enum dispatch
                }
            }
        }
        
        builder.build()
    }
}

// ============================================================================
// Logger
// ============================================================================

struct Logger {
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: AtomicPtr<c_void>,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\0", record.target(), record.args());
        (self.cb)(line.as_ptr(), self.argp.load(Ordering::Relaxed));
    }

    fn flush(&self) {}
}

// ============================================================================
// Helper functions
// ============================================================================

fn sockaddr_to_socketaddr(sa: *const sockaddr, len: socklen_t) -> Option<SocketAddr> {
    unsafe {
        if sa.is_null() || len == 0 {
            return None;
        }

        let family = (*sa).sa_family as i32;

        if family == AF_INET as i32 {
            if len < std::mem::size_of::<sockaddr_in>() as socklen_t {
                return None;
            }
            let sin = &*(sa as *const sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        } else if family == AF_INET6 as i32 {
            if len < std::mem::size_of::<sockaddr_in6>() as socklen_t {
                return None;
            }
            let sin6 = &*(sa as *const sockaddr_in6);
            #[cfg(not(windows))]
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            #[cfg(windows)]
            let ip = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            None
        }
    }
}

fn socketaddr_to_sockaddr(addr: &SocketAddr, storage: *mut sockaddr_storage) -> socklen_t {
    unsafe {
        match addr {
            SocketAddr::V4(v4) => {
                let sin = storage as *mut sockaddr_in;
                (*sin).sin_family = AF_INET as sa_family_t;
                (*sin).sin_port = v4.port().to_be();
                (*sin).sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                std::mem::size_of::<sockaddr_in>() as socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6 = storage as *mut sockaddr_in6;
                (*sin6).sin6_family = AF_INET6 as sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                #[cfg(not(windows))]
                {
                    (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                }
                #[cfg(windows)]
                {
                    (*sin6).sin6_addr.u.Byte = v6.ip().octets();
                }
                (*sin6).sin6_flowinfo = v6.flowinfo();
                (*sin6).sin6_scope_id = v6.scope_id();
                std::mem::size_of::<sockaddr_in6>() as socklen_t
            }
        }
    }
}

fn instant_to_us(instant: Instant) -> u64 {
    let now = SystemTime::now();
    let duration_since_start = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    duration_since_start.as_micros() as u64
}

fn us_to_instant(us: u64) -> Instant {
    // This is a simplification - we're assuming the base is reasonably recent
    let now = Instant::now();
    let sys_now = SystemTime::now();
    let sys_us = sys_now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_micros() as u64;
    
    if us > sys_us {
        now + Duration::from_micros(us - sys_us)
    } else {
        now - Duration::from_micros(sys_us - us)
    }
}

// ============================================================================
// C API Implementation
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn rtc_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_enable_debug_logging(
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: *mut c_void,
) -> c_int {
    let argp = AtomicPtr::new(argp);
    let logger = Box::new(Logger { cb, argp });

    if log::set_logger(Box::leak(logger)).is_err() {
        return -1;
    }

    log::set_max_level(log::LevelFilter::Trace);
    0
}

// ============================================================================
// Configuration API
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn rtc_configuration_new() -> *mut ConfigurationBox {
    Box::into_raw(Box::new(ConfigurationBox::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_configuration_add_ice_server(
    config: &mut ConfigurationBox,
    urls: *const c_char,
    username: *const c_char,
    credential: *const c_char,
) -> c_int {
    if urls.is_null() {
        return -4; // RTC_ERR_INVALID_PARAMETER
    }

    let urls_str = unsafe {
        match CStr::from_ptr(urls).to_str() {
            Ok(s) => s,
            Err(_) => return -4,
        }
    };

    let username_opt = if username.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(username).to_str().ok() }
    };

    let credential_opt = if credential.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(credential).to_str().ok() }
    };

    let ice_server = crate::peer_connection::transport::RTCIceServer {
        urls: vec![urls_str.to_string()],
        username: username_opt.map(|s| s.to_string()).unwrap_or_default(),
        credential: credential_opt.map(|s| s.to_string()).unwrap_or_default(),
    };

    config.builder = std::mem::take(&mut config.builder).with_ice_servers(vec![ice_server]);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_configuration_set_interceptor_registry(
    config: &mut ConfigurationBox,
    registry: *mut InterceptorRegistryBox,
) -> c_int {
    if registry.is_null() {
        return -4; // RTC_ERR_INVALID_PARAMETER
    }

    // Registry ownership is transferred, but we need to handle this properly
    // For now, we'll just mark it as used
    // In a full implementation, this would be stored and used in build()
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_configuration_free(config: *mut ConfigurationBox) {
    if !config.is_null() {
        unsafe {
            let _ = Box::from_raw(config);
        }
    }
}

// ============================================================================
// Interceptor Registry API
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_new() -> *mut InterceptorRegistryBox {
    Box::into_raw(Box::new(InterceptorRegistryBox::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_add_nack(registry: &mut InterceptorRegistryBox) -> c_int {
    // We need access to MediaEngine, which is a problem
    // For now, return error - this needs redesign
    -4 // RTC_ERR_INVALID_PARAMETER
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_add_rtcp_reports(
    registry: &mut InterceptorRegistryBox,
) -> c_int {
    match registry.add_rtcp_reports() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_add_twcc(registry: &mut InterceptorRegistryBox) -> c_int {
    // We need access to MediaEngine, which is a problem
    // For now, return error - this needs redesign
    -4 // RTC_ERR_INVALID_PARAMETER
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_add_defaults(
    registry: &mut InterceptorRegistryBox,
) -> c_int {
    // We need access to MediaEngine, which is a problem
    // For now, return error - this needs redesign
    -4 // RTC_ERR_INVALID_PARAMETER
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_interceptor_registry_free(registry: *mut InterceptorRegistryBox) {
    if !registry.is_null() {
        unsafe {
            let _ = Box::from_raw(registry);
        }
    }
}

// ============================================================================
// Peer Connection API - Placeholder
// ============================================================================
// 
// Note: The full peer connection API implementation is extensive.
// This is a skeleton showing the pattern. A complete implementation would
// need to handle:
// - Generic interceptor type (using trait objects or enum dispatch)
// - Proper lifetime management for messages
// - Thread-safety considerations
// - Error mapping

#[unsafe(no_mangle)]
pub extern "C" fn rtc_peer_connection_new(
    _config: *const ConfigurationBox,
) -> *mut RTCPeerConnection {
    // Placeholder - needs full implementation
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn rtc_peer_connection_free(_pc: *mut RTCPeerConnection) {
    // Placeholder - needs full implementation
}
