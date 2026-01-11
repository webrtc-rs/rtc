// Copyright (C) 2025, RTC Contributors
// All rights reserved.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn main() {
    // MacOS: Allow cdylib to link with undefined symbols
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    #[cfg(feature = "ffi")]
    if target_os != "windows" {
        cdylib_link_lines::metabuild();
    }
}
