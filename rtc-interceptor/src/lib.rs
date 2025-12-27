#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use std::collections::HashMap;

pub mod stream_info;

/// Attributes are a generic key/value store used by interceptors
pub type Attributes = HashMap<usize, usize>;
