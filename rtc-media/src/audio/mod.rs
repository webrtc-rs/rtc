/// Multi-channel audio buffers in interleaved or deinterleaved layout.
pub mod buffer;
mod sample;

pub use sample::Sample;

mod sealed {
    pub trait Sealed {}
}
