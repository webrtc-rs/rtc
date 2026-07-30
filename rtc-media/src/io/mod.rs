/// Reads H.264/H.265 Annex B byte streams into NAL units.
pub mod h26x_reader;
/// Writes H.264/H.265 Annex B byte streams.
pub mod h26x_writer;

/// Reads IVF files, the simple container used for VP8, VP9 and AV1.
pub mod ivf_reader;
/// Writes IVF files.
pub mod ivf_writer;
/// Reads Ogg files carrying Opus audio.
pub mod ogg_reader;
/// Writes Ogg files carrying Opus audio.
pub mod ogg_writer;
/// Reassembles inbound RTP packets into complete media samples.
pub mod sample_builder;

use shared::error::Result;

/// A callback that produces a fresh reader or writer, used to restart a stream.
pub type ResetFn<R> = Box<dyn FnMut(usize) -> R>;

// Writer defines an interface to handle
// the creation of media files
/// A sink for RTP packets, such as a file in a container format.
pub trait Writer {
    // Add the content of an RTP packet to the media
    /// Writes one RTP packet's media to the sink.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error, or if the packet cannot be depacketized for this format.
    fn write_rtp(&mut self, pkt: &rtp::Packet) -> Result<()>;
    // close the media
    // Note: close implementation must be idempotent
    /// Finalizes the sink, writing any trailing header or index the format needs.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error while flushing.
    fn close(&mut self) -> Result<()>;
}
