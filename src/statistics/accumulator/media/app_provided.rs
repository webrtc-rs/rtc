//! Application-provided statistics update types.
//!
//! Since sansio doesn't handle media encoding/decoding, these types allow
//! the application to provide stats that require access to the encoder,
//! decoder, or audio processing pipeline.

/// Decoder statistics provided by the application.
///
/// These stats are for video decoding and are typically
/// collected from the video decoder in the application layer.
#[derive(Debug, Clone, Default)]
pub struct DecoderStatsUpdate {
    /// Total frames decoded.
    pub frames_decoded: u32,
    /// Key frames decoded.
    pub key_frames_decoded: u32,
    /// Frames rendered to the display.
    pub frames_rendered: u32,
    /// Width of decoded frames.
    pub frame_width: u32,
    /// Height of decoded frames.
    pub frame_height: u32,
    /// Sum of QP values for decoded frames.
    pub qp_sum: u64,
    /// Total time spent decoding in seconds.
    pub total_decode_time: f64,
    /// Total inter-frame delay in seconds.
    pub total_inter_frame_delay: f64,
    /// Total squared inter-frame delay.
    pub total_squared_inter_frame_delay: f64,
    /// Name of the decoder implementation.
    pub decoder_implementation: String,
    /// Whether the decoder is power efficient.
    pub power_efficient_decoder: bool,
}

/// Encoder statistics provided by the application.
///
/// These stats are for video encoding and are typically
/// collected from the video encoder in the application layer.
#[derive(Debug, Clone, Default)]
pub struct EncoderStatsUpdate {
    /// Width of encoded frames.
    pub frame_width: u32,
    /// Height of encoded frames.
    pub frame_height: u32,
    /// Total frames encoded.
    pub frames_encoded: u32,
    /// Key frames encoded.
    pub key_frames_encoded: u32,
    /// Sum of QP values for encoded frames.
    pub qp_sum: u64,
    /// Total time spent encoding in seconds.
    pub total_encode_time: f64,
    /// Name of the encoder implementation.
    pub encoder_implementation: String,
    /// Whether the encoder is power efficient.
    pub power_efficient_encoder: bool,
    /// Scalability mode (e.g., "L1T3").
    pub scalability_mode: String,
}

/// Audio receiver statistics provided by the application.
///
/// These stats are for audio reception and decoding, typically
/// collected from the audio decoder/jitter buffer in the application layer.
#[derive(Debug, Clone, Default)]
pub struct AudioReceiverStatsUpdate {
    /// Total audio samples received.
    pub total_samples_received: u64,
    /// Audio samples concealed due to packet loss.
    pub concealed_samples: u64,
    /// Silent samples inserted for concealment.
    pub silent_concealed_samples: u64,
    /// Number of concealment events.
    pub concealment_events: u64,
    /// Samples inserted for deceleration (playout slowdown).
    pub inserted_samples_for_deceleration: u64,
    /// Samples removed for acceleration (playout speedup).
    pub removed_samples_for_acceleration: u64,
    /// Current audio level (0.0 - 1.0).
    pub audio_level: f64,
    /// Total audio energy in joules.
    pub total_audio_energy: f64,
    /// Total duration of audio samples in seconds.
    pub total_samples_duration: f64,
    /// Jitter buffer delay in seconds.
    pub jitter_buffer_delay: f64,
    /// Jitter buffer target delay in seconds.
    pub jitter_buffer_target_delay: f64,
    /// Number of samples emitted from jitter buffer.
    pub jitter_buffer_emitted_count: u64,
}

/// Audio source statistics provided by the application.
///
/// These stats are for audio capture, typically collected from
/// the audio capture device in the application layer.
#[derive(Debug, Clone, Default)]
pub struct AudioSourceStatsUpdate {
    /// Current audio level (0.0 - 1.0).
    pub audio_level: f64,
    /// Total audio energy in joules.
    pub total_audio_energy: f64,
    /// Total duration of audio samples in seconds.
    pub total_samples_duration: f64,
    /// Echo return loss in decibels.
    pub echo_return_loss: f64,
    /// Echo return loss enhancement in decibels.
    pub echo_return_loss_enhancement: f64,
}

/// Video source statistics provided by the application.
///
/// These stats are for video capture, typically collected from
/// the video capture device in the application layer.
#[derive(Debug, Clone, Default)]
pub struct VideoSourceStatsUpdate {
    /// Width of captured frames.
    pub width: u32,
    /// Height of captured frames.
    pub height: u32,
    /// Total frames captured.
    pub frames: u32,
    /// Current capture frame rate.
    pub frames_per_second: f64,
}

/// Audio playout statistics provided by the application.
///
/// These stats are for audio playout, typically collected from
/// the audio output device in the application layer.
#[derive(Debug, Clone, Default)]
pub struct AudioPlayoutStatsUpdate {
    /// Duration of synthesized samples in seconds.
    pub synthesized_samples_duration: f64,
    /// Number of sample synthesis events.
    pub synthesized_samples_events: u32,
    /// Total duration of samples played in seconds.
    pub total_samples_duration: f64,
    /// Total playout delay in seconds.
    pub total_playout_delay: f64,
    /// Total number of samples played.
    pub total_samples_count: u64,
}
