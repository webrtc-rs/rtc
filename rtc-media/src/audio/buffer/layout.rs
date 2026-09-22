use crate::audio::buffer::BufferInfo;
use crate::audio::sealed::Sealed;

/// How multi-channel samples are arranged in a flat buffer.
///
/// Sealed: the only layouts are [`Interleaved`] and [`Deinterleaved`].
pub trait BufferLayout: Sized + Sealed {
    /// The flat index of `frame` on `channel`, for a buffer described by `info`.
    fn index_of(info: &BufferInfo<Self>, channel: usize, frame: usize) -> usize;
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
/// Channels stored one after another: all of channel 0, then all of channel 1.
///
/// A marker type — it has no values.
pub enum Deinterleaved {}

impl Sealed for Deinterleaved {}

impl BufferLayout for Deinterleaved {
    #[inline]
    fn index_of(info: &BufferInfo<Self>, channel: usize, frame: usize) -> usize {
        (channel * info.frames()) + frame
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
/// Frames stored one after another, each holding one sample per channel.
///
/// The layout most audio APIs use, and a marker type with no values.
pub enum Interleaved {}

impl Sealed for Interleaved {}

impl BufferLayout for Interleaved {
    #[inline]
    fn index_of(info: &BufferInfo<Self>, channel: usize, frame: usize) -> usize {
        (frame * info.channels()) + channel
    }
}

#[cfg(test)]
#[inline(always)]
pub(crate) fn deinterleaved<T>(input: &[T], output: &mut [T], channels: usize)
where
    T: Copy,
{
    deinterleaved_by(input, output, channels, |sample| *sample)
}

/// De-interleaves `input` (frame after frame) into `output` (channel after channel), mapping
/// each sample through `f`.
///
/// Mono, stereo and four-channel audio take fast paths: mono is a straight map, and the others
/// split `output` into one slice per channel and walk the input a whole frame at a time. With
/// the channel count fixed at compile time the compiler can vectorize these loops — on ARM64 the
/// stereo and four-channel ones become NEON structure loads (`ld2`, `ld4`) — where the general
/// loop, whose stride is only known at run time, stays scalar. Any other channel count takes
/// that general loop, which reads the input sequentially.
///
/// The order in which `f` is called is unspecified.
///
/// # Panics
///
/// If `input` and `output` differ in length, if `channels` is zero, or if it does not divide
/// the length.
pub(crate) fn deinterleaved_by<T, U, F>(input: &[T], output: &mut [U], channels: usize, f: F)
where
    F: Fn(&T) -> U,
{
    assert_eq!(input.len(), output.len());
    assert_eq!(input.len() % channels, 0);

    let frames = input.len() / channels;
    match channels {
        1 => {
            for (output, input) in output.iter_mut().zip(input) {
                *output = f(input);
            }
        }
        2 => {
            let (left, right) = output.split_at_mut(frames);
            let (input, _) = input.as_chunks::<2>();
            for ((frame, left), right) in input.iter().zip(left).zip(right) {
                *left = f(&frame[0]);
                *right = f(&frame[1]);
            }
        }
        4 => {
            let (front, back) = output.split_at_mut(2 * frames);
            let (channel_0, channel_1) = front.split_at_mut(frames);
            let (channel_2, channel_3) = back.split_at_mut(frames);
            let (input, _) = input.as_chunks::<4>();
            let zipped = input
                .iter()
                .zip(channel_0)
                .zip(channel_1)
                .zip(channel_2)
                .zip(channel_3);
            for ((((frame, sample_0), sample_1), sample_2), sample_3) in zipped {
                *sample_0 = f(&frame[0]);
                *sample_1 = f(&frame[1]);
                *sample_2 = f(&frame[2]);
                *sample_3 = f(&frame[3]);
            }
        }
        _ => {
            let mut interleaved_index = 0;
            for frame in 0..frames {
                let mut deinterleaved_index = frame;
                for _channel in 0..channels {
                    output[deinterleaved_index] = f(&input[interleaved_index]);
                    interleaved_index += 1;
                    deinterleaved_index += frames;
                }
            }
        }
    }
}

#[cfg(test)]
#[inline(always)]
pub(crate) fn interleaved<T>(input: &[T], output: &mut [T], channels: usize)
where
    T: Copy,
{
    interleaved_by(input, output, channels, |sample| *sample)
}

/// Interleaves `input` (channel after channel) into `output` (frame after frame), mapping each
/// sample through `f`.
///
/// The fast paths mirror [`deinterleaved_by`]'s: mono is a straight map, and stereo and
/// four-channel audio split `input` into one slice per channel and fill the output a whole frame
/// at a time, which the compiler can vectorize (NEON structure stores, `st2` and `st4`, on
/// ARM64). Any other channel count takes the general loop, which reads the input sequentially.
///
/// The order in which `f` is called is unspecified.
///
/// # Panics
///
/// If `input` and `output` differ in length, if `channels` is zero, or if it does not divide
/// the length.
pub(crate) fn interleaved_by<T, U, F>(input: &[T], output: &mut [U], channels: usize, f: F)
where
    F: Fn(&T) -> U,
{
    assert_eq!(input.len(), output.len());
    assert_eq!(input.len() % channels, 0);

    let frames = input.len() / channels;
    match channels {
        1 => {
            for (output, input) in output.iter_mut().zip(input) {
                *output = f(input);
            }
        }
        2 => {
            let (left, right) = input.split_at(frames);
            let (output, _) = output.as_chunks_mut::<2>();
            for ((frame, left), right) in output.iter_mut().zip(left).zip(right) {
                frame[0] = f(left);
                frame[1] = f(right);
            }
        }
        4 => {
            let (front, back) = input.split_at(2 * frames);
            let (channel_0, channel_1) = front.split_at(frames);
            let (channel_2, channel_3) = back.split_at(frames);
            let (output, _) = output.as_chunks_mut::<4>();
            let zipped = output
                .iter_mut()
                .zip(channel_0)
                .zip(channel_1)
                .zip(channel_2)
                .zip(channel_3);
            for ((((frame, sample_0), sample_1), sample_2), sample_3) in zipped {
                frame[0] = f(sample_0);
                frame[1] = f(sample_1);
                frame[2] = f(sample_2);
                frame[3] = f(sample_3);
            }
        }
        _ => {
            let mut deinterleaved_index = 0;
            for channel in 0..channels {
                let mut interleaved_index = channel;
                for _frame in 0..frames {
                    output[interleaved_index] = f(&input[deinterleaved_index]);
                    deinterleaved_index += 1;
                    interleaved_index += channels;
                }
            }
        }
    }
}

/// The layout loops as they were before the fast paths, kept as the oracle for differential
/// tests, plus the frame counts those tests sweep.
#[cfg(test)]
pub(crate) mod reference {
    pub(crate) fn deinterleaved_by<T, U, F>(input: &[T], output: &mut [U], channels: usize, f: F)
    where
        F: Fn(&T) -> U,
    {
        assert_eq!(input.len(), output.len());
        assert_eq!(input.len() % channels, 0);

        let frames = input.len() / channels;
        let mut interleaved_index = 0;
        for frame in 0..frames {
            let mut deinterleaved_index = frame;
            for _channel in 0..channels {
                output[deinterleaved_index] = f(&input[interleaved_index]);
                interleaved_index += 1;
                deinterleaved_index += frames;
            }
        }
    }

    pub(crate) fn interleaved_by<T, U, F>(input: &[T], output: &mut [U], channels: usize, f: F)
    where
        F: Fn(&T) -> U,
    {
        assert_eq!(input.len(), output.len());
        assert_eq!(input.len() % channels, 0);

        let frames = input.len() / channels;
        let mut deinterleaved_index = 0;
        for channel in 0..channels {
            let mut interleaved_index = channel;
            for _frame in 0..frames {
                output[interleaved_index] = f(&input[deinterleaved_index]);
                deinterleaved_index += 1;
                interleaved_index += channels;
            }
        }
    }

    /// The channel counts swept: the three fast paths and the general loop either side of them.
    pub(crate) const CHANNELS: std::ops::RangeInclusive<usize> = 1..=8;

    /// The largest frame count swept.
    pub(crate) const MAX_FRAMES: usize = 2048;

    /// Every frame count through 64, which covers each fast path's vector remainder whatever the
    /// vector width, then a stride through [`MAX_FRAMES`]: cheap enough for debug builds.
    pub(crate) fn sampled_frame_counts() -> impl Iterator<Item = usize> + Clone {
        (0..=64)
            .chain((65..MAX_FRAMES).step_by(97))
            .chain([MAX_FRAMES - 1, MAX_FRAMES])
    }

    /// Every frame count through [`MAX_FRAMES`]; for release-mode test runs.
    pub(crate) fn all_frame_counts() -> impl Iterator<Item = usize> + Clone {
        0..=MAX_FRAMES
    }

    /// Distinct values for up to 65,536 samples, far more than the largest sweep uses.
    pub(crate) fn make_i16(index: usize) -> i16 {
        (index as u16).wrapping_mul(40_503) as i16
    }

    pub(crate) fn make_i32(index: usize) -> i32 {
        (index as i32).wrapping_mul(-1_640_531_527)
    }

    /// Distinct, finite floats of both signs, alternating in fours between subnormals and
    /// normals in `0.5..1`.
    pub(crate) fn make_f32(index: usize) -> f32 {
        let sign_and_mantissa = (index as u32).wrapping_mul(0x9E37_79B9) & 0x807F_FFFF;
        let exponent = if index & 4 == 0 { 0 } else { 0x3F00_0000 };
        f32::from_bits(sign_and_mantissa | exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_1_channel() {
        let input: Vec<_> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut output = vec![0; input.len()];
        let channels = 1;

        interleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        assert_eq!(actual, expected);
    }

    #[test]
    fn deinterleaved_1_channel() {
        let input: Vec<_> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut output = vec![0; input.len()];
        let channels = 1;

        deinterleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        assert_eq!(actual, expected);
    }

    #[test]
    fn interleaved_2_channel() {
        let input: Vec<_> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut output = vec![0; input.len()];
        let channels = 2;

        interleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];

        assert_eq!(actual, expected);
    }

    #[test]
    fn deinterleaved_2_channel() {
        let input: Vec<_> = vec![0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];
        let mut output = vec![0; input.len()];
        let channels = 2;

        deinterleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        assert_eq!(actual, expected);
    }

    #[test]
    fn interleaved_3_channel() {
        let input: Vec<_> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut output = vec![0; input.len()];
        let channels = 3;

        interleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 5, 10, 1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14];

        assert_eq!(actual, expected);
    }

    #[test]
    fn deinterleaved_3_channel() {
        let input: Vec<_> = vec![0, 5, 10, 1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14];
        let mut output = vec![0; input.len()];
        let channels = 3;

        deinterleaved(&input[..], &mut output[..], channels);

        let actual = output;
        let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

        assert_eq!(actual, expected);
    }
    /// Checks both layout functions against [`reference`] for every channel count in
    /// [`reference::CHANNELS`] and each of `frame_counts`, on samples made by `make`.
    ///
    /// Each sample is mapped to `Some(key)`, so a slot the fast path fails to write stays `None`,
    /// and floats are compared by their bits; the identity copy the buffer conversions use is
    /// checked too.
    fn check_against_reference<T, K>(
        frame_counts: impl Iterator<Item = usize> + Clone,
        make: impl Fn(usize) -> T,
        key: impl Fn(&T) -> K,
    ) where
        T: Copy,
        K: Clone + PartialEq + std::fmt::Debug,
    {
        for channels in reference::CHANNELS {
            for frames in frame_counts.clone() {
                let input: Vec<T> = (0..channels * frames).map(&make).collect();
                let keys = |samples: &[T]| samples.iter().map(&key).collect::<Vec<_>>();

                let mut expected = vec![None; input.len()];
                let mut actual = vec![None; input.len()];
                reference::deinterleaved_by(&input, &mut expected, channels, |s| Some(key(s)));
                deinterleaved_by(&input, &mut actual, channels, |s| Some(key(s)));
                assert_eq!(
                    actual, expected,
                    "de-interleave {channels} ch, {frames} frames"
                );

                let mut copied = input.clone();
                deinterleaved(&input, &mut copied, channels);
                let expected: Vec<K> = expected.into_iter().map(Option::unwrap).collect();
                assert_eq!(keys(&copied), expected, "de-interleave copy {channels} ch");

                let mut expected = vec![None; input.len()];
                let mut actual = vec![None; input.len()];
                reference::interleaved_by(&input, &mut expected, channels, |s| Some(key(s)));
                interleaved_by(&input, &mut actual, channels, |s| Some(key(s)));
                assert_eq!(
                    actual, expected,
                    "interleave {channels} ch, {frames} frames"
                );

                let mut copied = input.clone();
                interleaved(&input, &mut copied, channels);
                let expected: Vec<K> = expected.into_iter().map(Option::unwrap).collect();
                assert_eq!(keys(&copied), expected, "interleave copy {channels} ch");
            }
        }
    }

    fn check_sample_types(frame_counts: impl Iterator<Item = usize> + Clone) {
        check_against_reference(frame_counts.clone(), reference::make_i16, |s| *s);
        check_against_reference(frame_counts.clone(), reference::make_i32, |s| *s);
        check_against_reference(frame_counts, reference::make_f32, |s| s.to_bits());
    }

    #[test]
    fn fast_paths_match_reference() {
        check_sample_types(reference::sampled_frame_counts());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow unoptimized; run with --release")]
    fn fast_paths_match_reference_for_every_frame_count() {
        check_sample_types(reference::all_frame_counts());
    }

    #[test]
    #[should_panic(expected = "divisor of zero")]
    fn deinterleave_zero_channels_panics() {
        deinterleaved(&[0i16; 0], &mut [], 0);
    }

    #[test]
    #[should_panic(expected = "divisor of zero")]
    fn interleave_zero_channels_panics() {
        interleaved(&[0i16; 0], &mut [], 0);
    }

    #[test]
    fn mismatched_lengths_panic() {
        for channels in reference::CHANNELS {
            for (input, output) in [(2, 4), (4, 2), (channels, 0), (0, channels)] {
                let input = vec![0i16; input * channels];
                let mut output = vec![0i16; output * channels];
                let de = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    deinterleaved(&input, &mut output, channels)
                }));
                let int = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    interleaved(&input, &mut output, channels)
                }));
                assert!(de.is_err() && int.is_err(), "{channels} ch");
            }
        }
    }

    #[test]
    fn partial_frames_panic() {
        for channels in 2..=8 {
            let input = vec![0i16; 3 * channels + 1];
            let mut output = vec![0i16; input.len()];
            let de = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                deinterleaved(&input, &mut output, channels)
            }));
            let int = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                interleaved(&input, &mut output, channels)
            }));
            assert!(de.is_err() && int.is_err(), "{channels} ch");
        }
    }
}
