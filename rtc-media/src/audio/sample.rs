use std::io::{Cursor, Read};

use byteorder::{ByteOrder, ReadBytesExt};
#[cfg(test)]
use nearly_eq::NearlyEq;
use wide::{f32x8, i16x8, i32x8};

#[derive(Eq, PartialEq, Copy, Clone, Default, Debug)]
#[repr(transparent)]
/// One audio sample of raw type `Raw` (`i16`, `f32`, …).
///
/// A transparent newtype, so a `[Sample<T>]` can be reinterpreted as `[T]` without copying.
///
/// `Sample<i16>` and `Sample<f32>` convert into each other with [`From`], one sample at a time,
/// or a slice at a time with [`Sample::<f32>::convert_from_i16_slice`] and
/// [`Sample::<i16>::convert_from_f32_slice`], which give the same results.
pub struct Sample<Raw>(Raw);

impl From<i16> for Sample<i16> {
    #[inline]
    fn from(raw: i16) -> Self {
        Self(raw)
    }
}

impl From<f32> for Sample<f32> {
    #[inline]
    fn from(raw: f32) -> Self {
        Self(raw.clamp(-1.0, 1.0))
    }
}

macro_rules! impl_from_sample_for_raw {
    ($raw:ty) => {
        impl From<Sample<$raw>> for $raw {
            #[inline]
            fn from(sample: Sample<$raw>) -> $raw {
                sample.0
            }
        }
    };
}

impl_from_sample_for_raw!(i16);
impl_from_sample_for_raw!(f32);

// impl From<Sample<i16>> for Sample<i64> {
//     #[inline]
//     fn from(sample: Sample<i16>) -> Self {
//         // Fast but imprecise approach:
//         // Perform crude but fast upsample by bit-shifting the raw value:
//         Self::from((sample.0 as i64) << 16)

//         // Slow but precise approach:
//         // Perform a proper but expensive lerp from
//         // i16::MIN..i16::MAX to i32::MIN..i32::MAX:

//         // let value = sample.0 as i64;

//         // let from = if value <= 0 { i16::MIN } else { i16::MAX } as i64;
//         // let to = if value <= 0 { i32::MIN } else { i32::MAX } as i64;

//         // Self::from((value * to + from / 2) / from)
//     }
// }

impl From<Sample<i16>> for Sample<f32> {
    #[inline]
    fn from(sample: Sample<i16>) -> Self {
        let divisor = if sample.0 < 0 {
            i16::MIN as f32
        } else {
            i16::MAX as f32
        }
        .abs();
        Self::from((sample.0 as f32) / divisor)
    }
}

impl From<Sample<f32>> for Sample<i16> {
    #[inline]
    fn from(sample: Sample<f32>) -> Self {
        let multiplier = if sample.0 < 0.0 {
            i16::MIN as f32
        } else {
            i16::MAX as f32
        }
        .abs();
        Self::from((sample.0 * multiplier) as i16)
    }
}

/// Samples per vector in the slice conversions.
const LANES: usize = 8;

/// Vectors converted per iteration of the slice conversions' main loop. Four independent vectors
/// in flight, as the compiler unrolls the scalar loop, keep the conversion from waiting on the
/// latency of each step.
const VECTORS_PER_BLOCK: usize = 4;

/// The magnitude negative `i16` samples are scaled by: `-(i16::MIN as f32)`, so that `i16::MIN`
/// maps to exactly `-1.0`.
const NEGATIVE_SCALE: f32x8 = f32x8::splat(32_768.0);

/// The magnitude non-negative `i16` samples are scaled by: `i16::MAX as f32`, so that
/// `i16::MAX` maps to exactly `1.0`.
const POSITIVE_SCALE: f32x8 = f32x8::splat(32_767.0);

/// Converts `src` into `dst` a vector of [`LANES`] samples at a time with `vector`, and the few
/// samples left over with `scalar`.
///
/// # Panics
///
/// If `src` and `dst` differ in length.
#[inline(always)]
fn convert_slice<S: Copy, D>(
    src: &[S],
    dst: &mut [D],
    vector: impl Fn(&[S; LANES]) -> [D; LANES],
    scalar: impl Fn(S) -> D,
) {
    assert_eq!(src.len(), dst.len(), "slice lengths differ");

    let (src_vectors, src_tail) = src.as_chunks::<LANES>();
    let (dst_vectors, dst_tail) = dst.as_chunks_mut::<LANES>();
    let (src_blocks, src_vectors) = src_vectors.as_chunks::<VECTORS_PER_BLOCK>();
    let (dst_blocks, dst_vectors) = dst_vectors.as_chunks_mut::<VECTORS_PER_BLOCK>();
    for (src, dst) in src_blocks.iter().zip(dst_blocks) {
        for (src, dst) in src.iter().zip(dst) {
            *dst = vector(src);
        }
    }
    for (src, dst) in src_vectors.iter().zip(dst_vectors) {
        *dst = vector(src);
    }
    for (src, dst) in src_tail.iter().zip(dst_tail) {
        *dst = scalar(*src);
    }
}

impl Sample<f32> {
    /// Converts each `i16` sample in `src` to `f32`, writing the results to `dst`.
    ///
    /// Every result is bit-for-bit what [`From`] gives for that sample: negative samples are
    /// divided by 32,768 and the rest by 32,767, so the full `i16` range maps onto `-1.0..=1.0`.
    /// The division is IEEE division, not multiplication by a reciprocal, which would round
    /// differently for some inputs.
    ///
    /// Eight samples are converted at a time with the [`wide`] crate's portable vectors, which
    /// compile to SSE2 or AVX on x86, NEON on ARM64 and `simd128` on WebAssembly, as the target
    /// features enabled at build time allow, and to scalar code elsewhere.
    ///
    /// # Panics
    ///
    /// If `src` and `dst` differ in length.
    pub fn convert_from_i16_slice(src: &[Sample<i16>], dst: &mut [Sample<f32>]) {
        convert_slice(
            src,
            dst,
            |src| {
                let value = i32x8::from_i16x8(i16x8::new(src.map(|sample| sample.0)));
                let divisor = value
                    .simd_lt(i32x8::ZERO)
                    .select(NEGATIVE_SCALE, POSITIVE_SCALE);
                // The quotient is always within -1.0..=1.0, so the clamp `From` applies would
                // never change it and is left out.
                (f32x8::from_i32x8(value) / divisor).to_array().map(Sample)
            },
            Self::from,
        );
    }
}

impl Sample<i16> {
    /// Converts each `f32` sample in `src` to `i16`, writing the results to `dst`.
    ///
    /// Every result is what [`From`] gives for that sample: negative samples are multiplied by
    /// 32,768 and the rest by 32,767, then truncated toward zero with the saturation of an `as`
    /// cast. A NaN sample, which clamping lets through, becomes 0.
    ///
    /// Eight samples are converted at a time with the [`wide`] crate's portable vectors, which
    /// compile to SSE2 or AVX on x86, NEON on ARM64 and `simd128` on WebAssembly, as the target
    /// features enabled at build time allow, and to scalar code elsewhere.
    ///
    /// # Panics
    ///
    /// If `src` and `dst` differ in length.
    pub fn convert_from_f32_slice(src: &[Sample<f32>], dst: &mut [Sample<i16>]) {
        convert_slice(
            src,
            dst,
            |src| {
                let value = f32x8::new(src.map(|sample| sample.0));
                let multiplier = value
                    .simd_lt(f32x8::ZERO)
                    .select(NEGATIVE_SCALE, POSITIVE_SCALE);
                // `trunc_int` truncates toward zero, saturating at the `i32` bounds and sending
                // NaN to 0, as `as i32` does; narrowing that with saturation is then exactly
                // `as i16`.
                let product = (value * multiplier).trunc_int();
                i16x8::from_i32x8_saturate(product).to_array().map(Sample)
            },
            Self::from,
        );
    }
}

trait FromBytes: Sized {
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self, std::io::Error>;

    fn from_bytes<B: ByteOrder>(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let mut cursor = Cursor::new(bytes);
        Self::from_reader::<B, _>(&mut cursor)
    }
}

impl FromBytes for Sample<i16> {
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        reader.read_i16::<B>().map(Self::from)
    }
}

impl FromBytes for Sample<f32> {
    fn from_reader<B: ByteOrder, R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        reader.read_f32::<B>().map(Self::from)
    }
}

#[cfg(test)]
impl<Raw> NearlyEq<Self, Raw> for Sample<Raw>
where
    Raw: NearlyEq<Raw, Raw>,
{
    fn eps() -> Raw {
        Raw::eps()
    }

    fn eq(&self, other: &Self, eps: &Raw) -> bool {
        NearlyEq::eq(&self.0, &other.0, eps)
    }
}

#[cfg(test)]
mod tests {
    use nearly_eq::assert_nearly_eq;

    use super::*;

    #[test]
    fn sample_i16_from_i16() {
        // i16:
        assert_eq!(Sample::<i16>::from(i16::MIN).0, i16::MIN);
        assert_eq!(Sample::<i16>::from(i16::MIN / 2).0, i16::MIN / 2);
        assert_eq!(Sample::<i16>::from(0).0, 0);
        assert_eq!(Sample::<i16>::from(i16::MAX / 2).0, i16::MAX / 2);
        assert_eq!(Sample::<i16>::from(i16::MAX).0, i16::MAX);
    }

    #[test]
    fn sample_f32_from_f32() {
        assert_eq!(Sample::<f32>::from(-1.0).0, -1.0);
        assert_eq!(Sample::<f32>::from(-0.5).0, -0.5);
        assert_eq!(Sample::<f32>::from(0.0).0, 0.0);
        assert_eq!(Sample::<f32>::from(0.5).0, 0.5);
        assert_eq!(Sample::<f32>::from(1.0).0, 1.0);

        // For any values outside of -1.0..=1.0 we expect clamping:
        assert_eq!(Sample::<f32>::from(f32::MIN).0, -1.0);
        assert_eq!(Sample::<f32>::from(f32::MAX).0, 1.0);
    }

    #[test]
    fn sample_i16_from_sample_f32() {
        assert_nearly_eq!(
            Sample::<i16>::from(Sample::<f32>::from(-1.0)),
            Sample::from(i16::MIN)
        );
        assert_nearly_eq!(
            Sample::<i16>::from(Sample::<f32>::from(-0.5)),
            Sample::from(i16::MIN / 2)
        );
        assert_nearly_eq!(
            Sample::<i16>::from(Sample::<f32>::from(0.0)),
            Sample::from(0)
        );
        assert_nearly_eq!(
            Sample::<i16>::from(Sample::<f32>::from(0.5)),
            Sample::from(i16::MAX / 2)
        );
        assert_nearly_eq!(
            Sample::<i16>::from(Sample::<f32>::from(1.0)),
            Sample::from(i16::MAX)
        );
    }

    #[test]
    fn sample_f32_from_sample_i16() {
        assert_nearly_eq!(
            Sample::<f32>::from(Sample::<i16>::from(i16::MIN)),
            Sample::from(-1.0)
        );
        assert_nearly_eq!(
            Sample::<f32>::from(Sample::<i16>::from(i16::MIN / 2)),
            Sample::from(-0.5)
        );
        assert_nearly_eq!(
            Sample::<f32>::from(Sample::<i16>::from(0)),
            Sample::from(0.0)
        );
        assert_nearly_eq!(
            Sample::<f32>::from(Sample::<i16>::from(i16::MAX / 2)),
            Sample::from(0.5),
            0.0001 // rounding error due to i16::MAX being odd
        );
        assert_nearly_eq!(
            Sample::<f32>::from(Sample::<i16>::from(i16::MAX)),
            Sample::from(1.0)
        );
    }

    /// Converts `src` a slice at a time and checks every result against [`From`], bit for bit.
    ///
    /// `dst` is filled first with each of two sentinels, so a slot the slice conversion skips
    /// cannot pass by already holding the expected value.
    fn check_i16_to_f32(src: &[Sample<i16>]) {
        for sentinel in [0.25, -0.75] {
            let mut dst = vec![Sample(sentinel); src.len()];
            Sample::<f32>::convert_from_i16_slice(src, &mut dst);
            for (src, dst) in src.iter().zip(&dst) {
                let expected = Sample::<f32>::from(*src);
                assert_eq!(dst.0.to_bits(), expected.0.to_bits(), "input {}", src.0);
            }
        }
    }

    /// As [`check_i16_to_f32`], the other way.
    fn check_f32_to_i16(src: &[Sample<f32>]) {
        for sentinel in [12_345, -12_345] {
            let mut dst = vec![Sample(sentinel); src.len()];
            Sample::<i16>::convert_from_f32_slice(src, &mut dst);
            for (src, dst) in src.iter().zip(&dst) {
                let expected = Sample::<i16>::from(*src);
                assert_eq!(*dst, expected, "input {:#010x}", src.0.to_bits());
            }
        }
    }

    #[test]
    fn i16_slice_matches_per_sample_for_every_input() {
        let src: Vec<Sample<i16>> = (i16::MIN..=i16::MAX).map(Sample::from).collect();
        check_i16_to_f32(&src);
    }

    /// Every length through a few blocks, at every alignment within a vector, so the block loop,
    /// the single-vector loop and the scalar tail each write exactly the right slots.
    #[test]
    fn slice_conversions_handle_every_remainder() {
        let len = 3 * VECTORS_PER_BLOCK * LANES + LANES;
        let ints: Vec<Sample<i16>> = (0..len as i32)
            .map(|i| Sample((i * 2_731 - 40_000) as i16))
            .collect();
        let floats: Vec<Sample<f32>> = ints.iter().map(|&s| Sample::<f32>::from(s)).collect();
        for start in 0..LANES {
            for end in start..=ints.len() {
                check_i16_to_f32(&ints[start..end]);
                check_f32_to_i16(&floats[start..end]);
            }
        }
    }

    /// Values a `Sample<f32>` can hold whose conversion is easiest to get wrong: signed zeros,
    /// the endpoints, subnormals, NaNs (which clamping lets through), and every point where the
    /// scaled value crosses an integer or a half-integer, with both of its float neighbours.
    /// Infinities and out-of-range values, which the constructors clamp away, are included too.
    fn f32_edge_cases() -> Vec<Sample<f32>> {
        let mut values = vec![
            0.0,
            1.0,
            0.5,
            f32::MIN_POSITIVE,
            f32::from_bits(1),
            f32::from_bits(0x007F_FFFF),
            f32::EPSILON,
            f32::NAN,
            f32::from_bits(0x7F80_0001),
            f32::from_bits(0x7FFF_FFFF),
            f32::INFINITY,
            f32::MAX,
            2.0,
            1.0e10,
        ];
        for k in 0..=32_768 {
            let k = k as f32;
            values.extend([
                k / 32_767.0,
                k / 32_768.0,
                (k + 0.5) / 32_767.0,
                (k + 0.5) / 32_768.0,
            ]);
        }
        let neighbours = |value: f32| {
            let bits = value.to_bits();
            [bits.wrapping_sub(1), bits, bits.wrapping_add(1)].map(f32::from_bits)
        };
        values
            .into_iter()
            .flat_map(|value| [value, -value])
            .flat_map(neighbours)
            .map(Sample)
            .collect()
    }

    #[test]
    fn f32_slice_matches_per_sample_on_edge_cases() {
        check_f32_to_i16(&f32_edge_cases());

        let nan = Sample::<f32>::from(f32::NAN);
        assert!(nan.0.is_nan(), "clamp passes NaN through");
        let mut dst = [Sample(1)];
        Sample::<i16>::convert_from_f32_slice(&[nan], &mut dst);
        assert_eq!(dst, [Sample(0)]);
    }

    /// Every 4,099th `f32` bit pattern: a cheap spread over all of them.
    #[test]
    fn f32_slice_matches_per_sample_on_spread_of_bit_patterns() {
        let src: Vec<Sample<f32>> = (0..=u32::MAX)
            .step_by(4_099)
            .map(|bits| Sample(f32::from_bits(bits)))
            .collect();
        check_f32_to_i16(&src);
    }

    /// Every `f32` bit pattern: all the values a `Sample<f32>` can hold, and those its
    /// constructors clamp away. Split across threads, this takes a few seconds optimized.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "all 2^32 bit patterns; run with --release")]
    fn f32_slice_matches_per_sample_for_every_bit_pattern() {
        use std::sync::atomic::{AtomicU32, Ordering};

        const BLOCK: u32 = 1 << 16;
        let next_block = AtomicU32::new(0);
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let mut src = vec![Sample(0.0); BLOCK as usize];
                    let mut dst = vec![Sample(0); BLOCK as usize];
                    loop {
                        let block = next_block.fetch_add(1, Ordering::Relaxed);
                        if block >= BLOCK {
                            break;
                        }
                        for (low, src) in (0..BLOCK).zip(&mut src) {
                            *src = Sample(f32::from_bits(block * BLOCK + low));
                        }
                        Sample::<i16>::convert_from_f32_slice(&src, &mut dst);
                        for (src, dst) in src.iter().zip(&dst) {
                            let expected = Sample::<i16>::from(*src);
                            assert_eq!(*dst, expected, "input {:#010x}", src.0.to_bits());
                        }
                    }
                });
            }
        });
    }

    #[test]
    #[should_panic(expected = "lengths differ")]
    fn i16_slice_length_mismatch_panics() {
        Sample::<f32>::convert_from_i16_slice(&[Sample(0); 3], &mut [Sample(0.0); 4]);
    }

    #[test]
    #[should_panic(expected = "lengths differ")]
    fn f32_slice_length_mismatch_panics() {
        Sample::<i16>::convert_from_f32_slice(&[Sample(0.0); 9], &mut [Sample(0); 8]);
    }
}
