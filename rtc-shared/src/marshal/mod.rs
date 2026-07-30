use bytes::{Buf, BytesMut};

use crate::error::{Error, Result};

/// The encoded size of a value, in bytes.
///
/// Implemented alongside [`Marshal`]/[`Unmarshal`] so a caller can size a buffer before
/// encoding, and so nested codecs can compute offsets without encoding twice.
pub trait MarshalSize: Send + Sync {
    /// The number of bytes [`Marshal::marshal_to`] will write for this value.
    fn marshal_size(&self) -> usize;
}

/// Encodes a value into its wire format.
///
/// Every protocol codec in the stack — STUN, RTP, RTCP, SDP, DTLS, SCTP — implements this
/// so that higher layers can serialize uniformly.
pub trait Marshal: MarshalSize {
    /// Encodes into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Fails if `buf` is shorter than [`MarshalSize::marshal_size`], or if the value itself is
    /// not encodable (an out-of-range field, for instance).
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize>;

    /// Encodes into a freshly allocated buffer sized by [`MarshalSize::marshal_size`].
    ///
    /// # Errors
    ///
    /// Propagates any failure from [`Self::marshal_to`].
    fn marshal(&self) -> Result<BytesMut> {
        let l = self.marshal_size();
        let mut buf = BytesMut::with_capacity(l);
        buf.resize(l, 0);
        let n = self.marshal_to(&mut buf)?;
        if n != l {
            Err(Error::Other(format!(
                "marshal_to output size {n}, but expect {l}"
            )))
        } else {
            Ok(buf)
        }
    }
}

/// Decodes a value from its wire format.
pub trait Unmarshal: MarshalSize {
    /// Decodes one value from `buf`, advancing it past the bytes consumed.
    ///
    /// # Errors
    ///
    /// Fails if `buf` is truncated, or if its contents are not a valid encoding of `Self`.
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf;
}
