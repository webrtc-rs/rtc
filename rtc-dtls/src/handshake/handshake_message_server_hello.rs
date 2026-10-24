#[cfg(test)]
mod handshake_message_server_hello_test;

use super::handshake_random::*;
use super::*;
use crate::cipher_suite::*;
use crate::compression_methods::*;
use crate::extension::*;
use crate::record_layer::record_layer_header::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::BufWriter;

/*
The server will send this message in response to a ClientHello
message when it was able to find an acceptable set of algorithms.
If it cannot find such a match, it will respond with a handshake
failure alert.
https://tools.ietf.org/html/rfc5246#section-7.4.1.3
*/
#[derive(Clone)]
/// The server's reply: its random, and the cipher suite and extensions it selected.
pub struct HandshakeMessageServerHello {
    pub(crate) version: ProtocolVersion,
    pub(crate) random: HandshakeRandom,
    /// The session ID the client offered, echoed back; carried but not used.
    pub(crate) session_id: Vec<u8>,

    pub(crate) cipher_suite: CipherSuiteId,
    pub(crate) compression_method: CompressionMethodId,
    pub(crate) extensions: Vec<Extension>,
}

impl PartialEq for HandshakeMessageServerHello {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.random == other.random
            && self.session_id == other.session_id
            && self.compression_method == other.compression_method
            && self.extensions == other.extensions
            && self.cipher_suite == other.cipher_suite
    }
}

impl fmt::Debug for HandshakeMessageServerHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = [
            format!("version: {:?} random: {:?}", self.version, self.random),
            format!("session_id: {:?}", self.session_id),
            format!("cipher_suites: {:?}", self.cipher_suite),
            format!("compression_method: {:?}", self.compression_method),
            format!("extensions: {:?}", self.extensions),
        ];
        write!(f, "{}", s.join(" "))
    }
}

impl HandshakeMessageServerHello {
    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::ServerHello
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        let mut len = 2 + self.random.size();

        // SessionID
        len += 1 + self.session_id.len();

        len += 2;

        len += 1;

        len += 2;
        for extension in &self.extensions {
            len += extension.size();
        }

        len
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.session_id.len() > 255 {
            return Err(Error::ErrSessionIdTooLong);
        }

        writer.write_u8(self.version.major)?;
        writer.write_u8(self.version.minor)?;
        self.random.marshal(writer)?;

        // SessionID
        writer.write_u8(self.session_id.len() as u8)?;
        writer.write_all(&self.session_id)?;

        writer.write_u16::<BigEndian>(self.cipher_suite as u16)?;

        writer.write_u8(self.compression_method as u8)?;

        let mut extension_buffer = vec![];
        {
            let mut extension_writer = BufWriter::<&mut Vec<u8>>::new(extension_buffer.as_mut());
            for extension in &self.extensions {
                extension.marshal(&mut extension_writer)?;
            }
        }

        writer.write_u16::<BigEndian>(extension_buffer.len() as u16)?;
        writer.write_all(&extension_buffer)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let random = HandshakeRandom::unmarshal(reader)?;

        // Session ID
        let session_id_len = reader.read_u8()? as usize;
        let mut session_id = vec![0u8; session_id_len];
        reader.read_exact(&mut session_id)?;

        let cipher_suite: CipherSuiteId = reader.read_u16::<BigEndian>()?.into();

        let compression_method = reader.read_u8()?.into();
        // The extension block is optional (RFC 5246 §7.4.1.2): a hello that ends here has none.
        let extension_buffer_len = read_optional_u16(reader)?.unwrap_or(0) as usize;
        let mut extension_buffer = vec![0u8; extension_buffer_len];
        reader.read_exact(&mut extension_buffer)?;

        let extensions = unmarshal_extensions(&extension_buffer)?;

        // Nothing may follow the extension block (pion: `errLengthMismatch`).
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(Error::ErrLengthMismatch);
        }

        Ok(HandshakeMessageServerHello {
            version: ProtocolVersion { major, minor },
            random,
            session_id,

            cipher_suite,
            compression_method,
            extensions,
        })
    }
}
