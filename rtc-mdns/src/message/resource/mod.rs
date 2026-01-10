pub(crate) mod a;
pub(crate) mod aaaa;
pub(crate) mod cname;
pub(crate) mod mx;
pub(crate) mod ns;
pub(crate) mod opt;
pub(crate) mod ptr;
pub(crate) mod soa;
pub(crate) mod srv;
pub(crate) mod txt;

use std::any::Any;
use std::collections::HashMap;
use std::fmt;

use a::*;
use aaaa::*;
use cname::*;
use mx::*;
use ns::*;
use opt::*;
use ptr::*;
use soa::*;
use srv::*;
use txt::*;

use super::name::*;
use super::packer::*;
use super::*;
use shared::error::*;

// EDNS(0) wire constants.

const EDNS0_VERSION: u32 = 0;
const EDNS0_DNSSEC_OK: u32 = 0x00008000;
const EDNS_VERSION_MASK: u32 = 0x00ff0000;
const EDNS0_DNSSEC_OK_MASK: u32 = 0x00ff8000;

// A Resource is a DNS resource record.
#[derive(Default, Debug)]
pub(crate) struct Resource {
    pub(crate) header: ResourceHeader,
    pub(crate) body: Option<Box<dyn ResourceBody>>,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dnsmessage.Resource{{Header: {}, Body: {}}}",
            self.header,
            if let Some(body) = &self.body {
                body.to_string()
            } else {
                "None".to_owned()
            }
        )
    }
}

impl Resource {
    // pack appends the wire format of the Resource to msg.
    pub(crate) fn pack(
        &mut self,
        msg: Vec<u8>,
        compression: &mut Option<HashMap<String, usize>>,
        compression_off: usize,
    ) -> Result<Vec<u8>> {
        self.header.typ = self
            .body
            .as_ref()
            .ok_or(Error::ErrNilResourceBody)?
            .real_type();
        let (mut msg, len_off) = self.header.pack(msg, compression, compression_off)?;
        let pre_len = msg.len();
        if let Some(body) = &self.body {
            msg = body.pack(msg, compression, compression_off)?;
            self.header.fix_len(&mut msg, len_off, pre_len)?;
        }
        Ok(msg)
    }

    pub(crate) fn unpack(&mut self, msg: &[u8], mut off: usize) -> Result<usize> {
        off = self.header.unpack(msg, off, 0)?;
        let (rb, off) =
            unpack_resource_body(self.header.typ, msg, off, self.header.length as usize)?;
        self.body = Some(rb);
        Ok(off)
    }

    pub(crate) fn skip(msg: &[u8], off: usize) -> Result<usize> {
        let mut new_off = Name::skip(msg, off)?;
        new_off = DnsType::skip(msg, new_off)?;
        new_off = DnsClass::skip(msg, new_off)?;
        new_off = skip_uint32(msg, new_off)?;
        let (length, mut new_off) = unpack_uint16(msg, new_off)?;
        new_off += length as usize;
        if new_off > msg.len() {
            return Err(Error::ErrResourceLen);
        }
        Ok(new_off)
    }
}

/// Header for a DNS resource record.
///
/// A `ResourceHeader` contains the common fields that appear at the beginning
/// of every DNS resource record (RR). While there are many types of resource
/// records (A, AAAA, CNAME, MX, etc.), they all share this same header format.
///
/// # Wire Format
///
/// The resource record header has the following wire format:
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      NAME                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     RDATA                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(crate) struct ResourceHeader {
    /// The domain name for which this resource record pertains.
    pub(crate) name: Name,

    /// The type of DNS resource record (e.g., A, AAAA, CNAME).
    ///
    /// This field will be set automatically during packing.
    pub(crate) typ: DnsType,

    /// The class of network to which this DNS resource record pertains.
    ///
    /// Almost always [`DNSCLASS_INET`](crate::DNSCLASS_INET) for Internet records.
    pub(crate) class: DnsClass,

    /// Time to live in seconds.
    ///
    /// The length of time this resource record is valid. After this time,
    /// the record should be discarded and re-queried. All resources in a
    /// set should have the same TTL (RFC 2181 Section 5.2).
    pub(crate) ttl: u32,

    /// Length of the resource data (RDATA) following this header.
    ///
    /// This field will be set automatically during packing.
    pub(crate) length: u16,
}

impl fmt::Display for ResourceHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dnsmessage.ResourceHeader{{Name: {}, Type: {}, Class: {}, TTL: {}, Length: {}}}",
            self.name, self.typ, self.class, self.ttl, self.length,
        )
    }
}

impl ResourceHeader {
    // pack appends the wire format of the ResourceHeader to oldMsg.
    //
    // lenOff is the offset in msg where the Length field was packed.
    pub(crate) fn pack(
        &self,
        mut msg: Vec<u8>,
        compression: &mut Option<HashMap<String, usize>>,
        compression_off: usize,
    ) -> Result<(Vec<u8>, usize)> {
        msg = self.name.pack(msg, compression, compression_off)?;
        msg = self.typ.pack(msg);
        msg = self.class.pack(msg);
        msg = pack_uint32(msg, self.ttl);
        let len_off = msg.len();
        msg = pack_uint16(msg, self.length);
        Ok((msg, len_off))
    }

    pub(crate) fn unpack(&mut self, msg: &[u8], off: usize, _length: usize) -> Result<usize> {
        let mut new_off = off;
        new_off = self.name.unpack(msg, new_off)?;
        new_off = self.typ.unpack(msg, new_off)?;
        new_off = self.class.unpack(msg, new_off)?;
        let (ttl, new_off) = unpack_uint32(msg, new_off)?;
        self.ttl = ttl;
        let (l, new_off) = unpack_uint16(msg, new_off)?;
        self.length = l;

        Ok(new_off)
    }

    // fixLen updates a packed ResourceHeader to include the length of the
    // ResourceBody.
    //
    // lenOff is the offset of the ResourceHeader.Length field in msg.
    //
    // preLen is the length that msg was before the ResourceBody was packed.
    pub(crate) fn fix_len(&mut self, msg: &mut [u8], len_off: usize, pre_len: usize) -> Result<()> {
        if msg.len() < pre_len || msg.len() > pre_len + u16::MAX as usize {
            return Err(Error::ErrResTooLong);
        }

        let con_len = msg.len() - pre_len;

        // Fill in the length now that we know how long the content is.
        msg[len_off] = ((con_len >> 8) & 0xFF) as u8;
        msg[len_off + 1] = (con_len & 0xFF) as u8;
        self.length = con_len as u16;

        Ok(())
    }

    // set_edns0 configures h for EDNS(0).
    //
    // The provided ext_rcode must be an extended RCode.
    pub(crate) fn set_edns0(
        &mut self,
        udp_payload_len: u16,
        ext_rcode: u32,
        dnssec_ok: bool,
    ) -> Result<()> {
        self.name = Name {
            data: ".".to_owned(),
        }; // RFC 6891 section 6.1.2
        self.typ = DnsType::Opt;
        self.class = DnsClass(udp_payload_len);
        self.ttl = (ext_rcode >> 4) << 24;
        if dnssec_ok {
            self.ttl |= EDNS0_DNSSEC_OK;
        }
        Ok(())
    }

    // dnssec_allowed reports whether the DNSSEC OK bit is set.
    pub(crate) fn dnssec_allowed(&self) -> bool {
        self.ttl & EDNS0_DNSSEC_OK_MASK == EDNS0_DNSSEC_OK // RFC 6891 section 6.1.3
    }

    // extended_rcode returns an extended RCode.
    //
    // The provided rcode must be the RCode in DNS message header.
    pub(crate) fn extended_rcode(&self, rcode: RCode) -> RCode {
        if self.ttl & EDNS_VERSION_MASK == EDNS0_VERSION {
            // RFC 6891 section 6.1.3
            let ttl = ((self.ttl >> 24) << 4) as u8 | rcode as u8;
            return RCode::from(ttl);
        }
        rcode
    }
}

// A ResourceBody is a DNS resource record minus the header.
pub(crate) trait ResourceBody: fmt::Display + fmt::Debug {
    // real_type returns the actual type of the Resource. This is used to
    // fill in the header Type field.
    fn real_type(&self) -> DnsType;

    // pack packs a Resource except for its header.
    fn pack(
        &self,
        msg: Vec<u8>,
        compression: &mut Option<HashMap<String, usize>>,
        compression_off: usize,
    ) -> Result<Vec<u8>>;

    fn unpack(&mut self, msg: &[u8], off: usize, length: usize) -> Result<usize>;

    fn as_any(&self) -> &dyn Any;
}

pub(crate) fn unpack_resource_body(
    typ: DnsType,
    msg: &[u8],
    mut off: usize,
    length: usize,
) -> Result<(Box<dyn ResourceBody>, usize)> {
    let mut rb: Box<dyn ResourceBody> = match typ {
        DnsType::A => Box::<AResource>::default(),
        DnsType::Ns => Box::<NsResource>::default(),
        DnsType::Cname => Box::<CnameResource>::default(),
        DnsType::Soa => Box::<SoaResource>::default(),
        DnsType::Ptr => Box::<PtrResource>::default(),
        DnsType::Mx => Box::<MxResource>::default(),
        DnsType::Txt => Box::<TxtResource>::default(),
        DnsType::Aaaa => Box::<AaaaResource>::default(),
        DnsType::Srv => Box::<SrvResource>::default(),
        DnsType::Opt => Box::<OptResource>::default(),
        _ => return Err(Error::ErrNilResourceBody),
    };

    off = rb.unpack(msg, off, length)?;

    Ok((rb, off))
}
