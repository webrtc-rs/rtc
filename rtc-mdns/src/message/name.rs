use std::fmt;

use shared::error::*;

pub(crate) const NAME_LEN: usize = 255;

/// A DNS domain name.
///
/// `Name` represents a domain name in DNS format. Domain names are used throughout
/// DNS messages to identify resources (e.g., `example.com.`, `_services._dns-sd._udp.local.`).
///
/// # Format
///
/// Domain names in DNS are:
/// - A sequence of labels separated by dots
/// - Must end with a trailing dot (e.g., `example.com.` not `example.com`)
/// - Maximum total length of 255 bytes
/// - Each label has a maximum length of 63 bytes
///
/// # Wire Format
///
/// On the wire, domain names are encoded as a sequence of length-prefixed labels,
/// terminated by a zero-length label. DNS supports name compression where repeated
/// suffixes can be replaced with pointers to earlier occurrences.
#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub(crate) struct Name {
    /// The domain name string, including the trailing dot.
    pub(crate) data: String,
}

// String implements fmt.Stringer.String.
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl Name {
    pub(crate) fn new(data: &str) -> Result<Self> {
        if data.len() > NAME_LEN {
            Err(Error::ErrCalcLen)
        } else {
            Ok(Name {
                data: data.to_owned(),
            })
        }
    }

    // pack appends the wire format of the Name to msg.
    //
    // Domain names are a sequence of counted strings split at the dots. They end
    // with a zero-length string. Compression can be used to reuse domain suffixes.
    //
    // The compression map will be updated with new domain suffixes. If compression
    // is nil, compression will not be used.
    pub(crate) fn pack(
        &self,
        msg: Vec<u8>,
        compression: &mut Option<NameTable>,
        compression_off: usize,
    ) -> Result<Vec<u8>> {
        pack_name(&self.data, msg, compression, compression_off)
    }

    // unpack unpacks a domain name.
    pub(crate) fn unpack(&mut self, msg: &[u8], off: usize) -> Result<usize> {
        self.unpack_compressed(msg, off, true /* allowCompression */)
    }

    pub(crate) fn unpack_compressed(
        &mut self,
        msg: &[u8],
        off: usize,
        allow_compression: bool,
    ) -> Result<usize> {
        // curr_off is the current working offset.
        let mut curr_off = off;

        // new_off is the offset where the next record will start. Pointers lead
        // to data that belongs to other names and thus doesn't count towards to
        // the usage of this name.
        let mut new_off = off;

        // ptr is the number of pointers followed.
        let mut ptr = 0;

        // Name is a slice representation of the name data.
        let mut name = String::with_capacity(NAME_LEN.min(msg.len() - off.min(msg.len())).min(64));

        loop {
            if curr_off >= msg.len() {
                return Err(Error::ErrBaseLen);
            }
            let c = msg[curr_off];
            curr_off += 1;
            match c & 0xC0 {
                0x00 => {
                    // String segment
                    if c == 0x00 {
                        // A zero length signals the end of the name.
                        break;
                    }
                    let end_off = curr_off + c as usize;
                    if end_off > msg.len() {
                        return Err(Error::ErrCalcLen);
                    }
                    let segment = &msg[curr_off..end_off];
                    match std::str::from_utf8(segment) {
                        Ok(s) => name.push_str(s),
                        // The error type carries the offending bytes, so rebuild it from a copy;
                        // this is the failure path only.
                        Err(_) => {
                            return Err(String::from_utf8(segment.to_vec()).unwrap_err().into());
                        }
                    }
                    name.push('.');
                    curr_off = end_off;
                }
                0xC0 => {
                    // Pointer
                    if !allow_compression {
                        return Err(Error::ErrCompressedSrv);
                    }
                    if curr_off >= msg.len() {
                        return Err(Error::ErrInvalidPtr);
                    }
                    let c1 = msg[curr_off];
                    curr_off += 1;
                    if ptr == 0 {
                        new_off = curr_off;
                    }
                    // Don't follow too many pointers, maybe there's a loop.
                    ptr += 1;
                    if ptr > 10 {
                        return Err(Error::ErrTooManyPtr);
                    }
                    curr_off = ((c ^ 0xC0) as usize) << 8 | (c1 as usize);
                }
                _ => {
                    // Prefixes 0x80 and 0x40 are reserved.
                    return Err(Error::ErrReserved);
                }
            }
        }
        if name.is_empty() {
            name.push('.');
        }
        if name.len() > NAME_LEN {
            return Err(Error::ErrCalcLen);
        }
        self.data = name;
        if ptr == 0 {
            new_off = curr_off;
        }
        Ok(new_off)
    }

    pub(crate) fn skip(msg: &[u8], off: usize) -> Result<usize> {
        // new_off is the offset where the next record will start. Pointers lead
        // to data that belongs to other names and thus doesn't count towards to
        // the usage of this name.
        let mut new_off = off;

        loop {
            if new_off >= msg.len() {
                return Err(Error::ErrBaseLen);
            }
            let c = msg[new_off];
            new_off += 1;
            match c & 0xC0 {
                0x00 => {
                    if c == 0x00 {
                        // A zero length signals the end of the name.
                        break;
                    }
                    // literal string
                    new_off += c as usize;
                    if new_off > msg.len() {
                        return Err(Error::ErrCalcLen);
                    }
                }
                0xC0 => {
                    // Pointer to somewhere else in msg.

                    // Pointers are two bytes.
                    new_off += 1;

                    // Don't follow the pointer as the data here has ended.
                    break;
                }
                _ => {
                    // Prefixes 0x80 and 0x40 are reserved.
                    return Err(Error::ErrReserved);
                }
            }
        }

        Ok(new_off)
    }
}

/// The suffixes of the names packed so far, for compression (RFC 1035 §4.1.4): where in the message
/// each one starts. A suffix is looked up by comparing it with the bytes already written at that
/// offset, so building the table copies no name text.
#[derive(Default)]
pub(crate) struct NameTable {
    /// (hash of the suffix, its offset from the start of the message): the first few live inline,
    /// so packing an ordinary message allocates nothing for compression.
    inline: [(u64, usize); NAME_TABLE_INLINE],
    used: usize,
    spill: Vec<(u64, usize)>,
}

const NAME_TABLE_INLINE: usize = 12;

impl NameTable {
    fn hash(suffix: &str) -> u64 {
        // FNV-1a: cheap, and only a filter; a hit is confirmed against the message bytes.
        suffix
            .as_bytes()
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
            })
    }

    /// The offset at which `suffix` was packed earlier into `msg`, whose message starts at `base`.
    pub(crate) fn find(&self, msg: &[u8], base: usize, suffix: &str) -> Option<usize> {
        let hash = Self::hash(suffix);
        self.inline[..self.used]
            .iter()
            .chain(&self.spill)
            .find(|(h, off)| *h == hash && wire_name_equals(msg, base, base + off, suffix))
            .map(|(_, off)| *off)
    }

    /// Records that `suffix` starts at `offset` (from the start of the message).
    pub(crate) fn insert(&mut self, suffix: &str, offset: usize) {
        let entry = (Self::hash(suffix), offset);
        if self.used < NAME_TABLE_INLINE {
            self.inline[self.used] = entry;
            self.used += 1;
        } else {
            self.spill.push(entry);
        }
    }
}

/// Whether the name encoded in `msg` at `pos` (following compression pointers, which count from
/// `base`) is exactly `suffix`, written with a trailing dot. False if the name is not fully
/// written yet.
fn wire_name_equals(msg: &[u8], base: usize, mut pos: usize, suffix: &str) -> bool {
    let mut rest = suffix.as_bytes();
    let mut pointers = 0;
    loop {
        let Some(&c) = msg.get(pos) else {
            return false;
        };
        match c & 0xC0 {
            0x00 => {
                if c == 0 {
                    return rest.is_empty();
                }
                let len = c as usize;
                let Some(label) = msg.get(pos + 1..pos + 1 + len) else {
                    return false;
                };
                if rest.len() <= len || &rest[..len] != label || rest[len] != b'.' {
                    return false;
                }
                rest = &rest[len + 1..];
                pos += 1 + len;
            }
            0xC0 => {
                let Some(&c1) = msg.get(pos + 1) else {
                    return false;
                };
                pointers += 1;
                if pointers > 10 {
                    return false;
                }
                pos = base + ((usize::from(c ^ 0xC0) << 8) | usize::from(c1));
            }
            _ => return false,
        }
    }
}

/// Appends the wire format of the domain name `name` (with its trailing dot) to `msg`; see
/// [`Name::pack`].
pub(crate) fn pack_name(
    name: &str,
    mut msg: Vec<u8>,
    compression: &mut Option<NameTable>,
    compression_off: usize,
) -> Result<Vec<u8>> {
    let data = name.as_bytes();

    // Add a trailing dot to canonicalize name.
    if data.is_empty() || data[data.len() - 1] != b'.' {
        return Err(Error::ErrNonCanonicalName);
    }

    // Allow root domain.
    if data.len() == 1 && data[0] == b'.' {
        msg.push(0);
        return Ok(msg);
    }

    // Emit sequence of counted strings, chopping at dots.
    let mut begin = 0;
    for i in 0..data.len() {
        // Check for the end of the segment.
        if data[i] == b'.' {
            // The two most significant bits have special meaning.
            // It isn't allowed for segments to be long enough to
            // need them.
            if i - begin >= (1 << 6) {
                return Err(Error::ErrSegTooLong);
            }

            // Segments must have a non-zero length.
            if i - begin == 0 {
                return Err(Error::ErrZeroSegLen);
            }

            msg.push((i - begin) as u8);
            msg.extend_from_slice(&data[begin..i]);

            begin = i + 1;
            continue;
        }

        // We can only compress domain suffixes starting with a new
        // segment. A pointer is two bytes with the two most significant
        // bits set to 1 to indicate that it is a pointer.
        if (i == 0 || data[i - 1] == b'.')
            && let Some(compression) = compression
        {
            // `i` follows a `.` (or is 0), so it falls on a character boundary.
            let key = &name[i..];
            if let Some(ptr) = compression.find(&msg, compression_off, key) {
                // Hit. Emit a pointer instead of the rest of
                // the domain.
                msg.push(((ptr >> 8) | 0xC0) as u8);
                msg.push((ptr & 0xFF) as u8);
                return Ok(msg);
            }

            // Miss. Add the suffix to the compression table if the
            // offset can be stored in the available 14 bytes.
            if msg.len() <= 0x3FFF {
                compression.insert(key, msg.len() - compression_off);
            }
        }
    }

    msg.push(0);
    Ok(msg)
}
