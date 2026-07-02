use bytes::{BufMut, Bytes, BytesMut};

pub fn decode_leb128(mut val: u64) -> u32 {
    let mut b = 0;
    loop {
        b |= val & 0b_0111_1111;
        val >>= 8;
        if val == 0 {
            return b as u32;
        }
        b <<= 7;
    }
}

pub fn read_leb128(bytes: &Bytes) -> (u32, usize) {
    let mut encoded = 0;
    for i in 0..bytes.len() {
        encoded |= bytes[i] as u64;
        if bytes[i] & 0b_1000_0000 == 0 {
            return (decode_leb128(encoded), i + 1);
        }
        encoded <<= 8;
    }
    (0, 0)
}

pub fn leb128_size(value: u32) -> usize {
    let mut size = 0;
    let mut value = value;
    while value >= 0b_1000_0000 {
        size += 1;
        value >>= 7;
    }
    size + 1
}

pub trait BytesMutExt {
    fn put_leb128(&mut self, n: u32);
}

impl BytesMutExt for BytesMut {
    /// Appends `n` to the buffer using unsigned LEB128 variable-length encoding,
    /// as required by the AV1 bitstream/RTP OBU size fields. Each output byte
    /// carries 7 bits of the value in its low bits; bit 7 is a continuation flag
    /// that is set on every byte except the last.
    fn put_leb128(&mut self, mut n: u32) {
        loop {
            let byte = (n & 0b_0111_1111) as u8;
            n >>= 7;
            if n == 0 {
                self.put_u8(byte);
                return;
            }
            self.put_u8(byte | 0b_1000_0000);
        }
    }
}
