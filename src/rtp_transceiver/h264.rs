//! H.264 profile/level semantics shared by SDP matching and encoded-media callers.
//!
//! RFC 6184 sections 8.1 and 8.2.2 define profile equivalence independently of
//! level negotiation. Neither comparison below negotiates an offer/answer or
//! permits a fixed encoded stream to exceed a receiver's level.

/// The three octets of an explicit `profile-level-id`, retained without rewriting.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct H264ProfileLevelId([u8; 3]);

impl H264ProfileLevelId {
    /// Parses the three hexadecimal octets and a defined H.264 level.
    /// Missing SDP values and their defaults belong to the SDP caller.
    pub fn parse(value: &str) -> Option<Self> {
        let bytes: [u8; 3] = hex::decode(value).ok()?.try_into().ok()?;
        let [idc, _, level] = bytes;
        if idc == 0
            || !matches!(level, 9..=13 | 20..=22 | 30..=32 | 40..=42 | 50..=52 | 60..=62)
            || (level == 9 && matches!(idc, 0x42 | 0x4d | 0x58))
        {
            return None;
        }
        Some(Self(bytes))
    }

    /// Whether both values identify the same sub-profile, regardless of level.
    pub fn is_same_profile(self, other: Self) -> bool {
        self.profile_key() == other.profile_key()
    }

    /// Whether this value identifies the Constrained Baseline sub-profile.
    pub fn is_constrained_baseline(self) -> bool {
        self.profile_key() == 0x42e0
    }

    /// Compares levels only: Level 1 < Level 1b < Level 1.1.
    /// Callers must separately establish profile and packetization compatibility.
    /// `level-asymmetry-allowed` does not change this ordering.
    pub fn is_level_at_most(self, other: Self) -> bool {
        self.level_order() <= other.level_order()
    }

    pub(crate) fn with_level(self, other: Self) -> Self {
        let [idc, mut iop, _] = self.0;
        let is_base_profile = matches!(idc, 0x42 | 0x4d | 0x58);
        let level = if other.level_order() == 21 {
            if is_base_profile { 11 } else { 9 }
        } else {
            other.0[2]
        };
        if is_base_profile {
            iop = (iop & !0x10) | if other.level_order() == 21 { 0x10 } else { 0 };
        }
        Self([idc, iop, level])
    }

    fn profile_key(self) -> u16 {
        let [idc, iop, _] = self.0;
        // RFC 6184 Table 5. Remaining profiles retain their exact two octets.
        match (idc, iop) {
            (0x42, v) if v & 0x4f == 0x40 => 0x42e0,
            (0x4d, v) if v & 0x8f == 0x80 => 0x42e0,
            (0x58, v) if v & 0xcf == 0xc0 => 0x42e0,
            (0x42, v) if v & 0x4f == 0x00 => 0x4200,
            (0x58, v) if v & 0xcf == 0x80 => 0x4200,
            (0x4d, v) if v & 0xaf == 0x00 => 0x4d00,
            (0x58, v) if v & 0xcf == 0x00 => 0x5800,
            _ => u16::from_be_bytes([idc, iop]),
        }
    }

    fn level_order(self) -> u16 {
        let [idc, iop, level] = self.0;
        if level == 9 || (matches!(idc, 0x42 | 0x4d | 0x58) && level == 11 && iop & 0x10 != 0) {
            21 // Level 1b lies strictly between level_idc 10 and 11.
        } else {
            u16::from(level) * 2
        }
    }
}

impl std::fmt::Display for H264ProfileLevelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

#[cfg(test)]
mod tests {
    use super::H264ProfileLevelId;

    #[test]
    fn both_level1b_encodings_sort_between_level1_and_level11() {
        for values in [
            ["42e00a", "42f00b", "42e00b"],
            ["64000a", "640009", "64000b"],
        ] {
            let [one, one_b, one_one] =
                values.map(|value| H264ProfileLevelId::parse(value).unwrap());
            assert!(one.is_same_profile(one_b) && one_b.is_same_profile(one_one));
            assert!(one.is_level_at_most(one_b) && !one_b.is_level_at_most(one));
            assert!(one_b.is_level_at_most(one_one) && !one_one.is_level_at_most(one_b));
        }
    }
}
