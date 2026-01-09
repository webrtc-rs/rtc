use std::collections::HashMap;
use std::fmt;

use super::name::*;
use super::*;
use shared::error::Result;

// A question is a DNS query.
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub(crate) struct Question {
    pub(crate) name: Name,
    pub(crate) typ: DnsType,
    pub(crate) class: DnsClass,
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dnsmessage.question{{Name: {}, Type: {}, Class: {}}}",
            self.name, self.typ, self.class
        )
    }
}

impl Question {
    // pack appends the wire format of the question to msg.
    pub(crate) fn pack(
        &self,
        mut msg: Vec<u8>,
        compression: &mut Option<HashMap<String, usize>>,
        compression_off: usize,
    ) -> Result<Vec<u8>> {
        msg = self.name.pack(msg, compression, compression_off)?;
        msg = self.typ.pack(msg);
        Ok(self.class.pack(msg))
    }
}
