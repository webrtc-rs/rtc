use std::collections::HashSet;

use shared::error::{Error, Result};
use stun::attributes::*;
use stun::fingerprint::FINGERPRINT;
use stun::message::*;

/// Decode exactly one UDP STUN message, validating integrity layout before its checker runs.
pub(super) fn decode(data: &[u8]) -> Result<Message> {
    if data.len() < 20 || data[0] & 0xc0 != 0 {
        return Err(Error::Other("invalid STUN header".into()));
    }
    let size = u16::from_be_bytes([data[2], data[3]]) as usize;
    if !size.is_multiple_of(4) || size + 20 != data.len() {
        return Err(Error::Other("invalid STUN datagram length".into()));
    }
    let mut message = Message::new();
    message.unmarshal_binary(data)?;
    let mut seen = HashSet::new();
    let mut integrity_seen = false;
    for (index, attr) in message.attributes.0.iter().enumerate() {
        // Repeated XOR-PEER-ADDRESS values are permitted in CreatePermission only.
        if attr.typ == ATTR_XOR_PEER_ADDRESS {
            if message.typ.method != METHOD_CREATE_PERMISSION && !seen.insert(attr.typ.value()) {
                return Err(Error::Other("duplicate peer address".into()));
            }
        } else if !seen.insert(attr.typ.value()) {
            return Err(Error::Other("duplicate STUN attribute".into()));
        }
        if attr.typ == ATTR_MESSAGE_INTEGRITY {
            if attr.value.len() != 20 {
                return Err(Error::Other("invalid MESSAGE-INTEGRITY length".into()));
            }
            integrity_seen = true;
        } else if attr.typ == ATTR_FINGERPRINT {
            if attr.value.len() != 4 || index + 1 != message.attributes.0.len() {
                return Err(Error::Other("invalid FINGERPRINT layout".into()));
            }
            FINGERPRINT.check(&message)?;
        } else if integrity_seen {
            // Never act on unauthenticated attributes after MESSAGE-INTEGRITY.
            return Err(Error::Other("attribute follows MESSAGE-INTEGRITY".into()));
        }
    }
    Ok(message)
}

pub(super) fn unknown_attributes(message: &Message) -> Vec<AttrType> {
    message
        .attributes
        .0
        .iter()
        .filter_map(|attr| {
            let known = matches!(
                attr.typ,
                ATTR_USERNAME
                    | ATTR_REALM
                    | ATTR_NONCE
                    | ATTR_MESSAGE_INTEGRITY
                    | ATTR_REQUESTED_TRANSPORT
                    | ATTR_REQUESTED_ADDRESS_FAMILY
                    | ATTR_LIFETIME
                    | ATTR_XOR_PEER_ADDRESS
                    | ATTR_CHANNEL_NUMBER
                    | ATTR_DATA
                    | ATTR_EVEN_PORT
                    | ATTR_RESERVATION_TOKEN
                    | ATTR_DONT_FRAGMENT
            );
            (!known && attr.typ.value() < 0x8000).then_some(attr.typ)
        })
        .collect()
}

pub(super) fn response(request: &Message, class: MessageClass) -> Message {
    let mut message = Message::new();
    message.set_type(MessageType::new(request.typ.method, class));
    message.transaction_id = request.transaction_id;
    message.write_header();
    message
}

pub(super) fn text(message: &Message, attr: AttrType, max: usize) -> Option<String> {
    let value = message.get(attr).ok()?;
    if value.is_empty() || value.len() > max {
        return None;
    }
    String::from_utf8(value).ok()
}
