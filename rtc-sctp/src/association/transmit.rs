//! Wire sequence state belongs to a direction, not to a local Stream handle.

use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId};
use shared::error::{Error, Result};

#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct TransmitStream {
    pub(crate) next_ssn: u16,
    active_message: Option<(MessageId, u16)>,
}

impl TransmitStream {
    /// Prepare a fragment's SSN on a copy, then commit it after the pending
    /// queue accepts the pop. Waiting messages have consumed no SSN yet.
    pub(crate) fn assign_ssn(&mut self, chunk: &ChunkPayloadData) -> Result<u16> {
        let id = chunk
            .message_id
            .ok_or_else(|| Error::OtherSctpErr("outbound DATA has no message identity".into()))?;
        let ssn = if chunk.beginning_fragment {
            if self.active_message.is_some() {
                return Err(Error::OtherSctpErr(
                    "message fragmentation is still active".into(),
                ));
            }
            let ssn = self.next_ssn;
            if !chunk.unordered {
                self.next_ssn = self.next_ssn.wrapping_add(1);
            }
            self.active_message = Some((id, ssn));
            ssn
        } else {
            match self.active_message {
                Some((active, ssn)) if active == id => ssn,
                _ => {
                    return Err(Error::OtherSctpErr(
                        "missing active message fragment".into(),
                    ));
                }
            }
        };
        if chunk.ending_fragment {
            self.active_message = None;
        }
        Ok(ssn)
    }

    /// RFC 6525 H4. A reset boundary follows all previously queued fragments.
    pub(crate) fn reset(&mut self) -> Result<()> {
        if self.active_message.is_some() {
            return Err(Error::OtherSctpErr(
                "reset crosses an active message".into(),
            ));
        }
        self.next_ssn = 0;
        Ok(())
    }

    pub(crate) fn abandon_tail(&mut self, id: MessageId) -> Result<u16> {
        let ssn = match self.active_message {
            Some((active, ssn)) if active == id => ssn,
            _ => return Err(Error::OtherSctpErr("missing active message tail".into())),
        };
        self.active_message = None;
        Ok(ssn)
    }
}
