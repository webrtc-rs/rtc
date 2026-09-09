//! Wire sequence state belongs to a direction, not to a local Stream handle.

use crate::chunk::chunk_payload_data::{ChunkPayloadData, MessageId};

#[derive(Debug, Default)]
pub(crate) struct TransmitStream {
    pub(crate) next_ssn: u16,
    active_message: Option<(MessageId, u16)>,
}

impl TransmitStream {
    /// Called only when a fragment receives a TSN. Messages waiting for a send
    /// window or reset result have not consumed an SSN yet.
    pub(crate) fn assign_ssn(&mut self, chunk: &mut ChunkPayloadData) {
        let id = chunk.message_id.expect("queued message identity");
        let ssn = if chunk.beginning_fragment {
            debug_assert!(self.active_message.is_none());
            let ssn = self.next_ssn;
            if !chunk.unordered {
                self.next_ssn = self.next_ssn.wrapping_add(1);
            }
            self.active_message = Some((id, ssn));
            ssn
        } else {
            let (active, ssn) = self.active_message.expect("fragmentation in progress");
            debug_assert_eq!(active, id);
            ssn
        };
        chunk.stream_sequence_number = ssn;
        if chunk.ending_fragment {
            self.active_message = None;
        }
    }

    /// RFC 6525 H4. A reset boundary follows all previously queued fragments.
    pub(crate) fn reset(&mut self) {
        debug_assert!(self.active_message.is_none());
        self.next_ssn = 0;
    }

    pub(crate) fn abandon_tail(&mut self, id: MessageId) -> u16 {
        let (active, ssn) = self
            .active_message
            .take()
            .expect("fragmentation in progress");
        debug_assert_eq!(active, id);
        ssn
    }
}
