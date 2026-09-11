//! Separates deliverable messages from protocol reassembly and its SSN space.

use super::reassembly_queue::{Chunks, ReassemblyQueue};
use crate::StreamId;
use crate::chunk::chunk_payload_data::ChunkPayloadData;
use std::collections::VecDeque;

/// Local identity of an RX SSN space; independent of API delivery generations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReceiveEpoch(u64);

#[derive(Debug)]
pub(crate) enum DeferredReceive {
    Data(ChunkPayloadData),
    ForwardUnordered(u32),
}

#[derive(Debug, Default)]
pub(crate) struct ReceiveQueue {
    id: StreamId,
    assembly: ReassemblyQueue,
    // The wire SSN epoch may be newer than the oldest API delivery below.
    epoch: ReceiveEpoch,
    active: bool,
    outgoing_reset_requested: bool,
    // A completed RX reset still needs a pending TX reset to close both sides.
    // This obligation survives reuse of RX while TX requests stay serialized.
    required_outgoing_epoch: Option<ReceiveEpoch>,
    // None is EOF for the preceding API receiver. Later messages belong to
    // the next receiver even while the application is still reading the old one.
    ready: VecDeque<Option<Chunks>>,
    ready_bytes: usize,
    closed_deliveries: usize,
    stopped: bool,
    deferred: VecDeque<DeferredReceive>,
    deferred_bytes: usize,
}

impl ReceiveQueue {
    pub(crate) fn new(id: StreamId) -> Self {
        Self {
            id,
            assembly: ReassemblyQueue::new(id),
            active: true,
            ..Self::default()
        }
    }

    /// A local open starts use of the current wire epoch even before DATA.
    pub(crate) fn open(&mut self) {
        self.active = true;
    }

    pub(crate) fn needs_reciprocal_reset(&self) -> bool {
        self.active && !self.outgoing_reset_requested
    }

    pub(crate) fn note_outgoing_reset(&mut self) -> ReceiveEpoch {
        self.outgoing_reset_requested = true;
        self.epoch
    }

    pub(crate) fn require_outgoing_reset(&mut self) {
        if self.active {
            self.required_outgoing_epoch = Some(self.epoch);
        }
    }

    /// A later TX reset also covers any earlier unfinished close on this SID.
    pub(crate) fn complete_outgoing_reset(&mut self, epoch: ReceiveEpoch) {
        if self
            .required_outgoing_epoch
            .is_some_and(|required| epoch >= required)
        {
            self.required_outgoing_epoch = None;
        }
    }

    /// A refused last request may be attempted again by a later peer close.
    /// Returns whether an already completed RX reset now cannot be matched.
    pub(crate) fn refuse_outgoing_reset(&mut self) -> bool {
        self.outgoing_reset_requested = false;
        self.required_outgoing_epoch.is_some()
    }

    /// The API receiver at the front belongs to a completed wire epoch.
    pub(crate) fn delivery_closed(&self) -> bool {
        self.closed_deliveries != 0
    }

    fn collect_ready(&mut self) {
        while let Some(message) = self.assembly.read() {
            if !self.stopped || self.delivery_closed() {
                self.ready_bytes += message.len();
                self.ready.push_back(Some(message));
            }
        }
    }

    pub(crate) fn push(&mut self, data: ChunkPayloadData) -> bool {
        self.active = true;
        let before = self.ready.len();
        self.assembly.push(data);
        self.collect_ready();
        self.ready.len() > before
    }

    pub(crate) fn is_readable(&self) -> bool {
        matches!(self.ready.front(), Some(Some(_)))
    }

    pub(crate) fn read(&mut self) -> Option<Chunks> {
        if !self.is_readable() {
            return None;
        }
        let message = self.ready.pop_front().flatten().unwrap();
        self.ready_bytes -= message.len();
        Some(message)
    }

    pub(crate) fn forward_tsn_for_ordered(&mut self, ssn: u16) {
        self.active = true;
        self.assembly.forward_tsn_for_ordered(ssn);
        self.collect_ready();
    }

    pub(crate) fn forward_tsn_for_unordered(&mut self, tsn: u32) {
        self.assembly.forward_tsn_for_unordered(tsn);
        self.collect_ready();
    }

    pub(crate) fn get_num_bytes(&self) -> usize {
        // Moving a complete message into delivery does not reopen receive credit.
        self.assembly.get_num_bytes() + self.ready_bytes + self.deferred_bytes
    }

    pub(crate) fn reset(&mut self) {
        self.collect_ready();
        self.assembly = ReassemblyQueue::new(self.id);
        self.epoch.0 = self
            .epoch
            .0
            .checked_add(1)
            .expect("RX epoch counter exhausted");
        self.active = false;
        self.outgoing_reset_requested = false;
        // Empty generations need no separate delivery object or unbounded EOFs.
        if !matches!(self.ready.back(), Some(None)) {
            self.ready.push_back(None);
            self.closed_deliveries += 1;
        }
    }

    pub(crate) fn finish_delivery(&mut self) -> bool {
        if !matches!(self.ready.front(), Some(None)) {
            return false;
        }
        self.ready.pop_front();
        self.closed_deliveries -= 1;
        self.stopped = false;
        true
    }

    pub(crate) fn stop(&mut self) {
        while let Some(message) = self.read() {
            drop(message);
        }
        self.stopped = true;
    }

    pub(crate) fn defer(&mut self, action: DeferredReceive) {
        self.deferred_bytes += match &action {
            DeferredReceive::Data(data) => data.user_data.len(),
            DeferredReceive::ForwardUnordered(_) => 4,
        };
        self.deferred.push_back(action);
    }

    pub(crate) fn take_deferred(&mut self) -> VecDeque<DeferredReceive> {
        self.deferred_bytes = 0;
        std::mem::take(&mut self.deferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn completed_reset_covers_only_its_rx_epoch_and_earlier_obligations() {
        for newer_required in [false, true] {
            let mut queue = ReceiveQueue::new(1);
            let first = queue.note_outgoing_reset();
            queue.require_outgoing_reset();
            queue.reset();
            // Repeated reset of an unused epoch creates no new obligation.
            queue.require_outgoing_reset();
            queue.reset();
            queue.open();
            let next = queue.note_outgoing_reset();
            assert!(next > first);
            if newer_required {
                queue.require_outgoing_reset();
                queue.reset();
            }
            queue.complete_outgoing_reset(first);
            assert_eq!(queue.refuse_outgoing_reset(), newer_required);
            queue.complete_outgoing_reset(next);
            assert!(!queue.refuse_outgoing_reset());
        }
    }

    #[test]
    fn wire_reset_state_is_independent_of_saved_deliveries() {
        let mut queue = ReceiveQueue::new(1);
        for tsn in 1..=2 {
            assert!(queue.needs_reciprocal_reset());
            queue.note_outgoing_reset();
            assert!(!queue.needs_reciprocal_reset());
            queue.push(ChunkPayloadData {
                tsn,
                stream_identifier: 1,
                beginning_fragment: true,
                ending_fragment: true,
                user_data: Bytes::from_static(b"saved"),
                ..Default::default()
            });
            queue.reset();
            assert!(!queue.needs_reciprocal_reset());
            assert!(queue.delivery_closed());
            queue.open();
        }
        assert_eq!(queue.closed_deliveries, 2);
        assert!(queue.needs_reciprocal_reset());
        assert!(queue.read().is_some());
        assert!(queue.finish_delivery());
        assert!(
            queue.delivery_closed(),
            "a second saved receiver is still closed"
        );
        assert!(queue.read().is_some());
        assert!(queue.finish_delivery());
        assert!(!queue.delivery_closed());
        assert!(
            queue.needs_reciprocal_reset(),
            "reading EOF cannot reset the active wire epoch"
        );
    }

    #[test]
    fn ready_delivery_and_reset_preserve_payload_allocations_and_window_charge() {
        for size in [16, 4000] {
            for unordered in [false, true] {
                let original = Bytes::from(vec![0x5a; size]);
                let mut queue = ReceiveQueue::new(1);
                let mut pointers = vec![];
                for (index, start) in (0..size).step_by(1200).enumerate() {
                    let end = (start + 1200).min(size);
                    let data = original.slice(start..end);
                    pointers.push(data.as_ptr());
                    queue.push(ChunkPayloadData {
                        stream_identifier: 1,
                        tsn: index as u32,
                        unordered,
                        beginning_fragment: start == 0,
                        ending_fragment: end == size,
                        user_data: data,
                        ..Default::default()
                    });
                }
                queue.reset();
                assert_eq!(queue.get_num_bytes(), size);
                let delivered = queue.read().unwrap();
                assert_eq!(delivered.len(), size);
                assert_eq!(
                    delivered
                        .chunks
                        .iter()
                        .map(|chunk| chunk.user_data.as_ptr())
                        .collect::<Vec<_>>(),
                    pointers,
                    "moving unread messages across reset must not copy payload"
                );
                assert_eq!(queue.get_num_bytes(), 0);
                assert!(queue.finish_delivery());
                assert!(!queue.finish_delivery(), "EOF is consumed once");
            }
        }
    }
}
