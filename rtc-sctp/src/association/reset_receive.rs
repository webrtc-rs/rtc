//! Accepted incoming reset procedures and a bounded replay history.
//!
//! RFC 6525 §§5.2.1–5.2.2 requires retransmissions to retain their result and
//! deferred requests to resume at their TSN boundary. An accepted procedure is
//! consequently independent of the small history used for completed duplicates.
//! The original wire request is immutable; an empty SID list is resolved
//! separately as incoming streams become known before application of the reset.
//!
//! E1 acknowledgement/timer handling, E3 RX mutation, E4 held DATA, and E5–E6
//! response packet construction belong to the association, not this container.

use std::collections::{BTreeSet, VecDeque};

use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_reconfig_response::ReconfigResult;
use crate::util::{sna32gt, sna32lte};

// Administrative admission limits permitted by RFC 6525 §5.2.1. The SID budget
// counts immutable wire lists plus resolved SID sets. An all-stream request
// reserves its negotiated maximum immediately, so later observe_stream calls
// cannot grow accepted state beyond the admission budget.
const MAX_PENDING_REQUESTS: usize = 32;
const MAX_PENDING_STREAM_IDS: usize = 65_536;
const REPLAY_RESULTS: usize = 2;
// A parameter has a u16 wire length, including its 16-byte fixed fields.
const MAX_WIRE_STREAM_IDS: usize = (u16::MAX as usize - 16) / 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum ReceiveResetAction {
    /// Newly accepted request; apply it if ready, otherwise answer InProgress.
    New,
    /// Exact duplicate of an accepted request which still awaits application.
    Pending,
    /// A completed duplicate or an administrative/sequence rejection.
    Reply(ReconfigResult),
}

#[derive(Debug, Clone)]
pub(super) struct IncomingReset {
    original: ParamOutgoingResetRequest,
    streams: ResetStreams,
    max_inbound: u16,
    reserved_stream_ids: usize,
}

/// A one-SID reset needs no tree allocation. Larger selections retain the
/// BTreeSet's sorted, deduplicated traversal and logarithmic insert/lookup.
#[derive(Debug, Clone, Default)]
pub(super) struct ResetStreams {
    first: Option<u16>,
    remaining: BTreeSet<u16>,
}

impl ResetStreams {
    fn insert(&mut self, sid: u16) -> bool {
        match self.first {
            None => {
                self.first = Some(sid);
                true
            }
            Some(first) if sid == first => false,
            Some(first) if sid < first => {
                self.remaining.insert(first);
                self.first = Some(sid);
                true
            }
            Some(_) => self.remaining.insert(sid),
        }
    }

    fn contains(&self, sid: &u16) -> bool {
        self.first.as_ref() == Some(sid) || self.remaining.contains(sid)
    }

    fn len(&self) -> usize {
        usize::from(self.first.is_some()) + self.remaining.len()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &u16> {
        self.first.iter().chain(self.remaining.iter())
    }
}

impl FromIterator<u16> for ResetStreams {
    fn from_iter<T: IntoIterator<Item = u16>>(iter: T) -> Self {
        let mut iter = iter.into_iter();
        let Some(first) = iter.next() else {
            return Self::default();
        };
        let Some(second) = iter.next() else {
            return Self {
                first: Some(first),
                remaining: BTreeSet::new(),
            };
        };
        // Preserve the BTreeSet bulk-build path for larger incoming requests.
        let mut remaining: BTreeSet<_> = [first, second].into_iter().chain(iter).collect();
        Self {
            first: remaining.pop_first(),
            remaining,
        }
    }
}

impl IncomingReset {
    #[cfg(test)]
    pub(super) fn original(&self) -> &ParamOutgoingResetRequest {
        &self.original
    }

    /// Stable, deduplicated selection, separate from the original wire SID list.
    #[cfg(test)]
    pub(super) fn streams(&self) -> impl Iterator<Item = &u16> {
        self.streams.iter()
    }

    fn affects(&self, sid: u16) -> bool {
        sid < self.max_inbound
            && (self.original.stream_identifiers.is_empty() || self.streams.contains(&sid))
    }
}

#[derive(Debug)]
struct CompletedReset {
    original: ParamOutgoingResetRequest,
    result: ReconfigResult,
}

#[derive(Debug)]
pub(super) struct IncomingResetQueue {
    next_expected_rsn: u32,
    // Arrival order is RSN order, including wrapping from u32::MAX to zero.
    pending: VecDeque<IncomingReset>,
    // Ordered by request RSN, not by completion time. Completion of an older
    // deferred request must not evict the result of the latest received one.
    completed: VecDeque<CompletedReset>,
    reserved_stream_ids: usize,
}

impl IncomingResetQueue {
    pub(super) fn new(peer_initial_tsn: u32) -> Self {
        Self {
            next_expected_rsn: peer_initial_tsn,
            pending: VecDeque::new(),
            completed: VecDeque::new(),
            reserved_stream_ids: 0,
        }
    }

    #[cfg(test)]
    pub(super) fn next_expected_rsn(&self) -> u32 {
        self.next_expected_rsn
    }

    /// Value used by an independently initiated outgoing request's A4 field.
    pub(super) fn last_received_rsn(&self) -> u32 {
        self.next_expected_rsn.wrapping_sub(1)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[cfg(test)]
    pub(super) fn history_len(&self) -> usize {
        self.completed.len()
    }

    pub(super) fn get(&self, sequence: u32) -> Option<&IncomingReset> {
        self.pending
            .iter()
            .find(|p| p.original.reconfig_request_sequence_number == sequence)
    }

    /// Admission consumes an expected RSN exactly once, including a definitive
    /// administrative refusal. Exact pending/completed duplicates reuse their
    /// prior state. Changed payloads using the same RSN never execute a reset.
    pub(super) fn accept(
        &mut self,
        request: &ParamOutgoingResetRequest,
        known_sids: impl IntoIterator<Item = u16>,
        max_inbound: u16,
    ) -> ReceiveResetAction {
        let sequence = request.reconfig_request_sequence_number;
        if let Some(pending) = self.get(sequence) {
            return if pending.original == *request {
                ReceiveResetAction::Pending
            } else {
                ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
            };
        }
        if let Some(completed) = self
            .completed
            .iter()
            .find(|p| p.original.reconfig_request_sequence_number == sequence)
        {
            return ReceiveResetAction::Reply(if completed.original == *request {
                completed.result
            } else {
                ReconfigResult::ErrorBadSequenceNumber
            });
        }
        if sequence != self.next_expected_rsn {
            return ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber);
        }
        // Such a value cannot be produced by the wire decoder. Do not retain an
        // unbounded synthetic request if another internal caller constructs one.
        if request.stream_identifiers.len() > MAX_WIRE_STREAM_IDS {
            return ReceiveResetAction::Reply(ReconfigResult::Denied);
        }
        self.next_expected_rsn = self.next_expected_rsn.wrapping_add(1);
        let all_streams = request.stream_identifiers.is_empty();
        let streams: ResetStreams = if all_streams {
            known_sids
                .into_iter()
                .filter(|sid| *sid < max_inbound)
                .collect()
        } else {
            request.stream_identifiers.iter().copied().collect()
        };
        let reserved_stream_ids = request.stream_identifiers.len()
            + if all_streams {
                usize::from(max_inbound)
            } else {
                streams.len()
            };
        if streams.iter().any(|sid| *sid >= max_inbound)
            || self.pending.len() >= MAX_PENDING_REQUESTS
            || reserved_stream_ids > MAX_PENDING_STREAM_IDS - self.reserved_stream_ids
        {
            self.remember(request.clone(), ReconfigResult::Denied);
            return ReceiveResetAction::Reply(ReconfigResult::Denied);
        }
        self.reserved_stream_ids += reserved_stream_ids;
        self.pending.push_back(IncomingReset {
            original: request.clone(),
            streams,
            max_inbound,
            reserved_stream_ids,
        });
        ReceiveResetAction::New
    }

    /// Add an incoming stream discovered while an all-stream reset is deferred.
    /// This is also safe for DATA beyond the boundary: E2 holds its payload until
    /// reset, so resetting its freshly created RX state precedes DATA delivery.
    pub(super) fn observe_stream(&mut self, sid: u16) {
        for pending in &mut self.pending {
            if pending.original.stream_identifiers.is_empty() && sid < pending.max_inbound {
                pending.streams.insert(sid);
            }
        }
    }

    /// First reset affecting this SID. Hold DATA beyond this boundary per E2,
    /// then look again after completion to find a subsequent accepted reset.
    /// All-stream requests match valid SIDs even before their first DATA exists.
    pub(super) fn boundary(&self, sid: u16) -> Option<u32> {
        self.pending
            .iter()
            .find(|p| p.affects(sid))
            .map(|p| p.original.sender_last_tsn)
    }

    /// Requests ready for application, in acceptance/RSN order. The caller must
    /// apply and complete each request before applying the next returned RSN.
    /// A valid sender's Last Assigned TSN cannot move backwards across requests;
    /// retaining this prefix order also avoids reordering overlapping resets if
    /// an inconsistent peer supplies a later, smaller boundary.
    pub(super) fn ready(&self, peer_last_tsn: u32) -> Vec<u32> {
        self.pending
            .iter()
            .take_while(|p| sna32lte(p.original.sender_last_tsn, peer_last_tsn))
            .map(|p| p.original.reconfig_request_sequence_number)
            .collect()
    }

    /// Test membership in the same ready prefix without allocating its RSN list.
    pub(super) fn is_ready(&self, sequence: u32, peer_last_tsn: u32) -> bool {
        self.pending
            .iter()
            .take_while(|p| sna32lte(p.original.sender_last_tsn, peer_last_tsn))
            .any(|p| p.original.reconfig_request_sequence_number == sequence)
    }

    /// Remove only this completed procedure. Its result history is bounded,
    /// while other accepted requests retain their original selection and TSN.
    /// InProgress is a continuation and must not remove the accepted procedure.
    pub(super) fn complete(
        &mut self,
        sequence: u32,
        result: ReconfigResult,
    ) -> Option<ResetStreams> {
        if result == ReconfigResult::InProgress {
            return None;
        }
        let index = self
            .pending
            .iter()
            .position(|p| p.original.reconfig_request_sequence_number == sequence)?;
        let IncomingReset {
            original,
            streams,
            reserved_stream_ids,
            ..
        } = self.pending.remove(index)?;
        self.reserved_stream_ids -= reserved_stream_ids;
        // The wire request lives only in replay history after completion. The
        // caller applies the separately resolved selection, including all-SID
        // expansion, so retaining a second wire SID allocation is unnecessary.
        self.remember(original, result);
        Some(streams)
    }

    fn remember(&mut self, original: ParamOutgoingResetRequest, result: ReconfigResult) {
        let sequence = original.reconfig_request_sequence_number;
        let index = self
            .completed
            .iter()
            .position(|p| sna32gt(p.original.reconfig_request_sequence_number, sequence))
            .unwrap_or(self.completed.len());
        self.completed
            .insert(index, CompletedReset { original, result });
        if self.completed.len() > REPLAY_RESULTS {
            self.completed.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_stream_selection_preserves_sorted_set_semantics() {
        for input in [vec![], vec![7], vec![7, 7], vec![9, 1, 7, 1, 3]] {
            let mut selection: ResetStreams = input.iter().copied().collect();
            let mut expected: BTreeSet<_> = input.into_iter().collect();
            for sid in [7, 0, 12, 3, 0, 7] {
                assert_eq!(selection.insert(sid), expected.insert(sid));
                assert_eq!(selection.len(), expected.len());
                assert_eq!(
                    selection.iter().copied().collect::<Vec<_>>(),
                    expected.iter().copied().collect::<Vec<_>>()
                );
                for probe in [0, 1, 7, 12, 13] {
                    assert_eq!(selection.contains(&probe), expected.contains(&probe));
                }
            }
        }
        let single: ResetStreams = [7].into_iter().collect();
        assert!(single.remaining.is_empty());
        let mut copied = single.clone();
        copied.insert(1);
        assert_eq!(single.iter().copied().collect::<Vec<_>>(), [7]);
        assert_eq!(copied.iter().copied().collect::<Vec<_>>(), [1, 7]);
    }

    fn request(sequence: u32, boundary: u32, streams: &[u16]) -> ParamOutgoingResetRequest {
        ParamOutgoingResetRequest {
            reconfig_request_sequence_number: sequence,
            reconfig_response_sequence_number: 90,
            sender_last_tsn: boundary,
            stream_identifiers: streams.to_vec(),
        }
    }

    #[test]
    fn sequence_and_tsn_boundaries_wrap() {
        let mut resets = IncomingResetQueue::new(u32::MAX);
        assert_eq!(resets.last_received_rsn(), u32::MAX - 1);
        assert_eq!(
            resets.accept(&request(u32::MAX, u32::MAX, &[1]), [], 4),
            ReceiveResetAction::New
        );
        assert_eq!(
            resets.accept(&request(0, 0, &[2]), [], 4),
            ReceiveResetAction::New
        );
        assert_eq!(resets.ready(u32::MAX - 1), []);
        assert_eq!(resets.ready(u32::MAX), [u32::MAX]);
        assert_eq!(resets.ready(0), [u32::MAX, 0]);
        assert_eq!(resets.next_expected_rsn(), 1);
        assert_eq!(resets.last_received_rsn(), 0);
    }

    #[test]
    fn individual_readiness_preserves_the_accepted_prefix_barrier() {
        let mut resets = IncomingResetQueue::new(u32::MAX);
        resets.accept(&request(u32::MAX, 100, &[1]), [], 4);
        // Even an inconsistent later request with an earlier TSN must not pass
        // the still deferred prefix, including when the RSN wraps through zero.
        resets.accept(&request(0, 90, &[2]), [], 4);
        for boundary in [89, 90, 99, 100] {
            let ready = resets.ready(boundary);
            for sequence in [u32::MAX, 0, 1] {
                assert_eq!(
                    resets.is_ready(sequence, boundary),
                    ready.contains(&sequence)
                );
            }
        }
        assert!(!resets.is_ready(0, 90));
        resets.complete(u32::MAX, ReconfigResult::SuccessPerformed);
        assert!(resets.is_ready(0, 100));
        assert!(!resets.is_ready(u32::MAX, 100));
    }

    #[test]
    fn completion_moves_the_wire_selection_into_replay_history() {
        for wire_sids in [vec![2, 1, 2], vec![]] {
            let mut resets = IncomingResetQueue::new(10);
            let original = request(10, 100, &wire_sids);
            resets.accept(&original, [1, 2], 4);
            let saved_wire = resets.get(10).unwrap().original();
            let allocation = saved_wire.stream_identifiers.as_ptr();
            let completed = resets
                .complete(10, ReconfigResult::SuccessPerformed)
                .unwrap();
            assert_eq!(completed.iter().copied().collect::<Vec<_>>(), [1, 2]);
            let history = &resets.completed.back().unwrap().original;
            assert_eq!(history, &original);
            assert_eq!(history.stream_identifiers.as_ptr(), allocation);
            assert_eq!(
                resets.accept(&original, [], 4),
                ReceiveResetAction::Reply(ReconfigResult::SuccessPerformed)
            );
        }
    }

    #[test]
    fn rejects_skipped_rsn_without_consuming_it() {
        let mut resets = IncomingResetQueue::new(10);
        assert_eq!(
            resets.accept(&request(11, 9, &[1]), [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
        assert_eq!(resets.next_expected_rsn(), 10);
        assert_eq!(
            resets.accept(&request(10, 9, &[1]), [], 4),
            ReceiveResetAction::New
        );
    }

    #[test]
    fn all_streams_selection_is_separate_from_immutable_wire_request() {
        let mut resets = IncomingResetQueue::new(10);
        let original = request(10, 100, &[]);
        assert_eq!(
            resets.accept(&original, [1, 2, 2, 9], 8),
            ReceiveResetAction::New
        );
        assert_eq!(
            &resets
                .get(10)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([1, 2])
        );
        assert_eq!(resets.boundary(7), Some(100));
        assert_eq!(resets.boundary(8), None);
        resets.observe_stream(3);
        resets.observe_stream(8);
        assert_eq!(
            &resets
                .get(10)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([1, 2, 3])
        );
        assert_eq!(resets.get(10).unwrap().original(), &original);
        // A retry does not replace the resolved list with a new snapshot.
        assert_eq!(
            resets.accept(&original, [4], 8),
            ReceiveResetAction::Pending
        );
        assert_eq!(
            &resets
                .get(10)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([1, 2, 3])
        );
    }

    #[test]
    fn explicit_selection_validates_negotiated_max_and_deduplicates() {
        let mut resets = IncomingResetQueue::new(10);
        assert_eq!(
            resets.accept(&request(10, 9, &[u16::MAX - 1]), [], u16::MAX),
            ReceiveResetAction::New
        );
        let invalid = request(11, 9, &[u16::MAX]);
        assert_eq!(
            resets.accept(&invalid, [], u16::MAX),
            ReceiveResetAction::Reply(ReconfigResult::Denied)
        );
        assert_eq!(
            resets.accept(&invalid, [], u16::MAX),
            ReceiveResetAction::Reply(ReconfigResult::Denied)
        );
        assert_eq!(resets.next_expected_rsn(), 12);
        assert_eq!(
            resets.accept(&request(12, 9, &[1, 1, 2]), [], 4),
            ReceiveResetAction::New
        );
        assert_eq!(
            &resets
                .get(12)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([1, 2])
        );
    }

    #[test]
    fn duplicate_with_changed_payload_never_reexecutes() {
        let mut resets = IncomingResetQueue::new(10);
        let original = request(10, 100, &[1, 2]);
        assert_eq!(resets.accept(&original, [], 4), ReceiveResetAction::New);
        let mut changed = original.clone();
        changed.sender_last_tsn += 1;
        assert_eq!(
            resets.accept(&changed, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
        assert_eq!(resets.get(10).unwrap().original(), &original);
        resets
            .complete(10, ReconfigResult::SuccessPerformed)
            .unwrap();
        changed = original.clone();
        changed.stream_identifiers = vec![3];
        assert_eq!(
            resets.accept(&changed, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
        changed = original.clone();
        changed.reconfig_response_sequence_number += 1;
        assert_eq!(
            resets.accept(&changed, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
        assert_eq!(
            resets.accept(&original, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::SuccessPerformed)
        );
        assert!(resets.is_empty());
    }

    #[test]
    fn history_eviction_never_cancels_an_accepted_multistream_request() {
        let mut resets = IncomingResetQueue::new(10);
        let original = request(10, 100, &[1, 2]);
        assert_eq!(resets.accept(&original, [], 4), ReceiveResetAction::New);
        for sequence in 11..=13 {
            assert_eq!(
                resets.accept(&request(sequence, 100, &[1]), [], 4),
                ReceiveResetAction::New
            );
            resets
                .complete(sequence, ReconfigResult::SuccessPerformed)
                .unwrap();
        }
        // Inventory-level check: completion callbacks for newer operations may
        // evict history but must not mutate any still accepted operation.
        assert_eq!(resets.accept(&original, [], 4), ReceiveResetAction::Pending);
        assert_eq!(resets.get(10).unwrap().original(), &original);
        assert_eq!(
            &resets
                .get(10)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([1, 2])
        );
        assert_eq!(resets.ready(100), [10]);
        resets
            .complete(10, ReconfigResult::SuccessPerformed)
            .unwrap();
        // An old completion must not displace the last two RSNs' results.
        assert_eq!(
            resets.accept(&request(12, 100, &[1]), [], 4),
            ReceiveResetAction::Reply(ReconfigResult::SuccessPerformed)
        );
        assert_eq!(
            resets.accept(&request(13, 100, &[1]), [], 4),
            ReceiveResetAction::Reply(ReconfigResult::SuccessPerformed)
        );
        assert_eq!(
            resets.accept(&original, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
    }

    #[test]
    fn history_keeps_last_two_results_across_rsn_wrap() {
        let mut resets = IncomingResetQueue::new(u32::MAX - 1);
        for sequence in [u32::MAX - 1, u32::MAX, 0] {
            let request = request(sequence, 9, &[1]);
            assert_eq!(resets.accept(&request, [], 4), ReceiveResetAction::New);
            resets
                .complete(sequence, ReconfigResult::SuccessPerformed)
                .unwrap();
        }
        assert_eq!(
            resets.accept(&request(u32::MAX - 1, 9, &[1]), [], 4),
            ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
        );
        for sequence in [u32::MAX, 0] {
            assert_eq!(
                resets.accept(&request(sequence, 9, &[1]), [], 4),
                ReceiveResetAction::Reply(ReconfigResult::SuccessPerformed)
            );
        }
    }

    #[test]
    fn in_progress_and_boundary_lookup_retain_the_procedure() {
        let mut resets = IncomingResetQueue::new(10);
        resets.accept(&request(10, 100, &[1]), [], 4);
        resets.accept(&request(11, 110, &[1, 2]), [], 4);
        assert_eq!(resets.boundary(1), Some(100));
        assert_eq!(resets.boundary(2), Some(110));
        assert_eq!(resets.boundary(3), None);
        assert!(resets.complete(10, ReconfigResult::InProgress).is_none());
        assert_eq!(resets.ready(105), [10]);
        resets
            .complete(10, ReconfigResult::SuccessPerformed)
            .unwrap();
        assert_eq!(resets.boundary(1), Some(110));
        assert_eq!(resets.ready(105), []);
        assert_eq!(resets.ready(110), [11]);
    }

    #[test]
    fn admission_count_limit_is_definitive_and_replayable() {
        let mut resets = IncomingResetQueue::new(0);
        for sequence in 0..MAX_PENDING_REQUESTS as u32 {
            assert_eq!(
                resets.accept(&request(sequence, 100, &[1]), [], 4),
                ReceiveResetAction::New
            );
        }
        let denied = request(MAX_PENDING_REQUESTS as u32, 100, &[1]);
        assert_eq!(
            resets.accept(&denied, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::Denied)
        );
        resets
            .complete(0, ReconfigResult::SuccessPerformed)
            .unwrap();
        assert_eq!(
            resets.accept(&denied, [], 4),
            ReceiveResetAction::Reply(ReconfigResult::Denied)
        );
        assert_eq!(
            resets.accept(&request(MAX_PENDING_REQUESTS as u32 + 1, 100, &[1]), [], 4),
            ReceiveResetAction::New
        );
    }

    #[test]
    fn all_stream_reservation_bounds_future_stream_discovery() {
        let mut resets = IncomingResetQueue::new(0);
        assert_eq!(
            resets.accept(&request(0, 100, &[]), [], u16::MAX),
            ReceiveResetAction::New
        );
        assert_eq!(resets.reserved_stream_ids, usize::from(u16::MAX));
        assert_eq!(
            resets.accept(&request(1, 100, &[]), [], u16::MAX),
            ReceiveResetAction::Reply(ReconfigResult::Denied)
        );
        resets.observe_stream(u16::MAX - 1);
        assert_eq!(
            &resets
                .get(0)
                .unwrap()
                .streams()
                .copied()
                .collect::<BTreeSet<_>>(),
            &BTreeSet::from([u16::MAX - 1])
        );
        resets
            .complete(0, ReconfigResult::SuccessPerformed)
            .unwrap();
        assert_eq!(resets.reserved_stream_ids, 0);
        assert_eq!(
            resets.accept(&request(2, 100, &[]), [], u16::MAX),
            ReceiveResetAction::New
        );
    }
}
