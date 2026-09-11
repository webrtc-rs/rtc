//! One outgoing reset procedure owns its immutable wire request and result.
//! Receipt (RFC 6525 E1) does not commit a new SSN space (H4).

use super::*;

#[derive(Debug, Copy, Clone)]
pub(super) enum RequestPhase {
    Active,
    ReceiptOnly {
        retry_at: Instant,
        in_progress: bool,
    },
}

#[derive(Debug)]
pub(super) struct OutgoingReset {
    pub(super) request: ParamOutgoingResetRequest,
    pub(super) phase: RequestPhase,
    streams: Vec<ResetMarker>,
}

impl OutgoingReset {
    fn to_chunk(&self) -> ChunkReconfig {
        ChunkReconfig {
            param_a: Some(Box::new(self.request.clone())),
            ..Default::default()
        }
    }
}

impl Association {
    pub(super) fn acknowledge_reconfig(&mut self, sequence: u32, now: Instant) {
        let Some(reset) = &mut self.outgoing_reset else {
            return;
        };
        if reset.request.reconfig_request_sequence_number != sequence
            || !matches!(reset.phase, RequestPhase::Active)
            || self.timers.get(Timer::Reconfig).is_none()
        {
            return;
        }
        reset.phase = RequestPhase::ReceiptOnly {
            retry_at: now + Duration::from_millis(self.rto_mgr.get_rto()),
            in_progress: self.timers.is_reconfig_in_progress(),
        };
        self.timers.stop(Timer::Reconfig);
        self.will_retransmit_reconfig = false;
    }

    pub(super) fn handle_reset_response(&mut self, now: Instant, response: &ParamReconfigResponse) {
        let Some(reset) = &self.outgoing_reset else {
            return;
        };
        // H1: an old result cannot affect a newer request, or commit a request
        // whose timer E1 already stopped. A query reactivates this same RSN.
        if reset.request.reconfig_request_sequence_number
            != response.reconfig_response_sequence_number
            || !matches!(reset.phase, RequestPhase::Active)
            || self.timers.get(Timer::Reconfig).is_none()
        {
            return;
        }
        self.timers.stop(Timer::Reconfig);
        self.will_retransmit_reconfig = false;
        if response.result == ReconfigResult::InProgress {
            self.timers
                .restart_reconfig_in_progress(now, self.rto_mgr.get_rto());
            return;
        }
        if matches!(
            response.result,
            ReconfigResult::ErrorBadSequenceNumber | ReconfigResult::Unknown
        ) {
            // An unknown old result proves neither success nor refusal. The
            // stronger serialization prevents history eviction by our N+1/N+2;
            // if the peer cannot resolve N, terminate instead of guessing SSNs.
            let abort = self.create_packet(vec![Box::new(ChunkAbort::default())]);
            let _ = self.close(AssociationError::TransportError);
            self.control_queue.push_back(abort);
            return;
        }
        let reset = self.outgoing_reset.take().unwrap();
        let performed = matches!(
            response.result,
            ReconfigResult::SuccessPerformed | ReconfigResult::SuccessNop
        );
        let OutgoingReset {
            request, streams, ..
        } = reset;
        let mut refused_reciprocal = false;
        for stream in streams {
            let si = stream.stream_identifier;
            if performed {
                // The sole commit point for the TX direction's SSN space.
                self.transmit_streams.entry(si).or_default().reset();
                self.fwd_tsn_stream_map.remove(&si);
                if sna32gt(request.sender_last_tsn, self.cumulative_tsn_ack_point) {
                    self.confirmed_reset_tsns
                        .insert(si, request.sender_last_tsn);
                }
                if let Some(received) = self.receive_streams.get_mut(&si) {
                    received.complete_outgoing_reset(stream.receive_epoch);
                }
            }
            self.pending_queue.complete_reset(si);
            if !performed
                && !self.pending_queue.is_resetting(si)
                && let Some(received) = self.receive_streams.get_mut(&si)
            {
                refused_reciprocal |= received.refuse_outgoing_reset();
            }
        }
        if refused_reciprocal {
            // H3 leaves TX SSNs unchanged. When RX already closed, this API
            // cannot finish the data-channel close after the last TX refusal.
            // Fail the association explicitly instead of silently allowing reuse.
            let abort = self.create_packet(vec![Box::new(ChunkAbort::default())]);
            let _ = self.close(AssociationError::TransportError);
            self.control_queue.push_back(abort);
            return;
        }
        if performed && sna32gt(request.sender_last_tsn, self.cumulative_tsn_ack_point) {
            // Completion is serialized; these TSN boundaries are nondecreasing.
            self.reset_tsn_ack_queue
                .push_back((request.sender_last_tsn, request.stream_identifiers));
        }
        if self.use_forward_tsn {
            self.advance_peer_ack_point();
        }
    }

    pub(super) fn can_start_reconfig(&self) -> bool {
        // A stronger local serialization than E1 requires keeps N in even a
        // one-result peer cache until an explicit outcome establishes TX SSNs.
        self.outgoing_reset.is_none()
    }

    pub(super) fn next_reconfig_result_retry(&self) -> Option<(u32, Instant)> {
        if self.state() != AssociationState::Established {
            return None;
        }
        let reset = self.outgoing_reset.as_ref()?;
        match reset.phase {
            RequestPhase::ReceiptOnly { retry_at, .. } => {
                Some((reset.request.reconfig_request_sequence_number, retry_at))
            }
            RequestPhase::Active => None,
        }
    }

    pub(super) fn resume_reset_query(&mut self, now: Instant) {
        let Some(reset) = &mut self.outgoing_reset else {
            return;
        };
        if let RequestPhase::ReceiptOnly {
            retry_at,
            in_progress,
        } = reset.phase
            && retry_at <= now
        {
            reset.phase = RequestPhase::Active;
            if in_progress {
                self.timers
                    .restart_reconfig_in_progress(now, self.rto_mgr.get_rto());
            } else {
                self.timers
                    .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
            }
            self.will_retransmit_reconfig = true;
        }
    }

    pub(super) fn emit_reconfig(&mut self, now: Instant, packets: &mut Vec<Bytes>) {
        if !std::mem::take(&mut self.will_retransmit_reconfig) {
            return;
        }
        if let Some(reset) = &self.outgoing_reset
            && matches!(reset.phase, RequestPhase::Active)
        {
            if let Ok(raw) = self.marshal_control_chunk(&reset.to_chunk()) {
                packets.push(raw);
            }
            self.timers
                .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
        }
    }

    pub(super) fn start_reconfig(
        &mut self,
        now: Instant,
        streams: Vec<ResetMarker>,
        packets: &mut Vec<Bytes>,
    ) {
        debug_assert!(self.can_start_reconfig());
        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: self.generate_next_rsn(),
            // A4 always acknowledges the most recently accepted request, even
            // when several queued reciprocal resets are bundled together.
            reconfig_response_sequence_number: self.incoming_resets.last_received_rsn(),
            sender_last_tsn: self.my_next_tsn.wrapping_sub(1),
            stream_identifiers: streams
                .iter()
                .map(|stream| stream.stream_identifier)
                .collect(),
        };
        self.outgoing_reset = Some(OutgoingReset {
            request,
            phase: RequestPhase::Active,
            streams,
        });
        self.will_retransmit_reconfig = true;
        self.emit_reconfig(now, packets);
    }
}
