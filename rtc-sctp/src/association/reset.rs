//! Reset requests retain their wire identity until the result is known.
//! Receipt (RFC 6525 E1) does not commit a new SSN space (H4), and duplicate
//! queries must not reset a reused SID or repeat a partially completed request.

use super::*;

#[derive(Debug, Clone)]
pub(super) struct IncomingReset {
    pub(super) original: ParamOutgoingResetRequest,
    // Partial application must not change the identity of a retransmission.
    pub(super) remaining: Vec<StreamId>,
}

#[derive(Debug)]
pub(super) struct CompletedReset {
    original: ParamOutgoingResetRequest,
    result: ReconfigResult,
}

pub(super) enum ReceiveResetAction {
    Apply,
    Reply(ReconfigResult),
}

#[derive(Debug, Copy, Clone)]
enum RequestPhase {
    Active,
    ReceiptOnly {
        retry_at: Instant,
        in_progress: bool,
    },
}

#[derive(Debug)]
pub(super) struct OutgoingReset {
    pub(super) request: ParamOutgoingResetRequest,
    phase: RequestPhase,
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
    pub(super) fn accept_incoming_reset(
        &mut self,
        request: &ParamOutgoingResetRequest,
    ) -> ReceiveResetAction {
        let sequence = request.reconfig_request_sequence_number;
        if let Some(pending) = self.reconfig_requests.get(&sequence) {
            return if pending.original == *request {
                ReceiveResetAction::Apply
            } else {
                ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber)
            };
        }
        if let Some(completed) = self
            .completed_resets
            .iter()
            .find(|p| p.original.reconfig_request_sequence_number == sequence)
        {
            return ReceiveResetAction::Reply(if completed.original == *request {
                completed.result
            } else {
                ReconfigResult::ErrorBadSequenceNumber
            });
        }
        if sequence != self.peer_last_rsn.wrapping_add(1) {
            return ReceiveResetAction::Reply(ReconfigResult::ErrorBadSequenceNumber);
        }
        self.peer_last_rsn = sequence;
        self.reconfig_requests.insert(
            sequence,
            IncomingReset {
                original: request.clone(),
                remaining: request.stream_identifiers.clone(),
            },
        );
        ReceiveResetAction::Apply
    }

    pub(super) fn complete_incoming_reset(&mut self, sequence: u32) {
        let Some(reset) = self.reconfig_requests.remove(&sequence) else {
            return;
        };
        // Keep the last two RSNs, not the last two completion callbacks: an
        // older multi-SID request can finish draining after a newer request.
        let index = self
            .completed_resets
            .iter()
            .position(|p| sna32gt(p.original.reconfig_request_sequence_number, sequence))
            .unwrap_or(self.completed_resets.len());
        self.completed_resets.insert(
            index,
            CompletedReset {
                original: reset.original,
                result: ReconfigResult::SuccessPerformed,
            },
        );
        if self.completed_resets.len() > 2 {
            self.completed_resets.pop_front();
        }
    }

    pub(super) fn reconfig_response_packet(&self, sequence: u32, result: ReconfigResult) -> Packet {
        self.create_packet(vec![Box::new(ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: sequence,
                result,
            })),
            param_b: None,
        })])
    }

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

    pub(super) fn handle_reset_response(
        &mut self,
        now: Instant,
        response: &ParamReconfigResponse,
    ) -> Result<()> {
        let Some(reset) = &self.outgoing_reset else {
            return Ok(());
        };
        // H1: a stale result cannot change the current request or its timer.
        if reset.request.reconfig_request_sequence_number
            != response.reconfig_response_sequence_number
            || !matches!(reset.phase, RequestPhase::Active)
            || self.timers.get(Timer::Reconfig).is_none()
        {
            return Ok(());
        }
        if response.result == ReconfigResult::InProgress {
            self.will_retransmit_reconfig = false;
            self.timers.stop(Timer::Reconfig);
            self.timers
                .restart_reconfig_in_progress(now, self.rto_mgr.get_rto());
            return Ok(());
        }
        if matches!(
            response.result,
            ReconfigResult::ErrorBadSequenceNumber | ReconfigResult::Unknown
        ) {
            // The result establishes neither the old nor the new SSN space.
            // Keep serialization until a known outcome; never guess on reuse.
            let abort = self.create_packet(vec![Box::new(ChunkAbort::default())]);
            self.close(AssociationError::TransportError)?;
            self.control_queue.push_back(abort);
            return Ok(());
        }
        let performed = matches!(
            response.result,
            ReconfigResult::SuccessPerformed | ReconfigResult::SuccessNop
        );
        // Validate every affected direction before committing any of them.
        let mut updates = Vec::with_capacity(reset.request.stream_identifiers.len());
        for &si in &reset.request.stream_identifiers {
            self.pending_queue.validate_reset_completion(si)?;
            let mut tx = self.transmit_streams.get(&si).copied().unwrap_or_default();
            if performed {
                tx.reset()?;
            }
            updates.push((si, tx));
        }
        let Some(reset) = self.outgoing_reset.take() else {
            return Err(Error::OtherSctpErr("missing outgoing reset".into()));
        };
        self.timers.stop(Timer::Reconfig);
        self.will_retransmit_reconfig = false;
        let request = reset.request;
        for (si, tx) in updates {
            if performed {
                self.transmit_streams.insert(si, tx);
                self.fwd_tsn_stream_map.remove(&si);
                if sna32gt(request.sender_last_tsn, self.cumulative_tsn_ack_point) {
                    self.confirmed_reset_tsns
                        .insert(si, request.sender_last_tsn);
                }
            }
            self.pending_queue.complete_reset(si)?;
        }
        if performed && sna32gt(request.sender_last_tsn, self.cumulative_tsn_ack_point) {
            self.reset_tsn_ack_queue
                .push_back((request.sender_last_tsn, request.stream_identifiers));
        }
        if self.use_forward_tsn {
            self.advance_peer_ack_point();
        }
        self.awake_write_loop();
        Ok(())
    }

    pub(super) fn can_start_reconfig(&self) -> bool {
        // Stronger serialization than E1 requires keeps this request in even
        // a one-result peer cache until its outcome establishes the SSNs.
        self.outgoing_reset.is_none()
    }

    pub(super) fn next_reconfig_result_retry(&self) -> Option<Instant> {
        if !matches!(
            self.state(),
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownSent
                | AssociationState::ShutdownReceived
        ) {
            return None;
        }
        match self.outgoing_reset.as_ref()?.phase {
            RequestPhase::ReceiptOnly { retry_at, .. } => Some(retry_at),
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

    pub(super) fn emit_reconfig(&mut self, now: Instant, packets: &mut Vec<Bytes>) -> Result<()> {
        if !self.will_retransmit_reconfig {
            return Ok(());
        }
        if let Some(reset) = &self.outgoing_reset
            && matches!(reset.phase, RequestPhase::Active)
        {
            packets.push(self.marshal_control_chunk(&reset.to_chunk())?);
            self.timers
                .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
        }
        self.will_retransmit_reconfig = false;
        Ok(())
    }

    pub(super) fn start_reconfig(
        &mut self,
        now: Instant,
        streams: Vec<u16>,
        packets: &mut Vec<Bytes>,
    ) -> Result<()> {
        if !self.can_start_reconfig() {
            return Err(Error::OtherSctpErr("outgoing reset is still active".into()));
        }
        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: self.my_next_rsn,
            reconfig_response_sequence_number: self.peer_last_rsn,
            sender_last_tsn: self.my_next_tsn.wrapping_sub(1),
            stream_identifiers: streams,
        };
        let reset = OutgoingReset {
            request,
            phase: RequestPhase::Active,
        };
        let raw = self.marshal_control_chunk(&reset.to_chunk())?;
        self.generate_next_rsn();
        self.outgoing_reset = Some(reset);
        self.timers
            .start(Timer::Reconfig, now, self.rto_mgr.get_rto());
        packets.push(raw);
        Ok(())
    }
}
