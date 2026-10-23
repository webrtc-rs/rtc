//! Turning the two feedback formats into a common [`Acknowledgement`].
//!
//! TWCC and RFC 8888 answer the same question — which packets arrived, and when — in different
//! shapes. Converting both to one type is what lets congestion control read either without
//! knowing which is negotiated.

use super::acknowledgement::Acknowledgement;
use rtcp::transport_feedbacks::cc_feedback_report::{CcFeedbackReport, Ecn};
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, SymbolTypeTcc, TransportLayerCc,
};
use std::collections::HashMap;
use std::time::Duration;

/// TWCC's reference time counts in multiples of 64 ms.
const TWCC_REFERENCE_TICK: Duration = Duration::from_millis(64);

/// TWCC receive deltas are in microseconds.
const TWCC_DELTA_UNIT: Duration = Duration::from_micros(1);

/// RFC 8888 arrival offsets are in units of 1/1024 s.
const CCFB_OFFSET_DENOMINATOR: u32 = 1024;

/// The RFC 8888 offset meaning "arrived after the report timestamp", which carries no usable
/// arrival time.
const CCFB_OFFSET_AFTER_REPORT: u16 = 0x1FFF;

/// Convert a TWCC feedback packet into one acknowledgement per reported packet.
///
/// Arrival times are relative to the feedback's own 24-bit reference time, so they are comparable
/// across successive TWCC reports but not with any other clock.
pub fn convert_twcc(feedback: &TransportLayerCc) -> Vec<Acknowledgement> {
    let mut acknowledgements = Vec::new();

    // The reference time is a count of 64 ms ticks on the receiver's clock; deltas accumulate
    // from there, so each arrival depends on every arrival before it in the same report.
    let mut arrival = TWCC_REFERENCE_TICK * feedback.reference_time;
    let mut delta_index = 0usize;
    let mut offset = 0u16;
    // The report declares how many packets it describes; the chunks can overshoot it (a run
    // length or a status vector carries whole symbols), so conversion stops at the declared
    // count and a run is clamped to what remains. pion does the same.
    let mut processed = 0u16;

    let push = |symbol: SymbolTypeTcc,
                offset: &mut u16,
                arrival: &mut Duration,
                delta_index: &mut usize,
                acknowledgements: &mut Vec<Acknowledgement>| {
        let sequence_number = feedback.base_sequence_number.wrapping_add(*offset);
        *offset = offset.wrapping_add(1);

        match symbol {
            SymbolTypeTcc::PacketNotReceived => {
                acknowledgements.push(Acknowledgement::lost(sequence_number));
            }
            SymbolTypeTcc::PacketReceivedSmallDelta | SymbolTypeTcc::PacketReceivedLargeDelta => {
                // A delta may be negative — packets can be reported out of order — so the running
                // arrival is adjusted in whichever direction the report says.
                if let Some(delta) = feedback.recv_deltas.get(*delta_index) {
                    *delta_index += 1;
                    let magnitude = TWCC_DELTA_UNIT * delta.delta.unsigned_abs() as u32;
                    *arrival = if delta.delta < 0 {
                        arrival.saturating_sub(magnitude)
                    } else {
                        *arrival + magnitude
                    };
                    acknowledgements.push(Acknowledgement::received(
                        sequence_number,
                        Some(*arrival),
                        Ecn::NotEct,
                    ));
                }
                // A received symbol with no delta left is silently skipped, as in pion: the
                // report is malformed and inventing an arrival time for it would poison the
                // delay estimate.
            }
            SymbolTypeTcc::PacketReceivedWithoutDelta => {
                acknowledgements.push(Acknowledgement::received(
                    sequence_number,
                    None,
                    Ecn::NotEct,
                ));
            }
        }
    };

    'chunks: for chunk in &feedback.packet_chunks {
        if processed >= feedback.packet_status_count {
            break;
        }
        match chunk {
            PacketStatusChunk::RunLengthChunk(run) => {
                // A run may claim more packets than the report still has room to describe.
                let remaining = feedback.packet_status_count - processed;
                let run_length = run.run_length.min(remaining);
                for _ in 0..run_length {
                    push(
                        run.packet_status_symbol,
                        &mut offset,
                        &mut arrival,
                        &mut delta_index,
                        &mut acknowledgements,
                    );
                    processed += 1;
                }
            }
            PacketStatusChunk::StatusVectorChunk(vector) => {
                for &symbol in &vector.symbol_list {
                    if processed >= feedback.packet_status_count {
                        break 'chunks;
                    }
                    processed += 1;
                    push(
                        symbol,
                        &mut offset,
                        &mut arrival,
                        &mut delta_index,
                        &mut acknowledgements,
                    );
                }
            }
        }
    }

    acknowledgements
}

/// Convert an RFC 8888 report into acknowledgements per media stream, with the delay the receiver
/// added before sending it.
///
/// The returned delay is the gap between the newest arrival the report describes and the instant
/// it was stamped. A round trip measured without subtracting it counts the receiver's own
/// reporting interval as network time.
pub fn convert_ccfb(feedback: &CcFeedbackReport) -> (Duration, HashMap<u32, Vec<Acknowledgement>>) {
    let mut per_stream: HashMap<u32, Vec<Acknowledgement>> = HashMap::new();
    // Arrivals are offsets *back* from the report timestamp, so the newest arrival is the
    // smallest offset.
    let mut newest_arrival: Option<Duration> = None;

    for block in &feedback.report_blocks {
        let mut acknowledgements = Vec::with_capacity(block.metric_blocks.len());

        for (index, metric) in block.metric_blocks.iter().enumerate() {
            let sequence_number = block.begin_sequence.wrapping_add(index as u16);

            if !metric.received {
                acknowledgements.push(Acknowledgement::lost(sequence_number));
                continue;
            }

            // The reserved offset says the packet arrived after the report was stamped, which
            // leaves no usable time.
            let arrival = if metric.arrival_time_offset == CCFB_OFFSET_AFTER_REPORT {
                None
            } else {
                let offset = Duration::from_secs_f64(
                    f64::from(metric.arrival_time_offset) / f64::from(CCFB_OFFSET_DENOMINATOR),
                );
                newest_arrival = Some(match newest_arrival {
                    Some(newest) => newest.min(offset),
                    None => offset,
                });
                Some(offset)
            };

            acknowledgements.push(Acknowledgement::received(
                sequence_number,
                arrival,
                metric.ecn,
            ));
        }

        // A report may carry more than one block for the same stream — a long window is split
        // across blocks — and pion merges them; overwriting would drop every block but the
        // last and lose the packets the dropped blocks described.
        per_stream
            .entry(block.media_ssrc)
            .or_default()
            .extend(acknowledgements);
    }

    (newest_arrival.unwrap_or_default(), per_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::{
        CcFeedbackMetricBlock, CcFeedbackReportBlock,
    };
    use rtcp::transport_feedbacks::transport_layer_cc::{
        RecvDelta, RunLengthChunk, StatusVectorChunk,
    };

    fn run_length(symbol: SymbolTypeTcc, run_length: u16) -> PacketStatusChunk {
        PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            packet_status_symbol: symbol,
            run_length,
            ..Default::default()
        })
    }

    fn status_vector(symbols: Vec<SymbolTypeTcc>) -> PacketStatusChunk {
        PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
            symbol_list: symbols,
            ..Default::default()
        })
    }

    fn delta(microseconds: i64) -> RecvDelta {
        RecvDelta {
            delta: microseconds,
            ..Default::default()
        }
    }

    // ---------------------------------------------------------------------------------------
    // TWCC
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_run_of_lost_packets_converts_to_losses() {
        let feedback = TransportLayerCc {
            base_sequence_number: 100,
            packet_status_count: 3,
            reference_time: 0,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketNotReceived, 3)],
            recv_deltas: vec![],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            vec![
                Acknowledgement::lost(100),
                Acknowledgement::lost(101),
                Acknowledgement::lost(102)
            ],
            acknowledgements
        );
    }

    /// Deltas accumulate: each arrival is relative to the one before it, so a report describes a
    /// *sequence* of arrivals rather than independent timestamps.
    #[test]
    fn deltas_accumulate_from_the_reference_time() {
        let feedback = TransportLayerCc {
            base_sequence_number: 10,
            packet_status_count: 3,
            // One tick of 64 ms.
            reference_time: 1,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 3)],
            recv_deltas: vec![delta(1000), delta(2000), delta(500)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        let arrivals: Vec<Duration> = acknowledgements
            .iter()
            .map(|ack| ack.arrival.expect("arrived with a time"))
            .collect();

        assert_eq!(
            vec![
                Duration::from_millis(64) + Duration::from_micros(1000),
                Duration::from_millis(64) + Duration::from_micros(3000),
                Duration::from_millis(64) + Duration::from_micros(3500),
            ],
            arrivals
        );
        assert!(acknowledgements.iter().all(|ack| ack.arrived));
    }

    /// Packets can be reported arriving out of order, which is a negative delta. Treating it as
    /// positive would report the path as *less* delayed than it is.
    #[test]
    fn a_negative_delta_moves_the_arrival_backwards() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            packet_status_count: 2,
            reference_time: 1,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 2)],
            recv_deltas: vec![delta(5000), delta(-2000)],
            ..Default::default()
        };

        let arrivals: Vec<Duration> = convert_twcc(&feedback)
            .iter()
            .map(|ack| ack.arrival.expect("arrived"))
            .collect();

        assert_eq!(
            Duration::from_millis(64) + Duration::from_micros(5000),
            arrivals[0]
        );
        assert_eq!(
            Duration::from_millis(64) + Duration::from_micros(3000),
            arrivals[1],
            "the second packet arrived before the first"
        );
    }

    #[test]
    fn a_status_vector_converts_symbol_by_symbol() {
        let feedback = TransportLayerCc {
            base_sequence_number: 500,
            packet_status_count: 3,
            reference_time: 0,
            packet_chunks: vec![status_vector(vec![
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketReceivedLargeDelta,
            ])],
            recv_deltas: vec![delta(100), delta(200)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            vec![true, false, true],
            acknowledgements
                .iter()
                .map(|ack| ack.arrived)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![500, 501, 502],
            acknowledgements
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }

    /// "Received without delta" means the receiver got it but cannot say when. Reporting an
    /// invented time would feed congestion control a measurement nobody made.
    #[test]
    fn a_packet_received_without_a_delta_has_no_arrival_time() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            packet_status_count: 1,
            reference_time: 0,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedWithoutDelta, 1)],
            recv_deltas: vec![],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert!(acknowledgements[0].arrived);
        assert_eq!(None, acknowledgements[0].arrival);
    }

    /// A report claiming more received packets than it carries deltas for is malformed. As in
    /// pion, the symbols without a delta are dropped rather than reported with an invented
    /// time: a made-up arrival would poison the delay estimate.
    #[test]
    fn more_received_packets_than_deltas_does_not_panic() {
        let feedback = TransportLayerCc {
            base_sequence_number: 0,
            packet_status_count: 4,
            reference_time: 0,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 4)],
            recv_deltas: vec![delta(100)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            1,
            acknowledgements.len(),
            "only the packet the one real delta describes"
        );
        assert!(acknowledgements[0].arrival.is_some());
    }

    /// pion `TestConvertTWCC`: the report declares how many packets it describes, and a run
    /// length or status vector that overshoots that count is cut short — the extra symbols
    /// describe packets the sender never asked about.
    #[test]
    fn conversion_stops_at_the_declared_packet_status_count() {
        let feedback = TransportLayerCc {
            base_sequence_number: 200,
            packet_status_count: 4,
            reference_time: 3,
            packet_chunks: vec![
                run_length(SymbolTypeTcc::PacketNotReceived, 1),
                run_length(SymbolTypeTcc::PacketReceivedWithoutDelta, 1),
                run_length(SymbolTypeTcc::PacketReceivedSmallDelta, 5),
                status_vector(vec![SymbolTypeTcc::PacketNotReceived]),
            ],
            recv_deltas: vec![],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            vec![
                Acknowledgement::lost(200),
                Acknowledgement::received(201, None, Ecn::NotEct),
            ],
            acknowledgements,
            "the small-delta run is clamped to two symbols and its deltas are missing, so both are dropped"
        );
    }

    /// pion `TestConvertTWCC`: a count that runs out mid-status-vector stops there, and a
    /// received symbol whose delta is missing is dropped.
    #[test]
    fn a_status_vector_is_cut_short_at_the_declared_count() {
        let feedback = TransportLayerCc {
            base_sequence_number: 300,
            packet_status_count: 3,
            reference_time: 3,
            packet_chunks: vec![status_vector(vec![
                SymbolTypeTcc::PacketReceivedWithoutDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
            ])],
            recv_deltas: vec![delta(1000)],
            ..Default::default()
        };

        let acknowledgements = convert_twcc(&feedback);
        assert_eq!(
            2,
            acknowledgements.len(),
            "the count ends after three symbols"
        );
        assert!(acknowledgements[0].arrived);
        assert_eq!(None, acknowledgements[0].arrival);
        assert_eq!(
            Some(Duration::from_millis(3 * 64) + Duration::from_micros(1000)),
            acknowledgements[1].arrival
        );
    }

    /// pion `TestConvertTWCC`: a count larger than what the chunks describe is simply the end
    /// of the road — everything the chunks say is converted, nothing is invented.
    #[test]
    fn a_count_larger_than_the_chunks_converts_all_of_them() {
        let feedback = TransportLayerCc {
            base_sequence_number: 400,
            packet_status_count: 100,
            reference_time: 0,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketNotReceived, 2)],
            recv_deltas: vec![],
            ..Default::default()
        };

        assert_eq!(
            vec![Acknowledgement::lost(400), Acknowledgement::lost(401)],
            convert_twcc(&feedback)
        );
    }

    #[test]
    fn sequence_numbers_wrap_across_a_report() {
        let feedback = TransportLayerCc {
            base_sequence_number: 65534,
            packet_status_count: 4,
            reference_time: 0,
            packet_chunks: vec![run_length(SymbolTypeTcc::PacketNotReceived, 4)],
            recv_deltas: vec![],
            ..Default::default()
        };

        assert_eq!(
            vec![65534, 65535, 0, 1],
            convert_twcc(&feedback)
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_empty_feedback_converts_to_nothing() {
        let feedback = TransportLayerCc::default();
        assert!(convert_twcc(&feedback).is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // RFC 8888
    // ---------------------------------------------------------------------------------------

    fn metric(received: bool, offset: u16, ecn: Ecn) -> CcFeedbackMetricBlock {
        CcFeedbackMetricBlock {
            received,
            ecn,
            arrival_time_offset: offset,
        }
    }

    #[test]
    fn a_ccfb_report_converts_per_stream() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![
                CcFeedbackReportBlock {
                    media_ssrc: 10,
                    begin_sequence: 100,
                    metric_blocks: vec![
                        metric(true, 512, Ecn::NotEct),
                        metric(false, 0, Ecn::NotEct),
                    ],
                },
                CcFeedbackReportBlock {
                    media_ssrc: 20,
                    begin_sequence: 5,
                    metric_blocks: vec![metric(true, 256, Ecn::Ce)],
                },
            ],
            report_timestamp: 0,
        };

        let (_, per_stream) = convert_ccfb(&feedback);

        let first = &per_stream[&10];
        assert_eq!(100, first[0].sequence_number);
        assert_eq!(Some(Duration::from_millis(500)), first[0].arrival);
        assert!(!first[1].arrived);

        let second = &per_stream[&20];
        assert_eq!(5, second[0].sequence_number);
        assert_eq!(Ecn::Ce, second[0].ecn, "ECN survives conversion");
    }

    /// pion `TestConvertCCFB`: a long window is split across report blocks, and two blocks for
    /// the same media SSRC describe consecutive stretches of one stream — they must be merged,
    /// not overwritten.
    #[test]
    fn report_blocks_for_the_same_stream_are_merged() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![
                CcFeedbackReportBlock {
                    media_ssrc: 10,
                    begin_sequence: 100,
                    metric_blocks: vec![
                        metric(true, 512, Ecn::NotEct),
                        metric(false, 0, Ecn::NotEct),
                    ],
                },
                CcFeedbackReportBlock {
                    media_ssrc: 10,
                    begin_sequence: 102,
                    metric_blocks: vec![metric(true, 256, Ecn::NotEct)],
                },
            ],
            report_timestamp: 0,
        };

        let (_, per_stream) = convert_ccfb(&feedback);

        let merged = &per_stream[&10];
        assert_eq!(
            3,
            merged.len(),
            "both blocks' packets, not just the second block's"
        );
        assert_eq!(
            vec![100, 101, 102],
            merged
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
        assert!(
            !merged[1].arrived,
            "the loss the first block reported survives"
        );
        assert_eq!(
            Some(Duration::from_millis(250)),
            merged[2].arrival,
            "the newest arrival still drives the reporting delay"
        );
    }

    /// The receiver's own reporting delay is not network time. Without subtracting it, a round
    /// trip includes however long the receiver sat on the report before sending it.
    #[test]
    fn the_reporting_delay_is_the_gap_to_the_newest_arrival() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                // 1024 units = 1 s ago, 102 ≈ 100 ms ago. The newest is the smaller offset.
                metric_blocks: vec![
                    metric(true, 1024, Ecn::NotEct),
                    metric(true, 102, Ecn::NotEct),
                ],
            }],
            report_timestamp: 0,
        };

        let (delay, _) = convert_ccfb(&feedback);
        assert!(
            (Duration::from_millis(99)..=Duration::from_millis(101)).contains(&delay),
            "the newest arrival was ~100 ms before the report, got {delay:?}"
        );
    }

    /// The reserved offset means the packet arrived after the report was stamped, so there is no
    /// usable time — and it must not be taken as the newest arrival either.
    #[test]
    fn the_reserved_offset_yields_no_arrival_time() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                metric_blocks: vec![
                    metric(true, CCFB_OFFSET_AFTER_REPORT, Ecn::NotEct),
                    metric(true, 512, Ecn::NotEct),
                ],
            }],
            report_timestamp: 0,
        };

        let (delay, per_stream) = convert_ccfb(&feedback);
        assert!(per_stream[&10][0].arrived);
        assert_eq!(None, per_stream[&10][0].arrival);
        assert_eq!(
            Duration::from_millis(500),
            delay,
            "the reserved value did not become the newest arrival"
        );
    }

    #[test]
    fn a_report_with_no_arrivals_has_no_reporting_delay() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 0,
                metric_blocks: vec![metric(false, 0, Ecn::NotEct)],
            }],
            report_timestamp: 0,
        };

        let (delay, per_stream) = convert_ccfb(&feedback);
        assert_eq!(Duration::ZERO, delay);
        assert!(!per_stream[&10][0].arrived);
    }

    #[test]
    fn ccfb_sequence_numbers_wrap_within_a_block() {
        let feedback = CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: 10,
                begin_sequence: 65535,
                metric_blocks: vec![metric(false, 0, Ecn::NotEct), metric(false, 0, Ecn::NotEct)],
            }],
            report_timestamp: 0,
        };

        let (_, per_stream) = convert_ccfb(&feedback);
        assert_eq!(
            vec![65535, 0],
            per_stream[&10]
                .iter()
                .map(|ack| ack.sequence_number)
                .collect::<Vec<_>>()
        );
    }
}
