//! FlexFEC draft-03 encoder and decoder, validating each other.
//!
//! Upstream has no test that runs its encoder against its decoder — the decoder is never
//! constructed outside its own unit tests, and the encoder's tests stop at "a packet came out".
//! So this is the evidence that the two halves agree, and the only place the format is exercised
//! end to end: encode a block, drop one packet, decode, and require the packet that comes back to
//! be byte-identical to the one that was lost.
//!
//! Byte-identical matters. A recovery that gets the payload right but the marker bit, timestamp or
//! payload type wrong produces a packet a decoder will accept and render incorrectly, which is
//! worse than losing it.

use rtc_interceptor::{FlexFec03Decoder, FlexFec03Encoder};
use shared::marshal::{Marshal, MarshalSize};

const MEDIA_SSRC: u32 = 476_325_762;
const REPAIR_SSRC: u32 = 867_589_674;
const REPAIR_PT: u8 = 49;

fn media_packet(sequence_number: u16, payload: &[u8]) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: true,
            payload_type: 96,
            sequence_number,
            timestamp: 3_653_407_706u32.wrapping_add(u32::from(sequence_number) * 3000),
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: payload.to_vec().into(),
    }
}

fn block(first: u16, count: u16) -> Vec<rtp::Packet> {
    (0..count)
        .map(|offset| {
            media_packet(
                first.wrapping_add(offset),
                &[1, 2, 3, 4, 5, offset as u8, 0xAB],
            )
        })
        .collect()
}

fn encode(media: &[rtp::Packet], num_fec_packets: u32) -> Vec<rtp::Packet> {
    FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC).encode(media, num_fec_packets)
}

fn bytes_of(packet: &rtp::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    packet.marshal_to(&mut buffer).expect("marshal");
    buffer
}

/// Every media packet in the block, dropped in turn, must be recoverable — mirroring upstream's
/// `checkAnyPacketCanBeRecovered`. One packet recovering is luck; all of them recovering is the
/// coverage being right.
fn assert_every_packet_is_recoverable(media: &[rtp::Packet], repair: &[rtp::Packet]) {
    for lost in 0..media.len() {
        let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);

        let mut recovered = Vec::new();
        for (index, packet) in media.iter().enumerate() {
            if index != lost {
                recovered.extend(decoder.decode(packet.clone()));
            }
        }
        assert!(
            recovered.is_empty(),
            "nothing is recovered before a repair packet arrives (lost {lost})"
        );

        for packet in repair {
            recovered.extend(decoder.decode(packet.clone()));
        }

        assert_eq!(
            1,
            recovered.len(),
            "exactly one packet recovered when packet {lost} was lost, got {} ",
            recovered.len()
        );
        assert_eq!(
            bytes_of(&media[lost]),
            bytes_of(&recovered[0]),
            "packet {lost} recovered byte-identically"
        );
    }
}

// ---------------------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------------------

#[test]
fn a_single_loss_is_recovered_byte_identically() {
    let media = block(100, 5);
    let repair = encode(&media, 2);
    assert_eq!(2, repair.len());

    assert_every_packet_is_recoverable(&media, &repair);
}

#[test]
fn one_repair_packet_covering_the_whole_block_recovers_any_single_loss() {
    let media = block(100, 6);
    let repair = encode(&media, 1);
    assert_eq!(1, repair.len());

    assert_every_packet_is_recoverable(&media, &repair);
}

/// Two repair packets recover two losses — provided the interleaving puts them under different
/// repair packets, which is the whole reason for interleaving.
#[test]
fn two_interleaved_repair_packets_recover_two_consecutive_losses() {
    let media = block(100, 6);
    let repair = encode(&media, 2);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();

    // Lose 101 and 102 — consecutive, so they fall under different repair packets.
    for packet in media
        .iter()
        .filter(|packet| !matches!(packet.header.sequence_number, 101 | 102))
    {
        recovered.extend(decoder.decode(packet.clone()));
    }
    for packet in &repair {
        recovered.extend(decoder.decode(packet.clone()));
    }

    let mut recovered_sequence_numbers: Vec<u16> = recovered
        .iter()
        .map(|packet| packet.header.sequence_number)
        .collect();
    recovered_sequence_numbers.sort_unstable();
    assert_eq!(vec![101, 102], recovered_sequence_numbers);

    for packet in &recovered {
        let original = media
            .iter()
            .find(|m| m.header.sequence_number == packet.header.sequence_number)
            .expect("recovered a packet that was sent");
        assert_eq!(bytes_of(original), bytes_of(packet));
    }
}

/// Two losses under the *same* repair packet cannot both be recovered — that is the limit of the
/// scheme, not a defect, and it is worth pinning so nobody expects otherwise.
#[test]
fn two_losses_under_one_repair_packet_recover_neither() {
    let media = block(100, 6);
    let repair = encode(&media, 2);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();

    // 100 and 102 are both covered by the first repair packet.
    for packet in media
        .iter()
        .filter(|packet| !matches!(packet.header.sequence_number, 100 | 102))
    {
        recovered.extend(decoder.decode(packet.clone()));
    }
    for packet in &repair {
        recovered.extend(decoder.decode(packet.clone()));
    }

    assert!(
        recovered.is_empty(),
        "one repair packet cannot resolve two unknowns, got {:?}",
        recovered
            .iter()
            .map(|p| p.header.sequence_number)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------------------
// Block shapes
// ---------------------------------------------------------------------------------------

/// A block that needs the second packet mask, so the header grows and the payload moves.
#[test]
fn a_block_using_the_second_packet_mask_round_trips() {
    let media = block(100, 20);
    let repair = encode(&media, 1);

    assert_every_packet_is_recoverable(&media, &repair);
}

/// A block that needs the third packet mask — the draft-03 63-bit one, where a width mistake
/// would silently shift every covered sequence number.
#[test]
fn a_block_using_the_third_packet_mask_round_trips() {
    let media = block(100, 60);
    let repair = encode(&media, 1);

    assert_every_packet_is_recoverable(&media, &repair);
}

#[test]
fn a_block_that_wraps_the_sequence_space_round_trips() {
    let media = block(65_530, 10);
    let repair = encode(&media, 2);

    assert_every_packet_is_recoverable(&media, &repair);
}

/// Payloads of different lengths: the repair payload is sized to the largest, and recovery has to
/// restore each packet's own length rather than the padded one.
#[test]
fn packets_of_different_lengths_are_recovered_at_their_own_length() {
    let media = vec![
        media_packet(100, &[1]),
        media_packet(101, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        media_packet(102, &[7, 7, 7]),
    ];
    let repair = encode(&media, 1);

    assert_every_packet_is_recoverable(&media, &repair);
}

#[test]
fn a_two_packet_block_round_trips() {
    let media = block(100, 2);
    let repair = encode(&media, 1);

    assert_every_packet_is_recoverable(&media, &repair);
}

// ---------------------------------------------------------------------------------------
// What the decoder must not do
// ---------------------------------------------------------------------------------------

#[test]
fn nothing_is_recovered_when_no_packet_was_lost() {
    let media = block(100, 5);
    let repair = encode(&media, 2);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();
    for packet in media.iter().chain(repair.iter()) {
        recovered.extend(decoder.decode(packet.clone()));
    }

    assert!(recovered.is_empty(), "there was nothing to recover");
}

/// A repair packet protecting a different media stream must be ignored: XORing it against this
/// stream's packets would produce convincing rubbish.
#[test]
fn a_repair_packet_for_another_stream_is_ignored() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, 9_999_999);
    let mut recovered = Vec::new();
    for packet in media.iter().skip(1).chain(repair.iter()) {
        recovered.extend(decoder.decode(packet.clone()));
    }

    assert!(recovered.is_empty());
    assert_eq!(0, decoder.pending_repair_packets(), "and it is not held");
}

/// Packets from an unrelated SSRC are neither recovered from nor counted.
#[test]
fn packets_from_an_unrelated_stream_are_ignored() {
    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);

    let mut stray = media_packet(1, &[1, 2, 3]);
    stray.header.ssrc = 12_345;
    assert!(decoder.decode(stray).is_empty());
    assert_eq!(0, decoder.recovered_len());
}

#[test]
fn a_duplicate_media_packet_is_not_counted_twice() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();
    // 101 is lost; 100 arrives twice.
    for packet in [&media[0], &media[0], &media[2], &media[3]] {
        recovered.extend(decoder.decode(packet.clone()));
    }
    assert_eq!(3, decoder.recovered_len(), "the duplicate was not stored");

    for packet in &repair {
        recovered.extend(decoder.decode(packet.clone()));
    }
    assert_eq!(1, recovered.len());
    assert_eq!(bytes_of(&media[1]), bytes_of(&recovered[0]));
}

#[test]
fn a_duplicate_repair_packet_is_not_held_twice() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    decoder.decode(repair[0].clone());
    decoder.decode(repair[0].clone());

    assert_eq!(1, decoder.pending_repair_packets());
}

/// A truncated repair packet must be discarded rather than parsed out of whatever follows it.
#[test]
fn a_truncated_repair_packet_is_discarded() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut truncated = repair[0].clone();
    truncated.payload = repair[0].payload.slice(..10);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    assert!(decoder.decode(truncated).is_empty());
    assert_eq!(0, decoder.pending_repair_packets());
}

/// A repair packet whose payload is shorter than the length it claims to recover cannot rebuild
/// the packet. Zero padding the tail would produce something that parses, passes downstream and
/// renders as corruption — worse than the loss it was meant to repair.
#[test]
fn a_repair_packet_with_a_truncated_payload_recovers_nothing() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    // Keep the header intact and cut the repair payload short.
    let mut truncated = repair[0].clone();
    truncated.payload = repair[0].payload.slice(..repair[0].payload.len() - 3);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();
    for packet in [&media[0], &media[1], &media[3]] {
        recovered.extend(decoder.decode(packet.clone()));
    }
    recovered.extend(decoder.decode(truncated));

    assert!(
        recovered.is_empty(),
        "a corrupted recovery is worse than no recovery"
    );
}

/// A repair packet that has produced its recovery can never produce another, so holding it costs
/// capacity against the retention limit and is rescanned on every later pass.
#[test]
fn a_spent_repair_packet_is_released() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    decoder.decode(repair[0].clone());
    assert_eq!(1, decoder.pending_repair_packets(), "held while it waits");

    // 101 is missing; supplying the rest completes it.
    for packet in [&media[0], &media[2], &media[3]] {
        decoder.decode(packet.clone());
    }

    assert_eq!(
        0,
        decoder.pending_repair_packets(),
        "released once it has done its work"
    );
}

/// The repair packet can arrive before the media it protects — reordering is ordinary, and a
/// decoder that only matched backwards would recover nothing.
#[test]
fn a_repair_packet_arriving_first_still_recovers() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut decoder = FlexFec03Decoder::new(REPAIR_SSRC, MEDIA_SSRC);
    let mut recovered = Vec::new();

    recovered.extend(decoder.decode(repair[0].clone()));
    assert!(recovered.is_empty(), "nothing to work with yet");

    // 102 is lost.
    for packet in [&media[0], &media[1], &media[3]] {
        recovered.extend(decoder.decode(packet.clone()));
    }

    assert_eq!(1, recovered.len());
    assert_eq!(bytes_of(&media[2]), bytes_of(&recovered[0]));
}
