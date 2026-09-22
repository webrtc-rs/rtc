use super::*;
use crate::handshake::HandshakeType;

#[test]
fn test_fragment_buffer() -> Result<()> {
    let tests = vec![
        (
            "Single Fragment",
            vec![vec![
                0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
            ]],
            vec![vec![
                0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff,
                0x00,
            ]],
            0,
        ),
        (
            "Single Fragment Epoch 3",
            vec![vec![
                0x16, 0xfe, 0xff, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
            ]],
            vec![vec![
                0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff,
                0x00,
            ]],
            3,
        ),
        (
            "Multiple Fragments",
            vec![
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                    0x01, 0x02, 0x03, 0x04,
                ],
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x05, 0x05,
                    0x06, 0x07, 0x08, 0x09,
                ],
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x05, 0x0A,
                    0x0B, 0x0C, 0x0D, 0x0E,
                ],
            ],
            vec![vec![
                0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            ]],
            0,
        ),
        (
            "Multiple Unordered Fragments",
            vec![
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                    0x01, 0x02, 0x03, 0x04,
                ],
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x05, 0x0A,
                    0x0B, 0x0C, 0x0D, 0x0E,
                ],
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81,
                    0x0b, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x05, 0x05,
                    0x06, 0x07, 0x08, 0x09,
                ],
            ],
            vec![vec![
                0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            ]],
            0,
        ),
        (
            "Multiple Handshakes in Signle Fragment",
            vec![vec![
                0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x30, /* record header */
                0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff,
                0x01, 0x01, /*handshake msg 1*/
                0x03, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff,
                0x01, 0x01, /*handshake msg 2*/
                0x03, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff,
                0x01, 0x01, /*handshake msg 3*/
            ]],
            vec![
                vec![
                    0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe,
                    0xff, 0x01, 0x01,
                ],
                vec![
                    0x03, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe,
                    0xff, 0x01, 0x01,
                ],
                vec![
                    0x03, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe,
                    0xff, 0x01, 0x01,
                ],
            ],
            0,
        ),
        // Ensure zero length fragments don't cause an infinite recursive loop which in turn causes
        // a stack overflow. An empty fragment carries nothing; the message completes once its
        // byte arrives.
        (
            "Zero length fragment",
            vec![
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                vec![
                    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                ],
            ],
            vec![vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            ]],
            0,
        ),
        (
            "Zero length message",
            vec![vec![
                0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0e,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]],
            vec![vec![
                0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]],
            0,
        ),
    ];

    for (name, inputs, expects, expected_epoch) in tests {
        let mut fragment_buffer = FragmentBuffer::new();
        for frag in inputs {
            let status = fragment_buffer.push(&frag)?;
            assert!(
                status,
                "fragment_buffer didn't accept fragments for '{name}'"
            );
        }

        for expected in expects {
            let (out, epoch) = fragment_buffer.pop()?;
            assert_eq!(
                out, expected,
                "fragment_buffer '{name}' push/pop: got {out:?}, want {expected:?}"
            );

            assert_eq!(
                epoch, expected_epoch,
                "fragment_buffer returned wrong epoch: got {epoch}, want {expected_epoch}"
            );
        }

        let result = fragment_buffer.pop();
        assert!(
            result.is_err(),
            "fragment_buffer popped single buffer multiple times for '{name}'"
        );
    }

    Ok(())
}

/// A handshake record at `epoch` carrying one fragment of message `message_sequence`.
fn fragment_record(
    epoch: u16,
    message_sequence: u16,
    length: u32,
    fragment_offset: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header = HandshakeHeader {
        handshake_type: HandshakeType::Certificate,
        length,
        message_sequence,
        fragment_offset,
        fragment_length: payload.len() as u32,
    };
    let mut body = vec![];
    header.marshal(&mut body).unwrap();
    body.extend_from_slice(payload);
    record(epoch, &body)
}

fn record(epoch: u16, body: &[u8]) -> Vec<u8> {
    let mut raw = vec![];
    RecordLayerHeader {
        content_type: ContentType::Handshake,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch,
        sequence_number: 0,
        content_len: body.len() as u16,
    }
    .marshal(&mut raw)
    .unwrap();
    raw.extend_from_slice(body);
    raw
}

/// The body of a popped message, checking its rebuilt header on the way.
fn popped_body(out: &[u8], length: usize) -> &[u8] {
    let header = HandshakeHeader::unmarshal(&mut &out[..]).unwrap();
    assert_eq!(header.length as usize, length);
    assert_eq!(header.fragment_offset, 0);
    assert_eq!(header.fragment_length as usize, length);
    &out[HANDSHAKE_HEADER_LENGTH..]
}

fn size_for(length: u32, fragment_length: u32) -> usize {
    PendingMessage::size_for(&HandshakeHeader {
        length,
        fragment_length,
        ..Default::default()
    })
}

#[test]
fn test_fragment_buffer_overflow() -> Result<()> {
    let mut fragment_buffer = FragmentBuffer::new();

    // Each message advertises the largest accepted length, and message sequence 0 never
    // arrives, so every buffered message stays until the byte budget runs out.
    let mut result = Ok(true);
    for message_sequence in 1..FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD {
        result = fragment_buffer.push(&fragment_record(
            0,
            message_sequence,
            FRAGMENT_BUFFER_MAX_MESSAGE_LENGTH as u32,
            0,
            &[1],
        ));
        if result.is_err() {
            break;
        }
    }
    assert!(
        matches!(result, Err(Error::ErrFragmentBufferOverflow { .. })),
        "buffering past the byte budget must fail, got {result:?}"
    );
    assert!(fragment_buffer.size() < FRAGMENT_BUFFER_MAX_SIZE);

    // A single message may not advertise more than the per-message limit.
    let mut fragment_buffer = FragmentBuffer::new();
    let result = fragment_buffer.push(&fragment_record(
        0,
        0,
        FRAGMENT_BUFFER_MAX_MESSAGE_LENGTH as u32 + 1,
        0,
        &[1],
    ));
    assert!(matches!(
        result,
        Err(Error::ErrFragmentBufferOverflow { .. })
    ));
    assert_eq!(fragment_buffer.size(), 0);

    Ok(())
}

#[test]
fn test_fragment_buffer_rejects_malformed_fragments() -> Result<()> {
    let malformed = [
        (
            "payload after an empty fragment",
            vec![
                0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ),
        (
            "fragment longer than the record",
            vec![
                0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x0b,
                0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02,
            ],
        ),
        (
            "fragment past the message end",
            fragment_record(0, 0, 4, 2, &[1, 2, 3]),
        ),
    ];
    for (name, raw) in malformed {
        let mut fragment_buffer = FragmentBuffer::new();
        assert!(fragment_buffer.push(&raw).is_err(), "{name}: accepted");
        assert_eq!(fragment_buffer.size(), 0, "{name}: buffered");
        assert!(fragment_buffer.pop().is_err(), "{name}: popped");
    }

    // A record whose second fragment is malformed buffers nothing, not even the first.
    let mut body = fragment_record(0, 0, 1, 0, &[7])[RECORD_LAYER_HEADER_SIZE..].to_vec();
    body.extend_from_slice(&fragment_record(0, 1, 1, 1, &[8])[RECORD_LAYER_HEADER_SIZE..]);
    let mut fragment_buffer = FragmentBuffer::new();
    assert!(fragment_buffer.push(&record(0, &body)).is_err());
    assert_eq!(fragment_buffer.size(), 0);
    assert!(fragment_buffer.pop().is_err());

    // A fragment that disagrees with the rest of its message is rejected.
    let mut fragment_buffer = FragmentBuffer::new();
    assert!(fragment_buffer.push(&fragment_record(0, 0, 4, 0, &[1, 2]))?);
    assert!(
        fragment_buffer
            .push(&fragment_record(0, 0, 5, 2, &[3, 4]))
            .is_err()
    );
    assert!(
        fragment_buffer
            .push(&fragment_record(1, 0, 4, 2, &[3, 4]))
            .is_err()
    );
    assert!(fragment_buffer.pop().is_err());
    assert!(fragment_buffer.push(&fragment_record(0, 0, 4, 2, &[3, 4]))?);
    let (out, _) = fragment_buffer.pop()?;
    assert_eq!(popped_body(&out, 4), &[1, 2, 3, 4]);

    Ok(())
}

#[test]
fn test_fragment_buffer_overlaps_duplicates_and_sparse_order() -> Result<()> {
    let message: Vec<u8> = (0..10).collect();
    let mut fragment_buffer = FragmentBuffer::new();

    // Sparse, out of order, duplicated and overlapping.
    for (offset, len) in [(8, 2), (0, 2), (4, 2), (0, 2), (4, 2), (1, 4)] {
        assert!(fragment_buffer.push(&fragment_record(
            0,
            0,
            10,
            offset as u32,
            &message[offset..offset + len]
        ))?);
        assert!(fragment_buffer.pop().is_err(), "complete too early");
    }
    let size = fragment_buffer.size();
    assert!(fragment_buffer.push(&fragment_record(0, 0, 10, 4, &message[4..6]))?);
    assert_eq!(fragment_buffer.size(), size, "a duplicate grew the buffer");

    assert!(fragment_buffer.push(&fragment_record(0, 0, 10, 5, &message[5..9]))?);
    let (out, epoch) = fragment_buffer.pop()?;
    assert_eq!(epoch, 0);
    assert_eq!(popped_body(&out, 10), &message[..]);
    assert_eq!(fragment_buffer.size(), 0);

    Ok(())
}

#[test]
fn test_fragment_buffer_missing_earlier_and_obsolete_messages() -> Result<()> {
    let mut fragment_buffer = FragmentBuffer::new();

    // Message 1 is complete but waits for message 0.
    assert!(fragment_buffer.push(&fragment_record(0, 1, 2, 0, &[1, 1]))?);
    assert!(fragment_buffer.pop().is_err());
    assert!(fragment_buffer.push(&fragment_record(0, 0, 1, 0, &[0]))?);
    assert_eq!(popped_body(&fragment_buffer.pop()?.0, 1), &[0]);
    assert_eq!(popped_body(&fragment_buffer.pop()?.0, 2), &[1, 1]);
    assert!(fragment_buffer.pop().is_err());

    // A retransmission of a delivered message is still handshake data, but is not kept.
    assert!(fragment_buffer.push(&fragment_record(0, 0, 1, 0, &[0]))?);
    assert!(fragment_buffer.push(&fragment_record(0, 1, 2, 0, &[1, 1]))?);
    assert_eq!(fragment_buffer.size(), 0);
    assert!(fragment_buffer.pop().is_err());

    // Neither is a message too far ahead of the next expected one.
    assert!(fragment_buffer.push(&fragment_record(
        0,
        2 + FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD,
        1,
        0,
        &[9]
    ))?);
    assert_eq!(fragment_buffer.size(), 0);

    // Partially reassembled messages go when the handshake is abandoned.
    assert!(fragment_buffer.push(&fragment_record(0, 3, 4, 0, &[3]))?);
    assert!(fragment_buffer.size() > 0);
    fragment_buffer.release();
    assert_eq!(fragment_buffer.size(), 0);
    assert!(fragment_buffer.pop().is_err());

    Ok(())
}

#[test]
fn test_fragment_buffer_zero_payload_fragments_are_bounded() -> Result<()> {
    // The retention fixture from ISSUES.md: empty fragments of message 1 while 0 is missing.
    let mut fragment_buffer = FragmentBuffer::new();
    for _ in 0..10_000 {
        assert!(fragment_buffer.push(&fragment_record(0, 1, 0, 0, &[]))?);
    }
    assert_eq!(fragment_buffer.size(), size_for(0, 0));

    // Empty fragments of an unfinished message add nothing either.
    for offset in 0..10_000 {
        assert!(fragment_buffer.push(&fragment_record(0, 2, 64, offset % 64, &[]))?);
    }
    assert_eq!(fragment_buffer.size(), size_for(0, 0) + size_for(64, 0));

    // Distinct message sequences are capped by the look-ahead window.
    for message_sequence in 3..10_000u16 {
        assert!(fragment_buffer.push(&fragment_record(0, message_sequence, 0, 0, &[]))?);
    }
    assert_eq!(
        fragment_buffer.size(),
        (FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD as usize - 2) * size_for(0, 0) + size_for(64, 0)
    );

    Ok(())
}

#[test]
fn test_fragment_buffer_many_tiny_fragments() -> Result<()> {
    // One 64 KiB message in single-byte fragments, last byte first: storage follows the
    // message length, not the fragment count, and reassembly finishes promptly.
    let message: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
    let length = message.len() as u32;
    let mut fragment_buffer = FragmentBuffer::new();
    for (offset, byte) in message.iter().enumerate().rev() {
        assert!(fragment_buffer.push(&fragment_record(0, 0, length, offset as u32, &[*byte]))?);
        assert_eq!(fragment_buffer.size(), size_for(length, 1));
    }
    let (out, _) = fragment_buffer.pop()?;
    assert_eq!(popped_body(&out, message.len()), &message[..]);
    assert_eq!(fragment_buffer.size(), 0);

    Ok(())
}
