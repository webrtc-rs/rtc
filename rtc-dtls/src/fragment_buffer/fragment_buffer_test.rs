use super::*;

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
        // a stack overflow.
        (
            "Zero length fragment",
            vec![vec![
                0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]],
            vec![vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

#[test]
fn test_fragment_buffer_overflow() -> Result<()> {
    let mut fragment_buffer = FragmentBuffer::new();

    fragment_buffer.push(&[
        0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
    ])?;

    let big_buffer = vec![0; 2_000_000];
    let result = fragment_buffer.push(&big_buffer);

    assert!(
        result.is_err(),
        "Pushing a buffer of size 2MB should have caused FragmentBuffer::push to return an error"
    );

    Ok(())
}

/// pion `TestFragmentBuffer` "Not Aligned Fragments": a message with a hole is not reassembled.
#[test]
fn test_fragment_buffer_not_aligned_fragments_are_not_reassembled() -> Result<()> {
    let mut fragment_buffer = FragmentBuffer::new();
    for frag in [
        vec![
            0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b,
            0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02,
            0x03, 0x04,
        ],
        vec![
            0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b,
            0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05, 0x05, 0x06, 0x07,
            0x08, 0x09,
        ],
    ] {
        assert!(fragment_buffer.push(&frag)?);
    }
    assert!(fragment_buffer.pop().is_err());
    Ok(())
}

/// pion `TestFragmentBuffer_TooSmall` / `_UnmarshalInvalid`
#[test]
fn test_fragment_buffer_truncated_input_is_an_error() {
    let mut fb = FragmentBuffer::new();
    // The fragment claims 4 bytes but only 3 follow.
    assert_eq!(
        fb.push(&[
            0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x00,
        ])
        .unwrap_err(),
        Error::ErrBufferTooSmall
    );
    // A partial record header, and a partial handshake header.
    assert!(
        fb.push(&[
            0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])
        .is_err()
    );
    assert!(
        fb.push(&[
            0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03
        ])
        .is_err()
    );
}

fn test_message_body(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 7) as u8).collect()
}

fn u24(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

/// A handshake header (type Certificate unless `typ` says otherwise) followed by `payload`.
fn handshake_fragment(typ: u8, msg_seq: u16, length: u32, offset: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![typ];
    out.extend_from_slice(&u24(length));
    out.extend_from_slice(&msg_seq.to_be_bytes());
    out.extend_from_slice(&u24(offset));
    out.extend_from_slice(&u24(payload.len() as u32));
    out.extend_from_slice(payload);
    out
}

/// One handshake record carrying `handshake` (one or more handshake fragments).
fn handshake_record(handshake: &[u8]) -> Vec<u8> {
    let mut out = vec![0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    out.extend_from_slice(handshake);
    out
}

fn fragment_record(msg_seq: u16, body: &[u8], offset: u32, length: u32) -> Vec<u8> {
    handshake_record(&handshake_fragment(
        0x0b,
        msg_seq,
        body.len() as u32,
        offset,
        &body[offset as usize..(offset + length) as usize],
    ))
}

fn reassembled_message(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x0b];
    out.extend_from_slice(&u24(body.len() as u32));
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&u24(0));
    out.extend_from_slice(&u24(body.len() as u32));
    out.extend_from_slice(body);
    out
}

fn push_fragments(buffer: &mut FragmentBuffer, body: &[u8], frags: &[(u32, u32)]) {
    for &(offset, length) in frags {
        assert!(
            buffer
                .push(&fragment_record(0, body, offset, length))
                .unwrap()
        );
    }
}

fn assert_empty(buffer: &FragmentBuffer) {
    assert_eq!(buffer.size(), 0);
    assert_eq!(buffer.total_fragment_count, 0);
}

/// pion `TestFragmentBuffer_RetransmitWithDifferentBoundaries`: a 700 byte message is sent in 256
/// byte fragments and the middle one is lost; the retransmission uses 300 byte fragments (RFC 6347
/// §4.2.3 allows that), so the message is reassembled from two differently aligned sets.
#[test]
fn test_fragment_buffer_retransmit_with_different_boundaries() {
    let body = test_message_body(700);
    let mut buffer = FragmentBuffer::new();

    push_fragments(&mut buffer, &body, &[(0, 256), (512, 188)]); // (256, 256) is lost.
    assert!(
        buffer.pop().is_err(),
        "not reassembled while bytes are missing"
    );

    push_fragments(&mut buffer, &body, &[(0, 300), (300, 300), (600, 100)]);
    // (0, 300) replaced (0, 256); (600, 100) was already covered by (512, 188).
    assert_eq!(buffer.size(), 300 + 188 + 300);
    assert_eq!(buffer.total_fragment_count, 3);

    let (out, epoch) = buffer.pop().unwrap();
    assert_eq!(out, reassembled_message(&body));
    assert_eq!(epoch, 0);
    assert_empty(&buffer);
    assert!(buffer.pop().is_err());
}

/// pion `TestFragmentBuffer_OverlappingFragmentsReassemble`
#[test]
fn test_fragment_buffer_overlapping_fragments_reassemble() {
    let body = test_message_body(500);
    let mut buffer = FragmentBuffer::new();

    // Out of order, overlapping, duplicated, shorter at a cached offset and a strict superset of
    // an earlier fragment.
    push_fragments(
        &mut buffer,
        &body,
        &[
            (200, 100),
            (150, 100),
            (200, 100),
            (200, 50),
            (0, 250),
            (400, 100),
            (300, 150),
        ],
    );
    assert_eq!(buffer.pop().unwrap().0, reassembled_message(&body));
    assert_empty(&buffer);
}

/// pion `TestFragmentBuffer_LongerFragmentReplacesCachedOffset`
#[test]
fn test_fragment_buffer_longer_fragment_replaces_cached_offset() {
    let body = test_message_body(10);
    let mut buffer = FragmentBuffer::new();

    push_fragments(&mut buffer, &body, &[(0, 4), (0, 10)]);
    assert_eq!(buffer.size(), 10);
    assert_eq!(buffer.total_fragment_count, 1);
    assert_eq!(buffer.pop().unwrap().0, reassembled_message(&body));
    assert_empty(&buffer);
}

/// pion `TestFragmentBuffer_OutOfBoundsFragmentIgnored`
#[test]
fn test_fragment_buffer_out_of_bounds_fragment_ignored() {
    let body = test_message_body(100);
    let mut buffer = FragmentBuffer::new();

    for (offset, length) in [(80u32, 50u32), (120, 0)] {
        // Ends past the message / starts past the message.
        let record = handshake_record(&handshake_fragment(
            0x0b,
            0,
            100,
            offset,
            &vec![0; length as usize],
        ));
        assert!(buffer.push(&record).unwrap());
    }
    assert_empty(&buffer);
    assert!(buffer.pop().is_err());

    // The valid fragments still complete the message.
    push_fragments(&mut buffer, &body, &[(0, 60), (60, 40)]);
    assert_eq!(buffer.pop().unwrap().0, reassembled_message(&body));
}

/// pion `TestFragmentBuffer_CoveredPrefixBridgesEarlierFragments`
#[test]
fn test_fragment_buffer_covered_prefix_bridges_earlier_fragments() {
    let body = test_message_body(200);
    let mut buffer = FragmentBuffer::new();

    // [100, 150) is out of reach until [0, 120) arrives and bridges to it, and the message is
    // only complete once [150, 200) is bridged as well.
    push_fragments(&mut buffer, &body, &[(100, 50), (0, 120)]);
    assert!(buffer.pop().is_err());
    push_fragments(&mut buffer, &body, &[(150, 50)]);
    assert_eq!(buffer.pop().unwrap().0, reassembled_message(&body));
    assert_empty(&buffer);
}

/// pion `TestFragmentBuffer_CoveringFragmentReplacesSmallerOnes`
#[test]
fn test_fragment_buffer_covering_fragment_replaces_smaller_ones() {
    let body = test_message_body(300);
    let mut buffer = FragmentBuffer::new();

    push_fragments(&mut buffer, &body, &[(50, 50), (100, 50), (200, 100)]);
    assert_eq!(buffer.size(), 200);
    assert_eq!(buffer.total_fragment_count, 3);

    // Covers the first two entirely and overlaps the third.
    push_fragments(&mut buffer, &body, &[(0, 250)]);
    assert_eq!(buffer.size(), 350);
    assert_eq!(buffer.total_fragment_count, 2);

    assert_eq!(buffer.pop().unwrap().0, reassembled_message(&body));
    assert_empty(&buffer);
}

/// pion `TestFragmentBuffer_FragmentDisagreeingWithMessageIgnored`
#[test]
fn test_fragment_buffer_fragment_disagreeing_with_message_ignored() {
    let body = test_message_body(100);
    // (name, handshake type, message length, offset, fragment length)
    for (name, typ, length, offset, frag_len) in [
        // Within its own bounds, but beyond the cached message, where it would break reassembly.
        ("length", 0x0bu8, 300u32, 150u32, 50usize),
        ("type", 0x02, 100, 50, 50),
    ] {
        let mut buffer = FragmentBuffer::new();
        push_fragments(&mut buffer, &body, &[(0, 100)]);

        let record = handshake_record(&handshake_fragment(
            typ,
            0,
            length,
            offset,
            &vec![0; frag_len],
        ));
        assert!(buffer.push(&record).unwrap(), "{name}");
        assert_eq!(buffer.size(), 100, "{name}");
        assert_eq!(buffer.total_fragment_count, 1, "{name}");
        assert_eq!(
            buffer.pop().unwrap().0,
            reassembled_message(&body),
            "{name}"
        );
        assert_empty(&buffer);
    }
}

/// pion `TestFragmentBuffer_EmptyFragmentLimit`: empty fragments consume memory too, so the number
/// kept is capped, however they arrive.
#[test]
fn test_fragment_buffer_empty_fragment_limit() {
    for (message_length, per_record) in [
        (100usize, 1usize),
        (100, FRAGMENT_BUFFER_MAX_COUNT + 1),
        (0, 1),
        (0, FRAGMENT_BUFFER_MAX_COUNT + 1),
    ] {
        let mut buffer = FragmentBuffer::new();
        let body = vec![0u8; message_length];

        let mut first = 1usize;
        while first <= FRAGMENT_BUFFER_MAX_COUNT + 1 {
            let mut payload = vec![];
            for sequence in first..first + per_record {
                payload.extend(handshake_fragment(
                    0x0b,
                    sequence as u16,
                    body.len() as u32,
                    0,
                    &[],
                ));
            }
            let result = buffer.push(&handshake_record(&payload));
            if first + per_record - 1 <= FRAGMENT_BUFFER_MAX_COUNT {
                assert!(result.unwrap());
            } else {
                assert!(
                    matches!(result, Err(Error::ErrFragmentBufferOverflow { .. })),
                    "message {message_length}/{per_record}: {result:?}"
                );
            }
            first += per_record;
        }

        assert_eq!(buffer.cache.len(), FRAGMENT_BUFFER_MAX_COUNT);
        assert_eq!(buffer.total_fragment_count, FRAGMENT_BUFFER_MAX_COUNT);
        assert_eq!(buffer.size(), 0);
        assert!(buffer.pop().is_err());
    }
}
