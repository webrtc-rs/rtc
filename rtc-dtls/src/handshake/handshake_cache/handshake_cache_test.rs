use super::*;

#[test]
fn received_finished_matches_only_the_same_message_epoch_and_peer() {
    let mut cache = HandshakeCache::new();
    let mut finished = vec![20, 0, 0, 12, 0, 7, 0, 0, 0, 0, 0, 12];
    finished.extend_from_slice(b"verify-data!");
    cache.push(finished.clone(), 1, 7, HandshakeType::Finished, true);
    assert!(cache.matches_received_finished(&finished, 1, true));
    assert!(!cache.matches_received_finished(&finished, 0, true));
    assert!(!cache.matches_received_finished(&finished, 1, false));
    for index in [0, 3, 5, 8, 11, 12, 23] {
        let mut altered = finished.clone();
        altered[index] ^= 1;
        assert!(
            !cache.matches_received_finished(&altered, 1, true),
            "altered byte {index}"
        );
    }
    for length in 0..finished.len() {
        assert!(!cache.matches_received_finished(&finished[..length], 1, true));
    }
}

#[test]
fn only_the_matching_final_fragment_of_finished_triggers_a_reply() {
    let mut cache = HandshakeCache::new();
    let mut finished = vec![20, 0, 0, 12, 0, 7, 0, 0, 0, 0, 0, 12];
    finished.extend_from_slice(b"verify-data!");
    cache.push(finished.clone(), 1, 7, HandshakeType::Finished, true);

    let mut first = finished[..12].to_vec();
    first[11] = 6;
    first.extend_from_slice(&finished[12..18]);
    assert!(!cache.matches_received_finished(&first, 1, true));

    let mut last = finished[..12].to_vec();
    last[8] = 6;
    last[11] = 6;
    last.extend_from_slice(&finished[18..]);
    assert!(cache.matches_received_finished(&last, 1, true));
    let mut combined = first;
    combined.extend_from_slice(&last);
    assert!(cache.matches_received_finished(&combined, 1, true));

    last[12] ^= 1;
    assert!(!cache.matches_received_finished(&last, 1, true));
}

#[test]
fn test_handshake_cache_single_push() -> Result<()> {
    let tests = vec![
        (
            "Single Push",
            vec![HandshakeCacheItem {
                typ: 0.into(),
                is_client: true,
                epoch: 0,
                message_sequence: 0,
                data: vec![0x00],
            }],
            vec![HandshakeCachePullRule {
                typ: 0.into(),
                epoch: 0,
                is_client: true,
                optional: false,
            }],
            vec![0x00],
        ),
        (
            "Multi Push",
            vec![
                HandshakeCacheItem {
                    typ: 0.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: 2.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 0.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 2.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
            ],
            vec![0x00, 0x01, 0x02],
        ),
        (
            "Multi Push, Rules set order",
            vec![
                HandshakeCacheItem {
                    typ: 2.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: 0.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 0.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 2.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
            ],
            vec![0x00, 0x01, 0x02],
        ),
        (
            "Multi Push, Dupe Seqnum",
            vec![
                HandshakeCacheItem {
                    typ: 0.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 0.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
            ],
            vec![0x00, 0x01],
        ),
        (
            "Multi Push, Dupe Seqnum Client/Server",
            vec![
                HandshakeCacheItem {
                    typ: 0.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: false,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x02],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 0.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: false,
                    optional: false,
                },
            ],
            vec![0x00, 0x01, 0x02],
        ),
        (
            "Multi Push, Dupe Seqnum with Unique HandshakeType",
            vec![
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 2.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: 3.into(),
                    is_client: false,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x02],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 2.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 3.into(),
                    epoch: 0,
                    is_client: false,
                    optional: false,
                },
            ],
            vec![0x00, 0x01, 0x02],
        ),
        (
            "Multi Push, Wrong epoch",
            vec![
                HandshakeCacheItem {
                    typ: 1.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: 2.into(),
                    is_client: true,
                    epoch: 1,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: 2.into(),
                    is_client: true,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x11],
                },
                HandshakeCacheItem {
                    typ: 3.into(),
                    is_client: false,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: 3.into(),
                    is_client: false,
                    epoch: 1,
                    message_sequence: 0,
                    data: vec![0x12],
                },
                HandshakeCacheItem {
                    typ: 3.into(),
                    is_client: false,
                    epoch: 2,
                    message_sequence: 0,
                    data: vec![0x12],
                },
            ],
            vec![
                HandshakeCachePullRule {
                    typ: 1.into(),
                    epoch: 0,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 2.into(),
                    epoch: 1,
                    is_client: true,
                    optional: false,
                },
                HandshakeCachePullRule {
                    typ: 3.into(),
                    epoch: 0,
                    is_client: false,
                    optional: false,
                },
            ],
            vec![0x00, 0x01, 0x02],
        ),
    ];

    for (name, inputs, rules, expected) in tests {
        let mut h = HandshakeCache::new();
        for i in inputs {
            h.push(i.data, i.epoch, i.message_sequence, i.typ, i.is_client)?;
        }
        let verify_data = h.pull_and_merge(&rules);
        assert_eq!(
            verify_data, expected,
            "handshakeCache '{name}' exp:{expected:?} actual {verify_data:?}",
        );
    }

    Ok(())
}

#[test]
fn test_handshake_cache_session_hash() -> Result<()> {
    let tests = vec![
        (
            "Standard Handshake",
            vec![
                HandshakeCacheItem {
                    typ: HandshakeType::ClientHello,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHello,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Certificate,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerKeyExchange,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 3,
                    data: vec![0x03],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHelloDone,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 4,
                    data: vec![0x04],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ClientKeyExchange,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 5,
                    data: vec![0x05],
                },
            ],
            vec![
                0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65,
                0x27, 0xcd, 0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c,
                0x2d, 0x51, 0x1f, 0x43,
            ],
        ),
        (
            "Handshake With Client Cert Request",
            vec![
                HandshakeCacheItem {
                    typ: HandshakeType::ClientHello,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHello,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Certificate,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerKeyExchange,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 3,
                    data: vec![0x03],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::CertificateRequest,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 4,
                    data: vec![0x04],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHelloDone,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 5,
                    data: vec![0x05],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ClientKeyExchange,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 6,
                    data: vec![0x06],
                },
            ],
            vec![
                0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94,
                0x56, 0xb9, 0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93,
                0x25, 0x74, 0x9a, 0x6b,
            ],
        ),
        (
            "Handshake Ignores after ClientKeyExchange",
            vec![
                HandshakeCacheItem {
                    typ: HandshakeType::ClientHello,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHello,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Certificate,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerKeyExchange,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 3,
                    data: vec![0x03],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::CertificateRequest,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 4,
                    data: vec![0x04],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHelloDone,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 5,
                    data: vec![0x05],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ClientKeyExchange,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 6,
                    data: vec![0x06],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::CertificateVerify,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0x07],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: true,
                    epoch: 1,
                    message_sequence: 7,
                    data: vec![0x08],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: false,
                    epoch: 1,
                    message_sequence: 7,
                    data: vec![0x09],
                },
            ],
            vec![
                0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94,
                0x56, 0xb9, 0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93,
                0x25, 0x74, 0x9a, 0x6b,
            ],
        ),
        (
            "Handshake Ignores wrong epoch",
            vec![
                HandshakeCacheItem {
                    typ: HandshakeType::ClientHello,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 0,
                    data: vec![0x00],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHello,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 1,
                    data: vec![0x01],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Certificate,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 2,
                    data: vec![0x02],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerKeyExchange,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 3,
                    data: vec![0x03],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::CertificateRequest,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 4,
                    data: vec![0x04],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ServerHelloDone,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 5,
                    data: vec![0x05],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::ClientKeyExchange,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 6,
                    data: vec![0x06],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::CertificateVerify,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0x07],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0xf0],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0xf1],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: true,
                    epoch: 1,
                    message_sequence: 7,
                    data: vec![0x08],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: false,
                    epoch: 1,
                    message_sequence: 7,
                    data: vec![0x09],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: true,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0xf0],
                },
                HandshakeCacheItem {
                    typ: HandshakeType::Finished,
                    is_client: false,
                    epoch: 0,
                    message_sequence: 7,
                    data: vec![0xf1],
                },
            ],
            vec![
                0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94,
                0x56, 0xb9, 0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93,
                0x25, 0x74, 0x9a, 0x6b,
            ],
        ),
    ];

    for (name, inputs, expected) in tests {
        let mut h = HandshakeCache::new();
        for i in inputs {
            h.push(i.data, i.epoch, i.message_sequence, i.typ, i.is_client)?;
        }

        let provider = crypto::default_provider().map_err(|e| Error::Crypto(e.to_string()))?;
        let verify_data = h.session_hash(provider.crypto(), CipherSuiteHash::Sha256, 0, &[])?;

        assert_eq!(
            verify_data, expected,
            "handshakeCacheSesssionHassh '{name}' exp: {expected:?} actual {verify_data:?}"
        );
    }

    Ok(())
}

/// pion `TestHandshakeCacheLimits`, "duplicates preserve original transcript": a message already
/// held keeps its original bytes however often it is sent again, and the same sequence number in
/// another epoch or direction is a different message.
#[test]
fn test_handshake_cache_duplicates_preserve_original_transcript() -> Result<()> {
    let mut cache = HandshakeCache::new();
    assert!(cache.push(vec![1, 2, 3], 1, 4, HandshakeType::Finished, true)?);
    for _ in 0..=HANDSHAKE_CACHE_MAX_COUNT {
        assert!(!cache.push(vec![4], 1, 4, HandshakeType::Certificate, true)?);
    }
    assert_eq!(cache.cache.len(), 1);
    assert_eq!(cache.cache[0].data, vec![1, 2, 3]);
    assert_eq!(cache.size, 3);

    assert!(cache.push(vec![4], 1, 4, HandshakeType::Finished, false)?);
    assert!(cache.push(vec![4], 2, 4, HandshakeType::Finished, true)?);
    assert_eq!(cache.cache.len(), 3);
    Ok(())
}

/// pion `TestHandshakeCacheLimits`, "empty messages have a count limit"
#[test]
fn test_handshake_cache_empty_messages_have_a_count_limit() -> Result<()> {
    let mut cache = HandshakeCache::new();
    for i in 0..HANDSHAKE_CACHE_MAX_COUNT as u16 {
        cache.push(vec![], 0, i, HandshakeType::ServerHelloDone, false)?;
    }
    assert_eq!(
        cache
            .push(
                vec![],
                0,
                HANDSHAKE_CACHE_MAX_COUNT as u16,
                HandshakeType::ServerHelloDone,
                false
            )
            .unwrap_err(),
        Error::ErrHandshakeCacheOverflow
    );
    assert_eq!(cache.cache.len(), HANDSHAKE_CACHE_MAX_COUNT);
    Ok(())
}

/// pion `TestHandshakeCacheLimits`, "payload bytes have a limit"
#[test]
fn test_handshake_cache_payload_bytes_have_a_limit() -> Result<()> {
    let mut cache = HandshakeCache::new();
    cache.push(
        vec![0; HANDSHAKE_CACHE_MAX_SIZE],
        0,
        0,
        HandshakeType::Certificate,
        false,
    )?;
    assert_eq!(
        cache
            .push(vec![1], 0, 1, HandshakeType::Certificate, true)
            .unwrap_err(),
        Error::ErrHandshakeCacheOverflow
    );
    assert_eq!(cache.cache.len(), 1);
    assert_eq!(cache.size, HANDSHAKE_CACHE_MAX_SIZE);
    Ok(())
}

/// Once the handshake has finished the transcript is kept for retransmissions but nothing is
/// added to it (pion `TestHandshakeCachePostHandshakeFlood`).
#[test]
fn test_handshake_cache_finish_stops_growth_but_keeps_transcript() -> Result<()> {
    let mut cache = HandshakeCache::new();
    cache.push(vec![1], 1, 0, HandshakeType::Finished, false)?;
    cache.finish();
    for seq in 0..=(HANDSHAKE_CACHE_MAX_COUNT as u16 * 2) {
        assert!(!cache.push(vec![2], 1, seq + 1, HandshakeType::Finished, false)?);
    }
    assert_eq!(cache.cache.len(), 1);
    assert_eq!(cache.cache[0].data, vec![1]);
    assert_eq!(cache.size, 1);
    Ok(())
}
