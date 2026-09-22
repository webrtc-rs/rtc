use super::*;

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
            h.push(i.data, i.epoch, i.message_sequence, i.typ, i.is_client);
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
            h.push(i.data, i.epoch, i.message_sequence, i.typ, i.is_client);
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

/// A marshalled handshake message of `typ` (Finished carrying `body`, or ServerHelloDone).
fn cached_message(typ: HandshakeType, message_sequence: u16, body: &[u8]) -> Vec<u8> {
    let message = match typ {
        HandshakeType::Finished => {
            HandshakeMessage::Finished(handshake_message_finished::HandshakeMessageFinished {
                verify_data: body.to_vec(),
            })
        }
        _ => HandshakeMessage::ServerHelloDone(
            handshake_message_server_hello_done::HandshakeMessageServerHelloDone,
        ),
    };
    let mut handshake = Handshake::new(message);
    handshake.handshake_header.message_sequence = message_sequence;
    let mut raw = vec![];
    handshake.marshal(&mut raw).unwrap();
    raw
}

fn rule(typ: HandshakeType, epoch: u16, is_client: bool, optional: bool) -> HandshakeCachePullRule {
    HandshakeCachePullRule {
        typ,
        epoch,
        is_client,
        optional,
    }
}

#[test]
fn test_handshake_cache_full_pull_map() -> Result<()> {
    let mut h = HandshakeCache::new();
    // Two client Finished at epoch 0 (the later one wins, as a ClientHello with a cookie
    // does), one at epoch 1, and a server message of the same type.
    let early = cached_message(HandshakeType::Finished, 0, &[0xa0]);
    let late = cached_message(HandshakeType::Finished, 2, &[0xa2]);
    let epoch1 = cached_message(HandshakeType::Finished, 3, &[0xa3]);
    let server = cached_message(HandshakeType::Finished, 1, &[0xb1]);
    let done = cached_message(HandshakeType::ServerHelloDone, 2, &[]);
    h.push(early.clone(), 0, 0, HandshakeType::Finished, true);
    h.push(late.clone(), 0, 2, HandshakeType::Finished, true);
    h.push(epoch1.clone(), 1, 3, HandshakeType::Finished, true);
    h.push(server.clone(), 0, 1, HandshakeType::Finished, false);
    h.push(done.clone(), 0, 2, HandshakeType::ServerHelloDone, false);

    // Latest message for the rule's type, epoch and sender.
    assert_eq!(
        h.pull_and_merge(&[rule(HandshakeType::Finished, 0, true, false)]),
        late
    );
    assert_eq!(
        h.pull_and_merge(&[rule(HandshakeType::Finished, 1, true, false)]),
        epoch1
    );
    // Rule order, not cache order, sets the transcript order; unmatched rules are skipped.
    assert_eq!(
        h.pull_and_merge(&[
            rule(HandshakeType::ServerHelloDone, 0, false, false),
            rule(HandshakeType::Certificate, 0, false, true),
            rule(HandshakeType::Finished, 0, false, false),
        ]),
        [done.clone(), server.clone()].concat()
    );

    let (seq, messages) = h.full_pull_map(2, &[rule(HandshakeType::Finished, 0, true, false)])?;
    assert_eq!(seq, 3);
    assert_eq!(
        messages.get(&HandshakeType::Finished),
        Some(&HandshakeMessage::Finished(
            handshake_message_finished::HandshakeMessageFinished {
                verify_data: vec![0xa2]
            }
        ))
    );

    // Optional messages may be missing without breaking the sequence check.
    let (seq, messages) = h.full_pull_map(
        1,
        &[
            rule(HandshakeType::Certificate, 0, false, true),
            rule(HandshakeType::Finished, 0, false, false),
            rule(HandshakeType::ServerHelloDone, 0, false, false),
        ],
    )?;
    assert_eq!(seq, 3);
    assert_eq!(messages.len(), 2);

    // A missing mandatory message, or a gap in the sequence, fails.
    assert!(
        h.full_pull_map(0, &[rule(HandshakeType::Certificate, 0, false, false)])
            .is_err()
    );
    assert!(
        h.full_pull_map(0, &[rule(HandshakeType::Finished, 0, true, false)])
            .is_err()
    );

    Ok(())
}
