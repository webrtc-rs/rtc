//! Regression tests for partial reliability, recovery, and stream reset.

use super::*;

#[test]
fn test_extension_negotiation_for_init_and_init_ack() -> Result<()> {
    for is_ack in [false, true] {
        for (legacy_pr, listed_pr, reconfig) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let mut a = create_association(TransportConfig::default());
            let mut params: Vec<Box<dyn Param>> = vec![];
            if is_ack {
                params.push(Box::new(ParamStateCookie::new()));
            }
            if legacy_pr {
                params.push(Box::new(ParamForwardTsnSupported {}));
            }
            let mut chunk_types = vec![];
            if listed_pr {
                chunk_types.push(CT_FORWARD_TSN);
            }
            if reconfig {
                chunk_types.push(CT_RECONFIG);
            }
            params.push(Box::new(ParamSupportedExtensions { chunk_types }));
            let init = ChunkInit {
                is_ack,
                initiate_tag: 123,
                advertised_receiver_window_credit: 65536,
                num_outbound_streams: 10,
                num_inbound_streams: 10,
                initial_tsn: 1,
                params,
            };
            let packet = Packet {
                common_header: CommonHeader {
                    verification_tag: if is_ack { a.my_verification_tag } else { 0 },
                    source_port: a.destination_port,
                    destination_port: a.source_port,
                },
                chunks: vec![],
            };
            if is_ack {
                a.set_state(AssociationState::CookieWait);
                a.handle_init_ack(&packet, &init, Instant::now())?;
            } else {
                let response = a.handle_init(&packet, &init)?;
                let ack = response[0].chunks[0]
                    .as_any()
                    .downcast_ref::<ChunkInit>()
                    .unwrap();
                assert!(
                    ack.params
                        .iter()
                        .any(|p| p.as_any().is::<ParamForwardTsnSupported>())
                );
            }
            assert_eq!(a.use_forward_tsn, legacy_pr || listed_pr);
            assert_eq!(a.peer_supports_reconfig, reconfig);
        }
    }
    Ok(())
}

#[test]
fn test_unsupported_reset_leaves_both_api_halves_usable() -> Result<()> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut a = timed_test_association();
    a.peer_supports_reconfig = false;
    let mut stream = a.open_stream(1, ppi)?;
    assert!(stream.close(now).is_err());
    assert!(stream.is_readable());
    assert!(stream.is_writable());
    stream.write_sctp(now, &Bytes::from_static(b"still usable"), ppi)?;
    let packets = a.gather_outbound(now).0;
    assert!(reset_requests(&packets).is_empty());
    assert_eq!(transmitted_data(&packets).len(), 1);
    assert!(a.timers.get(Timer::Reconfig).is_none());
    Ok(())
}

#[test]
fn test_incoming_reset_without_peer_advertisement_gets_response_only() -> Result<()> {
    let now = Instant::now();
    let mut a = timed_test_association();
    a.peer_supports_reconfig = false;
    a.open_stream(1, PayloadProtocolIdentifier::Binary)?;
    let request = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: a.my_next_rsn.wrapping_sub(1),
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    assert_eq!(
        reconfig_results(&a.handle_reconfig(now, &reset_config(&request))?),
        [ReconfigResult::SuccessPerformed],
    );
    assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
    assert!(a.timers.get(Timer::Reconfig).is_none());
    assert!(a.stream(1).is_err());
    Ok(())
}

#[test]
fn test_retired_stream_handle_cannot_stop_next_delivery() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let first = ChunkPayloadData {
        tsn: a.peer_last_tsn.wrapping_add(1),
        stream_identifier: 1,
        stream_sequence_number: 0,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: Bytes::from_static(b"old"),
        ..Default::default()
    };
    a.handle_data(&first)?;
    let request = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: a.my_next_rsn.wrapping_sub(1),
        sender_last_tsn: first.tsn,
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&request))?;
    let reciprocal = reset_requests(&a.gather_outbound(now).0).remove(0);
    receive_reset_response(&mut a, now, &reciprocal, ReconfigResult::SuccessPerformed)?;
    a.handle_data(&ChunkPayloadData {
        tsn: first.tsn.wrapping_add(1),
        user_data: Bytes::from_static(b"new"),
        ..first
    })?;
    {
        let mut old = a.stream(1)?;
        assert_eq!(old.read()?.unwrap().len(), 3);
        old.stop(now)?;
    }
    while a.poll().is_some() {}
    assert_eq!(a.stream(1)?.read()?.unwrap().len(), 3);
    Ok(())
}

#[test]
fn test_window_reopening_restores_t3_congestion_response() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.cwnd = 4 * a.mtu;
    a.open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"fill"), ppi)?;
    let filled = transmitted_data(&a.gather_outbound(now).0).remove(0);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: filled.tsn,
            advertised_receiver_window_credit: 0,
            ..Default::default()
        },
        now,
    )?;
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"probe"), ppi)?;
    let probe = transmitted_data(&a.gather_outbound(now).0).remove(0);
    assert_eq!(a.zero_window_probe, Some(probe.tsn));
    // Probe is lost. The peer application drains the earlier payload and
    // advertises an open window without acknowledging the missing probe.
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: filled.tsn,
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        now,
    )?;
    a.stream(1)?.write_sctp(
        now,
        &Bytes::from_static(b"ordinary data in reopened window"),
        ppi,
    )?;
    assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
    assert!(a.inflight_queue.len() > 1);
    assert!(a.cwnd > a.mtu);
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
    assert_eq!(
        a.cwnd, a.mtu,
        "ordinary T3 loss after the window reopened must reduce cwnd"
    );
    Ok(())
}

#[test]
fn test_responsive_small_positive_window_does_not_exhaust_t3() -> Result<()> {
    let mut a = timed_test_association();
    let mut now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    // RFC 9260 6.1 A treats an rwnd smaller than the next DATA as closed,
    // including a positive but insufficient advertised receiver window.
    a.rwnd = 2;
    a.open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"probe"), ppi)?;
    let probe = transmitted_data(&a.gather_outbound(now).0).remove(0);
    assert_eq!(a.zero_window_probe, Some(probe.tsn));
    for _ in 0..9 {
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: probe.tsn.wrapping_sub(1),
                advertised_receiver_window_credit: 2,
                ..Default::default()
            },
            now,
        )?;
        now = a.timers.get(Timer::T3RTX).unwrap();
        a.handle_timeout(now);
        assert!(
            !a.is_closed(),
            "a responsive peer with a too-small positive window is not a failed path"
        );
        a.gather_outbound(now);
    }
    Ok(())
}

#[test]
fn test_rfc3758_forward_tsn_parameter_negotiates_partial_reliability() -> Result<()> {
    let mut a = create_association(TransportConfig::default());
    let init = ChunkInit {
        initiate_tag: 123,
        advertised_receiver_window_credit: 65536,
        num_outbound_streams: 10,
        num_inbound_streams: 10,
        initial_tsn: 1,
        params: vec![Box::new(
            crate::param::param_forward_tsn_supported::ParamForwardTsnSupported {},
        )],
        ..Default::default()
    };
    let packet = Packet {
        common_header: CommonHeader {
            verification_tag: 0,
            source_port: a.destination_port,
            destination_port: a.source_port,
        },
        chunks: vec![],
    };
    let _reply = a.handle_init(&packet, &init)?;
    assert!(
        a.use_forward_tsn,
        "RFC 3758 0xc000 advertisement must negotiate partial reliability"
    );
    Ok(())
}

#[test]
fn test_local_open_cannot_relabel_saved_receiver() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let mut data = ChunkPayloadData {
            tsn: a.peer_last_tsn.wrapping_add(1),
            stream_identifier: 1,
            stream_sequence_number: 0,
            beginning_fragment: true,
            ending_fragment: true,
            unordered,
            payload_type: PayloadProtocolIdentifier::Binary,
            ..Default::default()
        };
        let mut last_reciprocal = a.my_next_rsn.wrapping_sub(1);
        for (sequence, payload) in [b"old".as_slice(), b"middle".as_slice()]
            .into_iter()
            .enumerate()
        {
            data.user_data = Bytes::copy_from_slice(payload);
            a.handle_data(&data)?;
            let request = ParamOutgoingResetRequest {
                reconfig_request_sequence_number: sequence as u32 + 1,
                reconfig_response_sequence_number: last_reciprocal,
                sender_last_tsn: data.tsn,
                stream_identifiers: vec![1],
            };
            assert_eq!(
                reconfig_results(&a.handle_reconfig(now, &reset_config(&request))?),
                [ReconfigResult::SuccessPerformed],
            );
            let reciprocals = reset_requests(&a.gather_outbound(now).0);
            assert_eq!(reciprocals.len(), 1);
            last_reciprocal = reciprocals[0].reconfig_request_sequence_number;
            receive_reset_response(
                &mut a,
                now,
                &reciprocals[0],
                ReconfigResult::SuccessPerformed,
            )?;
            data.tsn = data.tsn.wrapping_add(1);
        }

        data.user_data = Bytes::from_static(b"current");
        a.handle_data(&data)?;
        let old = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&old[..], b"old");
        {
            assert!(matches!(
                a.open_stream(1, PayloadProtocolIdentifier::Binary),
                Err(Error::ErrStreamAlreadyExist)
            ));
            let mut middle = a
                .accept_stream()
                .expect("saved receiver has its own API epoch");
            assert!(!middle.is_writable());
            assert!(middle.is_readable());
            middle.stop(now)?;
        }
        assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
        while a.poll().is_some() {}
        assert!(a.stream(1)?.is_writable());
        let current = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&current[..], b"current");
        data.tsn = data.tsn.wrapping_add(1);
        data.stream_sequence_number = if unordered { 0 } else { 1 };
        data.user_data = Bytes::from_static(b"later in current");
        a.handle_data(&data)?;
        let later = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&later[..], b"later in current");
        assert_eq!(a.receive_streams[&1].get_num_bytes(), 0);

        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 3,
            reconfig_response_sequence_number: last_reciprocal,
            sender_last_tsn: data.tsn,
            stream_identifiers: vec![1],
        };
        a.handle_reconfig(now, &reset_config(&request))?;
        let reciprocals = reset_requests(&a.gather_outbound(now).0);
        assert_eq!(
            reciprocals.len(),
            1,
            "the current wire epoch still needs its own reciprocal reset"
        );
        assert_eq!(reciprocals[0].stream_identifiers, [1]);
    }
    Ok(())
}

#[test]
fn test_accept_stream_publishes_next_saved_delivery_without_poll_event() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let mut last_reciprocal = a.my_next_rsn.wrapping_sub(1);
    for sequence in 1..=2 {
        let data = ChunkPayloadData {
            tsn: a.peer_last_tsn.wrapping_add(1),
            stream_identifier: 1,
            stream_sequence_number: 0,
            beginning_fragment: true,
            ending_fragment: true,
            payload_type: PayloadProtocolIdentifier::Binary,
            user_data: Bytes::from(vec![sequence as u8]),
            ..Default::default()
        };
        a.handle_data(&data)?;
        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: sequence,
            reconfig_response_sequence_number: last_reciprocal,
            sender_last_tsn: data.tsn,
            stream_identifiers: vec![1],
        };
        a.handle_reconfig(now, &reset_config(&request))?;
        let reciprocal = reset_requests(&a.gather_outbound(now).0).remove(0);
        last_reciprocal = reciprocal.reconfig_request_sequence_number;
        receive_reset_response(&mut a, now, &reciprocal, ReconfigResult::SuccessPerformed)?;
    }
    let first = a
        .accept_stream()
        .expect("first accepted stream")
        .read_sctp()?
        .unwrap()
        .to_payload(8)?;
    assert_eq!(first.as_ref(), &[1]);
    let second = a
        .accept_stream()
        .expect("accept_stream itself must expose the next saved receiver")
        .read_sctp()?
        .unwrap()
        .to_payload(8)?;
    assert_eq!(second.as_ref(), &[2]);
    Ok(())
}
