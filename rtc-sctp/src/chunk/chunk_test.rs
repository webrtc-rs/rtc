use super::*;

///////////////////////////////////////////////////////////////////
//chunk_type_test
///////////////////////////////////////////////////////////////////
use super::chunk_type::*;

#[test]
fn test_chunk_type_string() -> Result<()> {
    let tests = vec![
        (CT_PAYLOAD_DATA, "DATA"),
        (CT_INIT, "INIT"),
        (CT_INIT_ACK, "INIT-ACK"),
        (CT_SACK, "SACK"),
        (CT_HEARTBEAT, "HEARTBEAT"),
        (CT_HEARTBEAT_ACK, "HEARTBEAT-ACK"),
        (CT_ABORT, "ABORT"),
        (CT_SHUTDOWN, "SHUTDOWN"),
        (CT_SHUTDOWN_ACK, "SHUTDOWN-ACK"),
        (CT_ERROR, "ERROR"),
        (CT_COOKIE_ECHO, "COOKIE-ECHO"),
        (CT_COOKIE_ACK, "COOKIE-ACK"),
        (CT_CWR, "ECNE"),
        (CT_SHUTDOWN_COMPLETE, "SHUTDOWN-COMPLETE"),
        (CT_RECONFIG, "RECONFIG"),
        (CT_FORWARD_TSN, "FORWARD-TSN"),
        (ChunkType(255), "Unknown ChunkType: 255"),
    ];

    for (ct, expected) in tests {
        assert_eq!(
            ct.to_string(),
            expected,
            "failed to stringify chunkType {}, expected {}",
            ct,
            expected
        );
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_abort_test
///////////////////////////////////////////////////////////////////
use super::chunk_abort::*;

#[test]
fn test_abort_chunk_one_error_cause() -> Result<()> {
    let abort1 = ChunkAbort {
        error_causes: vec![ErrorCause {
            code: PROTOCOL_VIOLATION,
            ..Default::default()
        }],
    };

    let b = abort1.marshal()?;
    let abort2 = ChunkAbort::unmarshal(&b)?;

    assert_eq!(1, abort2.error_causes.len(), "should have only one cause");
    assert_eq!(
        abort1.error_causes[0].error_cause_code(),
        abort2.error_causes[0].error_cause_code(),
        "errorCause code should match"
    );

    Ok(())
}

#[test]
fn test_abort_chunk_many_error_causes() -> Result<()> {
    let abort1 = ChunkAbort {
        error_causes: vec![
            ErrorCause {
                code: INVALID_MANDATORY_PARAMETER,
                ..Default::default()
            },
            ErrorCause {
                code: UNRECOGNIZED_CHUNK_TYPE,
                ..Default::default()
            },
            ErrorCause {
                code: PROTOCOL_VIOLATION,
                ..Default::default()
            },
        ],
    };

    let b = abort1.marshal()?;
    let abort2 = ChunkAbort::unmarshal(&b)?;
    assert_eq!(3, abort2.error_causes.len(), "should have only one cause");
    for (i, error_cause) in abort1.error_causes.iter().enumerate() {
        assert_eq!(
            error_cause.error_cause_code(),
            abort2.error_causes[i].error_cause_code(),
            "errorCause code should match"
        );
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_error_test
///////////////////////////////////////////////////////////////////
use super::chunk_error::*;
use bytes::BufMut;
use lazy_static::lazy_static;

const CHUNK_FLAGS: u8 = 0x00;
static ORG_UNRECOGNIZED_CHUNK: Bytes =
    Bytes::from_static(&[0xc0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3]);

lazy_static! {
    static ref RAW_IN: Bytes = {
        let mut raw = BytesMut::new();
        raw.put_u8(CT_ERROR.0);
        raw.put_u8(CHUNK_FLAGS);
        raw.extend(vec![0x00, 0x10, 0x00, 0x06, 0x00, 0x0c]);
        raw.extend(ORG_UNRECOGNIZED_CHUNK.clone());
        raw.freeze()
    };
}

#[test]
fn test_chunk_error_unrecognized_chunk_type_unmarshal() -> Result<()> {
    let c = ChunkError::unmarshal(&RAW_IN)?;
    assert_eq!(CT_ERROR, c.header().typ, "chunk type should be ERROR");
    assert_eq!(1, c.error_causes.len(), "there should be on errorCause");

    let ec = &c.error_causes[0];
    assert_eq!(
        UNRECOGNIZED_CHUNK_TYPE,
        ec.error_cause_code(),
        "cause code should be unrecognizedChunkType"
    );
    assert_eq!(
        ec.raw, ORG_UNRECOGNIZED_CHUNK,
        "should have valid unrecognizedChunk"
    );

    Ok(())
}

#[test]
fn test_chunk_error_unrecognized_chunk_type_marshal() -> Result<()> {
    let ec_unrecognized_chunk_type = ErrorCause {
        code: UNRECOGNIZED_CHUNK_TYPE,
        raw: ORG_UNRECOGNIZED_CHUNK.clone(),
    };

    let ec = ChunkError {
        error_causes: vec![ec_unrecognized_chunk_type],
    };

    let raw = ec.marshal()?;
    assert_eq!(raw, *RAW_IN, "unexpected serialization result");

    Ok(())
}

#[test]
fn test_chunk_error_unrecognized_chunk_type_marshal_with_cause_value_being_nil() -> Result<()> {
    let expected =
        Bytes::from_static(&[CT_ERROR.0, CHUNK_FLAGS, 0x00, 0x08, 0x00, 0x06, 0x00, 0x04]);
    let ec_unrecognized_chunk_type = ErrorCause {
        code: UNRECOGNIZED_CHUNK_TYPE,
        ..Default::default()
    };

    let ec = ChunkError {
        error_causes: vec![ec_unrecognized_chunk_type],
    };

    let raw = ec.marshal()?;
    assert_eq!(raw, expected, "unexpected serialization result");

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_forward_tsn_test
///////////////////////////////////////////////////////////////////
use super::chunk_forward_tsn::*;

static CHUNK_FORWARD_TSN_BYTES: Bytes =
    Bytes::from_static(&[0xc0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3]);

#[test]
fn test_chunk_forward_tsn_success() -> Result<()> {
    let tests = vec![
        CHUNK_FORWARD_TSN_BYTES.clone(),
        Bytes::from_static(&[0xc0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5]),
        Bytes::from_static(&[
            0xc0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7,
        ]),
    ];

    for binary in tests {
        let actual = ChunkForwardTsn::unmarshal(&binary)?;
        let b = actual.marshal()?;
        assert_eq!(binary, b, "test not equal");
    }

    Ok(())
}

#[test]
fn test_chunk_forward_tsn_unmarshal_failure() -> Result<()> {
    let tests = vec![
        ("chunk header to short", Bytes::from_static(&[0xc0])),
        (
            "missing New Cumulative TSN",
            Bytes::from_static(&[0xc0, 0x0, 0x0, 0x4]),
        ),
        (
            "missing stream sequence",
            Bytes::from_static(&[
                0xc0, 0x0, 0x0, 0xe, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6,
            ]),
        ),
    ];

    for (name, binary) in tests {
        let result = ChunkForwardTsn::unmarshal(&binary);
        assert!(result.is_err(), "expected unmarshal: {} to fail.", name);
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_reconfig_test
///////////////////////////////////////////////////////////////////
use super::chunk_reconfig::*;

static TEST_CHUNK_RECONFIG_PARAM_A: Bytes = Bytes::from_static(&[
    0x0, 0xd, 0x0, 0x16, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0,
    0x5, 0x0, 0x6,
]);

static TEST_CHUNK_RECONFIG_PARAM_B: Bytes = Bytes::from_static(&[
    0x0, 0xd, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3,
]);

static TEST_CHUNK_RECONFIG_RESPONCE: Bytes =
    Bytes::from_static(&[0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1]);

lazy_static! {
    static ref TEST_CHUNK_RECONFIG_BYTES: Vec<Bytes> = {
        let mut tests = vec![];
        {
            let mut test = BytesMut::new();
            test.extend(vec![0x82, 0x0, 0x0, 0x1a]);
            test.extend(TEST_CHUNK_RECONFIG_PARAM_A.clone());
            tests.push(test.freeze());
        }
        {
            let mut test = BytesMut::new();
            test.extend(vec![0x82, 0x0, 0x0, 0x14]);
            test.extend(TEST_CHUNK_RECONFIG_PARAM_B.clone());
            tests.push(test.freeze());
        }
        {
            let mut test = BytesMut::new();
            test.extend(vec![0x82, 0x0, 0x0, 0x10]);
            test.extend(TEST_CHUNK_RECONFIG_RESPONCE.clone());
            tests.push(test.freeze());
        }
        {
            let mut test = BytesMut::new();
            test.extend(vec![0x82, 0x0, 0x0, 0x2c]);
            test.extend(TEST_CHUNK_RECONFIG_PARAM_A.clone());
            test.extend(vec![0u8; 2]);
            test.extend(TEST_CHUNK_RECONFIG_PARAM_B.clone());
            tests.push(test.freeze());
        }
        {
            let mut test = BytesMut::new();
            test.extend(vec![0x82, 0x0, 0x0, 0x2a]);
            test.extend(TEST_CHUNK_RECONFIG_PARAM_B.clone());
            test.extend(TEST_CHUNK_RECONFIG_PARAM_A.clone());
            tests.push(test.freeze());
        }

        tests
    };
}

#[test]
fn test_chunk_reconfig_success() -> Result<()> {
    for (i, binary) in TEST_CHUNK_RECONFIG_BYTES.iter().enumerate() {
        let actual = ChunkReconfig::unmarshal(binary)?;
        let b = actual.marshal()?;
        assert_eq!(*binary, b, "test {} not equal: {:?} vs {:?}", i, *binary, b);
    }

    Ok(())
}

#[test]
fn test_chunk_reconfig_unmarshal_failure() -> Result<()> {
    let mut test = BytesMut::new();
    test.extend(vec![0x82, 0x0, 0x0, 0x18]);
    test.extend(TEST_CHUNK_RECONFIG_PARAM_B.clone());
    test.extend(vec![0x0, 0xd, 0x0, 0x0]);
    let tests = vec![
        ("chunk header to short", Bytes::from_static(&[0x82])),
        (
            "missing parse param type (A)",
            Bytes::from_static(&[0x82, 0x0, 0x0, 0x4]),
        ),
        (
            "wrong param (A)",
            Bytes::from_static(&[0x82, 0x0, 0x0, 0x8, 0x0, 0xd, 0x0, 0x0]),
        ),
        ("wrong param (B)", test.freeze()),
    ];

    for (name, binary) in tests {
        let result = ChunkReconfig::unmarshal(&binary);
        assert!(result.is_err(), "expected unmarshal: {} to fail.", name);
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_shutdown_test
///////////////////////////////////////////////////////////////////
use super::chunk_shutdown::*;

#[test]
fn test_chunk_shutdown_success() -> Result<()> {
    let tests = vec![Bytes::from_static(&[
        0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78,
    ])];

    for binary in tests {
        let actual = ChunkShutdown::unmarshal(&binary)?;
        let b = actual.marshal()?;
        assert_eq!(binary, b, "test not equal");
    }

    Ok(())
}

#[test]
fn test_chunk_shutdown_failure() -> Result<()> {
    let tests = vec![
        (
            "length too short",
            Bytes::from_static(&[0x07, 0x00, 0x00, 0x07, 0x12, 0x34, 0x56, 0x78]),
        ),
        (
            "length too long",
            Bytes::from_static(&[0x07, 0x00, 0x00, 0x09, 0x12, 0x34, 0x56, 0x78]),
        ),
        (
            "payload too short",
            Bytes::from_static(&[0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56]),
        ),
        (
            "payload too long",
            Bytes::from_static(&[0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9f]),
        ),
        (
            "invalid type",
            Bytes::from_static(&[0x08, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78]),
        ),
    ];

    for (name, binary) in tests {
        let result = ChunkShutdown::unmarshal(&binary);
        assert!(result.is_err(), "expected unmarshal: {} to fail.", name);
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_shutdown_ack_test
///////////////////////////////////////////////////////////////////
use super::chunk_shutdown_ack::*;

#[test]
fn test_chunk_shutdown_ack_success() -> Result<()> {
    let tests = vec![Bytes::from_static(&[0x08, 0x00, 0x00, 0x04])];

    for binary in tests {
        let actual = ChunkShutdownAck::unmarshal(&binary)?;
        let b = actual.marshal()?;
        assert_eq!(binary, b, "test not equal");
    }

    Ok(())
}

#[test]
fn test_chunk_shutdown_ack_failure() -> Result<()> {
    let tests = vec![
        ("length too short", Bytes::from_static(&[0x08, 0x00, 0x00])),
        (
            "length too long",
            Bytes::from_static(&[0x08, 0x00, 0x00, 0x04, 0x12]),
        ),
        (
            "invalid type",
            Bytes::from_static(&[0x0f, 0x00, 0x00, 0x04]),
        ),
    ];

    for (name, binary) in tests {
        let result = ChunkShutdownAck::unmarshal(&binary);
        assert!(result.is_err(), "expected unmarshal: {} to fail.", name);
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_shutdown_complete_test
///////////////////////////////////////////////////////////////////
use super::chunk_shutdown_complete::*;

#[test]
fn test_chunk_shutdown_complete_success() -> Result<()> {
    let tests = vec![Bytes::from_static(&[0x0e, 0x00, 0x00, 0x04])];

    for binary in tests {
        let actual = ChunkShutdownComplete::unmarshal(&binary)?;
        let b = actual.marshal()?;
        assert_eq!(binary, b, "test not equal");
    }

    Ok(())
}

#[test]
fn test_chunk_shutdown_complete_failure() -> Result<()> {
    let tests = vec![
        ("length too short", Bytes::from_static(&[0x0e, 0x00, 0x00])),
        (
            "length too long",
            Bytes::from_static(&[0x0e, 0x00, 0x00, 0x04, 0x12]),
        ),
        (
            "invalid type",
            Bytes::from_static(&[0x0f, 0x00, 0x00, 0x04]),
        ),
    ];

    for (name, binary) in tests {
        let result = ChunkShutdownComplete::unmarshal(&binary);
        assert!(result.is_err(), "expected unmarshal: {} to fail.", name);
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_test
///////////////////////////////////////////////////////////////////
use crate::chunk::chunk_init::*;
use crate::chunk::chunk_payload_data::*;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::packet::*;
use crate::param::param_forward_tsn_supported::ParamForwardTsnSupported;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;

#[test]
fn test_init_chunk() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x81, 0x46, 0x9d, 0xfc, 0x01, 0x00, 0x00,
        0x56, 0x55, 0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d,
        0x10, 0x30, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82,
        0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0x9f, 0xeb, 0xbb, 0x5c, 0x50, 0xc9, 0xbf, 0x75,
        0x9c, 0xb1, 0x2c, 0x57, 0x4f, 0xa4, 0x5a, 0x51, 0xba, 0x60, 0x17, 0x78, 0x27, 0x94, 0x5c,
        0x31, 0xe6, 0x5d, 0x5b, 0x09, 0x47, 0xe2, 0x22, 0x06, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01,
        0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;

    if let Some(c) = pkt.chunks[0].as_any().downcast_ref::<ChunkInit>() {
        assert_eq!(
            c.initiate_tag, 1438213285,
            "Unmarshal passed for SCTP packet, but got incorrect initiate tag exp: {} act: {}",
            1438213285, c.initiate_tag
        );
        assert_eq!(
            c.advertised_receiver_window_credit, 131072,
            "Unmarshal passed for SCTP packet, but got incorrect advertisedReceiverWindowCredit exp: {} act: {}",
            131072, c.advertised_receiver_window_credit
        );
        assert_eq!(
            c.num_outbound_streams, 1024,
            "Unmarshal passed for SCTP packet, but got incorrect numOutboundStreams tag exp:{} act: {}",
            1024, c.num_outbound_streams
        );
        assert_eq!(
            c.num_inbound_streams, 2048,
            "Unmarshal passed for SCTP packet, but got incorrect numInboundStreams exp: {} act: {}",
            2048, c.num_inbound_streams
        );
        assert_eq!(
            c.initial_tsn, 3899461680u32,
            "Unmarshal passed for SCTP packet, but got incorrect initialTSN exp: {} act: {}",
            3899461680u32, c.initial_tsn
        );
    } else {
        panic!("Failed to cast Chunk -> Init");
    }

    Ok(())
}

#[test]
fn test_init_ack() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xce, 0x15, 0x79, 0xa2, 0x96, 0x19, 0xe8, 0xb2, 0x02, 0x00, 0x00,
        0x1c, 0xeb, 0x81, 0x4e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x50, 0xdf,
        0x90, 0xd9, 0x00, 0x07, 0x00, 0x08, 0x94, 0x06, 0x2f, 0x93,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    assert!(
        pkt.chunks[0].as_any().downcast_ref::<ChunkInit>().is_some(),
        "Failed to cast Chunk -> Init"
    );

    Ok(())
}

#[test]
fn test_chrome_chunk1_init() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0xbc, 0xb3, 0x45, 0xa2, 0x01, 0x00, 0x00,
        0x56, 0xce, 0x15, 0x79, 0xa2, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x94, 0x57,
        0x95, 0xc0, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82,
        0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0xff, 0x5c, 0x49, 0x19, 0x4a, 0x94, 0xe8, 0x2a,
        0xec, 0x58, 0x55, 0x62, 0x29, 0x1f, 0x8e, 0x23, 0xcd, 0x7c, 0xe8, 0x46, 0xba, 0x58, 0x1b,
        0x3d, 0xab, 0xd7, 0x7e, 0x50, 0xf2, 0x41, 0xb1, 0x2e, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01,
        0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    let raw_pkt2 = pkt.marshal()?;
    assert_eq!(raw_pkt, raw_pkt2);

    Ok(())
}

#[test]
fn test_chrome_chunk2_init_ack() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xce, 0x15, 0x79, 0xa2, 0xb5, 0xdb, 0x2d, 0x93, 0x02, 0x00, 0x01,
        0x90, 0x9b, 0xd5, 0xb3, 0x6f, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0xef, 0xb4,
        0x72, 0x87, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82,
        0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0x2e, 0xf9, 0x9c, 0x10, 0x63, 0x72, 0xed, 0x0d,
        0x33, 0xc2, 0xdc, 0x7f, 0x9f, 0xd7, 0xef, 0x1b, 0xc9, 0xc4, 0xa7, 0x41, 0x9a, 0x07, 0x68,
        0x6b, 0x66, 0xfb, 0x6a, 0x4e, 0x32, 0x5d, 0xe4, 0x25, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01,
        0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00, 0x00, 0x07, 0x01, 0x38, 0x4b,
        0x41, 0x4d, 0x45, 0x2d, 0x42, 0x53, 0x44, 0x20, 0x31, 0x2e, 0x31, 0x00, 0x00, 0x00, 0x00,
        0x9c, 0x1e, 0x49, 0x5b, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x42, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x60, 0xea, 0x00, 0x00, 0xc4, 0x13, 0x3d, 0xe9, 0x86, 0xb1, 0x85, 0x75, 0xa2, 0x79,
        0x15, 0xce, 0x9b, 0xd5, 0xb3, 0x6f, 0x20, 0xe0, 0x9f, 0x89, 0xe0, 0x27, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0xe0, 0x9f, 0x89,
        0xe0, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x56, 0xce, 0x15, 0x79, 0xa2, 0x00,
        0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x94, 0x57, 0x95, 0xc0, 0xc0, 0x00, 0x00, 0x04,
        0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00,
        0x24, 0xff, 0x5c, 0x49, 0x19, 0x4a, 0x94, 0xe8, 0x2a, 0xec, 0x58, 0x55, 0x62, 0x29, 0x1f,
        0x8e, 0x23, 0xcd, 0x7c, 0xe8, 0x46, 0xba, 0x58, 0x1b, 0x3d, 0xab, 0xd7, 0x7e, 0x50, 0xf2,
        0x41, 0xb1, 0x2e, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03, 0x00, 0x06,
        0x80, 0xc1, 0x00, 0x00, 0x02, 0x00, 0x01, 0x90, 0x9b, 0xd5, 0xb3, 0x6f, 0x00, 0x02, 0x00,
        0x00, 0x04, 0x00, 0x08, 0x00, 0xef, 0xb4, 0x72, 0x87, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08,
        0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0x2e,
        0xf9, 0x9c, 0x10, 0x63, 0x72, 0xed, 0x0d, 0x33, 0xc2, 0xdc, 0x7f, 0x9f, 0xd7, 0xef, 0x1b,
        0xc9, 0xc4, 0xa7, 0x41, 0x9a, 0x07, 0x68, 0x6b, 0x66, 0xfb, 0x6a, 0x4e, 0x32, 0x5d, 0xe4,
        0x25, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1,
        0x00, 0x00, 0xca, 0x0c, 0x21, 0x11, 0xce, 0xf4, 0xfc, 0xb3, 0x66, 0x99, 0x4f, 0xdb, 0x4f,
        0x95, 0x6b, 0x6f, 0x3b, 0xb1, 0xdb, 0x5a,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    let raw_pkt2 = pkt.marshal()?;
    assert_eq!(raw_pkt, raw_pkt2);

    Ok(())
}

#[test]
fn test_init_marshal_unmarshal() -> Result<()> {
    let mut p = Packet {
        common_header: CommonHeader {
            destination_port: 1,
            source_port: 1,
            verification_tag: 123,
        },
        chunks: vec![],
    };

    let mut init_ack = ChunkInit {
        is_ack: true,
        initiate_tag: 123,
        advertised_receiver_window_credit: 1024,
        num_outbound_streams: 1,
        num_inbound_streams: 1,
        initial_tsn: 123,
        params: vec![],
    };

    let cookie = Box::new(ParamStateCookie::new());
    init_ack.params.push(cookie);

    p.chunks.push(Box::new(init_ack));

    let raw_pkt = p.marshal()?;
    let pkt = Packet::unmarshal(&raw_pkt)?;

    if let Some(c) = pkt.chunks[0].as_any().downcast_ref::<ChunkInit>() {
        assert_eq!(
            c.initiate_tag, 123,
            "Unmarshal passed for SCTP packet, but got incorrect initiate tag exp: {} act: {}",
            123, c.initiate_tag
        );
        assert_eq!(
            c.advertised_receiver_window_credit, 1024,
            "Unmarshal passed for SCTP packet, but got incorrect advertisedReceiverWindowCredit exp: {} act: {}",
            1024, c.advertised_receiver_window_credit
        );
        assert_eq!(
            c.num_outbound_streams, 1,
            "Unmarshal passed for SCTP packet, but got incorrect numOutboundStreams tag exp:{} act: {}",
            1, c.num_outbound_streams
        );
        assert_eq!(
            c.num_inbound_streams, 1,
            "Unmarshal passed for SCTP packet, but got incorrect numInboundStreams exp: {} act: {}",
            1, c.num_inbound_streams
        );
        assert_eq!(
            c.initial_tsn, 123,
            "Unmarshal passed for SCTP packet, but got incorrect initialTSN exp: {} act: {}",
            123, c.initial_tsn
        );
    } else {
        panic!("Failed to cast Chunk -> InitAck");
    }

    Ok(())
}

// RFC 4960 Sec 3.2.1: every parameter starts with a 4-byte TLV header, so a
// trailing zero-length parameter (ForwardTsnSupported) leaves exactly
// INIT_OPTIONAL_VAR_HEADER_LENGTH bytes unparsed when the loop reaches it.
// The loop must consume that last parameter instead of stopping one short.
#[test]
fn test_init_unmarshal_trailing_forward_tsn_supported() -> Result<()> {
    let mut p = Packet {
        common_header: CommonHeader {
            destination_port: 1,
            source_port: 1,
            verification_tag: 123,
        },
        chunks: vec![],
    };

    let mut init_ack = ChunkInit {
        is_ack: true,
        initiate_tag: 123,
        advertised_receiver_window_credit: 1024,
        num_outbound_streams: 1,
        num_inbound_streams: 1,
        initial_tsn: 123,
        params: vec![],
    };

    // State cookie first, ForwardTsnSupported last.
    init_ack.params.push(Box::new(ParamStateCookie::new()));
    init_ack.params.push(Box::new(ParamForwardTsnSupported));

    p.chunks.push(Box::new(init_ack));

    let raw_pkt = p.marshal()?;
    let pkt = Packet::unmarshal(&raw_pkt)?;

    let c = pkt.chunks[0]
        .as_any()
        .downcast_ref::<ChunkInit>()
        .expect("Failed to cast Chunk -> ChunkInit");
    assert_eq!(2, c.params.len());
    assert!(
        c.params[1]
            .as_any()
            .downcast_ref::<ParamForwardTsnSupported>()
            .is_some()
    );

    Ok(())
}

#[test]
fn test_payload_data_marshal_unmarshal() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xfc, 0xd6, 0x3f, 0xc6, 0xbe, 0xfa, 0xdc, 0x52, 0x0a, 0x00, 0x00,
        0x24, 0x9b, 0x28, 0x7e, 0x48, 0xa3, 0x7b, 0xc1, 0x83, 0xc4, 0x4b, 0x41, 0x04, 0xa4, 0xf7,
        0xed, 0x4c, 0x93, 0x62, 0xc3, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x1f, 0xa8, 0x79, 0xa1, 0xc7, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x32, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x66, 0x6f, 0x6f, 0x00,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    assert!(
        pkt.chunks[1]
            .as_any()
            .downcast_ref::<ChunkPayloadData>()
            .is_some(),
        "Failed to cast Chunk -> PayloadData"
    );
    Ok(())
}

#[test]
fn test_select_ack_chunk() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xc2, 0x98, 0x98, 0x0f, 0x42, 0x31, 0xea, 0x78, 0x03, 0x00, 0x00,
        0x14, 0x87, 0x73, 0xbd, 0xa4, 0x00, 0x01, 0xfe, 0x74, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x02,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    assert!(
        pkt.chunks[0]
            .as_any()
            .downcast_ref::<ChunkSelectiveAck>()
            .is_some(),
        "Failed to cast Chunk -> SelectiveAck"
    );
    Ok(())
}

#[test]
fn test_reconfig_chunk() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xb6, 0xa5, 0x12, 0xe5, 0x75, 0x3b, 0x12, 0xd3, 0x82, 0x0, 0x0,
        0x16, 0x0, 0xd, 0x0, 0x12, 0x4e, 0x1c, 0xb9, 0xe6, 0x3a, 0x74, 0x8d, 0xff, 0x4e, 0x1c,
        0xb9, 0xe6, 0x0, 0x1, 0x0, 0x0,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    if let Some(c) = pkt.chunks[0].as_any().downcast_ref::<ChunkReconfig>() {
        assert!(c.param_a.is_some(), "param_a must not be none");
        assert_eq!(
            c.param_a
                .as_ref()
                .unwrap()
                .as_any()
                .downcast_ref::<ParamOutgoingResetRequest>()
                .unwrap()
                .stream_identifiers[0],
            1,
            "unexpected stream identifier"
        );
    } else {
        panic!("Failed to cast Chunk -> Reconfig");
    }

    Ok(())
}

#[test]
fn test_forward_tsn_chunk() -> Result<()> {
    let mut raw_pkt = BytesMut::new();
    raw_pkt.extend(vec![
        0x13, 0x88, 0x13, 0x88, 0xb6, 0xa5, 0x12, 0xe5, 0x1f, 0x9d, 0xa0, 0xfb,
    ]);
    raw_pkt.extend(CHUNK_FORWARD_TSN_BYTES.clone());
    let raw_pkt = raw_pkt.freeze();
    let pkt = Packet::unmarshal(&raw_pkt)?;

    if let Some(c) = pkt.chunks[0].as_any().downcast_ref::<ChunkForwardTsn>() {
        assert_eq!(
            c.new_cumulative_tsn, 3,
            "unexpected New Cumulative TSN: {}",
            c.new_cumulative_tsn
        );
    } else {
        panic!("Failed to cast Chunk -> Forward TSN");
    }

    Ok(())
}

#[test]
fn test_select_ack_chunk_followed_by_a_payload_data_chunk() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x13, 0x88, 0x13, 0x88, 0xc2, 0x98, 0x98, 0x0f, 0x58, 0xcf, 0x38,
        0xC0, // A SACK chunk follows.
        0x03, 0x00, 0x00, 0x14, 0x87, 0x73, 0xbd, 0xa4, 0x00, 0x01, 0xfe, 0x74, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x02, // A payload data chunk follows.
        0x00, 0x07, 0x00, 0x3B, 0xA4, 0x50, 0x7B, 0xC5, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x33, 0x7B, 0x22, 0x65, 0x76, 0x65, 0x6E, 0x74, 0x22, 0x3A, 0x22, 0x72, 0x65, 0x73, 0x69,
        0x7A, 0x65, 0x22, 0x2C, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3A, 0x36, 0x36, 0x35,
        0x2C, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3A, 0x34, 0x39, 0x39, 0x7D, 0x00,
    ]);
    let pkt = Packet::unmarshal(&raw_pkt)?;
    assert!(
        pkt.chunks[0]
            .as_any()
            .downcast_ref::<ChunkSelectiveAck>()
            .is_some(),
        "Failed to cast Chunk -> SelectiveAck"
    );
    assert!(
        pkt.chunks[1]
            .as_any()
            .downcast_ref::<ChunkPayloadData>()
            .is_some(),
        "Failed to cast Chunk -> PayloadData"
    );
    Ok(())
}

///////////////////////////////////////////////////////////////////
//chunk_heartbeat_test
///////////////////////////////////////////////////////////////////
use super::chunk_heartbeat::*;
use super::chunk_heartbeat_ack::*;
use crate::param::Param;
use crate::param::param_header::PARAM_HEADER_LENGTH;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_state_cookie::ParamStateCookie;

fn heartbeat_info_param(info: &[u8]) -> Box<dyn Param> {
    Box::new(ParamHeartbeatInfo {
        heartbeat_information: Bytes::copy_from_slice(info),
    })
}

/// Mirrors pion's `chunkHeader{typ, flags, raw}.marshal()`: a raw chunk with
/// the given body and no padding.
fn heartbeat_chunk_bytes(typ: ChunkType, body: &[u8]) -> Bytes {
    let header = ChunkHeader {
        typ,
        flags: 0,
        value_length: body.len() as u16,
    };
    let mut buf = BytesMut::new();
    header.marshal_to(&mut buf).unwrap();
    buf.extend_from_slice(body);
    buf.freeze()
}

fn heartbeat_info_param_bytes(info: &[u8]) -> Bytes {
    heartbeat_info_param(info).marshal().unwrap()
}

#[test]
fn chunk_heartbeat_unmarshal_success_empty_body() -> Result<()> {
    // HEARTBEAT with no body (header only) should be accepted, params left empty.
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &[]);

    let hb = ChunkHeartbeat::unmarshal(&raw)?;
    assert_eq!(CT_HEARTBEAT, hb.header().typ);
    assert_eq!(0, hb.params.len());
    Ok(())
}

#[test]
fn chunk_heartbeat_unmarshal_success_with_info() -> Result<()> {
    let info = [0xde, 0xad, 0xbe, 0xef];
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &heartbeat_info_param_bytes(&info));

    let hb = ChunkHeartbeat::unmarshal(&raw)?;

    assert_eq!(CT_HEARTBEAT, hb.header().typ);
    assert_eq!(1, hb.params.len());
    let p = hb.params[0]
        .as_any()
        .downcast_ref::<ParamHeartbeatInfo>()
        .expect("param should be ParamHeartbeatInfo");
    assert_eq!(Bytes::copy_from_slice(&info), p.heartbeat_information);
    Ok(())
}

#[test]
fn chunk_heartbeat_unmarshal_success_with_zero_padding_after_tlv() -> Result<()> {
    let info = [0xaa, 0xbb, 0xcc, 0xdd];
    let mut body = heartbeat_info_param_bytes(&info).to_vec();
    // add extra zero padding outside the TLV
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &body);

    let hb = ChunkHeartbeat::unmarshal(&raw)?;

    assert_eq!(1, hb.params.len());
    let p = hb.params[0]
        .as_any()
        .downcast_ref::<ParamHeartbeatInfo>()
        .expect("param should be ParamHeartbeatInfo");
    assert_eq!(Bytes::copy_from_slice(&info), p.heartbeat_information);
    Ok(())
}

#[test]
fn chunk_heartbeat_unmarshal_failure_trailing_non_zero_bytes() {
    let info = [0x01, 0x02, 0x03, 0x04];
    let mut body = heartbeat_info_param_bytes(&info).to_vec();
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // non-zero trailing byte

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &body);

    let err = ChunkHeartbeat::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatExtraNonZero, err);
}

#[test]
fn chunk_heartbeat_unmarshal_failure_wrong_chunk_type() {
    let raw = heartbeat_chunk_bytes(CT_INIT, &[]);

    let err = ChunkHeartbeat::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrChunkTypeNotHeartbeat, err);
}

#[test]
fn chunk_heartbeat_unmarshal_failure_too_short_body() {
    // A body shorter than a parameter header (TLV, 4 bytes) should fail.
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &[0x00, 0x01, 0x02]);

    let err = ChunkHeartbeat::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatNotLongEnoughInfo, err);
}

#[test]
fn chunk_heartbeat_unmarshal_failure_truncated_param_body() {
    // Build a valid HeartbeatInfo TLV, then truncate it so the advertised
    // length is larger than the available bytes.
    let info = [0x11, 0x22, 0x33, 0x44];
    let pp = heartbeat_info_param_bytes(&info);
    assert!(pp.len() > PARAM_HEADER_LENGTH);

    let truncated = &pp[..pp.len() - 1]; // chop one byte off -> length mismatch

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, truncated);

    let err = ChunkHeartbeat::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrParseParamTypeFailed, err);
}

#[test]
fn chunk_heartbeat_unmarshal_failure_param_type_not_heartbeat_info() {
    // Use a different param type (StateCookie) to trigger ErrHeartbeatParam.
    let pp = ParamStateCookie {
        cookie: Bytes::from_static(&[0x01, 0x02, 0x03]),
    }
    .marshal()
    .unwrap();

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &pp);

    let err = ChunkHeartbeat::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatParam, err);
}

#[test]
fn chunk_heartbeat_marshal_round_trip() -> Result<()> {
    let info = [0xca, 0xfe, 0xba, 0xbe];
    let hb = ChunkHeartbeat {
        params: vec![heartbeat_info_param(&info)],
    };

    let raw = hb.marshal()?;
    let hb2 = ChunkHeartbeat::unmarshal(&raw)?;

    assert_eq!(1, hb2.params.len());
    let p = hb2.params[0]
        .as_any()
        .downcast_ref::<ParamHeartbeatInfo>()
        .expect("param should be ParamHeartbeatInfo");
    assert_eq!(Bytes::copy_from_slice(&info), p.heartbeat_information);
    Ok(())
}

#[test]
fn chunk_heartbeat_marshal_failure_no_params() {
    let hb = ChunkHeartbeat { params: vec![] };

    let err = hb.marshal().unwrap_err();
    assert_eq!(Error::ErrHeartbeatMarshalNoInfo, err);
}

#[test]
fn chunk_heartbeat_marshal_failure_more_than_one_param() {
    let hb = ChunkHeartbeat {
        params: vec![heartbeat_info_param(&[0x01]), heartbeat_info_param(&[0x02])],
    };

    let err = hb.marshal().unwrap_err();
    assert_eq!(Error::ErrHeartbeatMarshalNoInfo, err);
}

#[test]
fn chunk_heartbeat_marshal_failure_wrong_param_type() {
    // Not a ParamHeartbeatInfo -> ErrHeartbeatParam.
    let hb = ChunkHeartbeat {
        params: vec![Box::new(ParamStateCookie {
            cookie: Bytes::from_static(&[0x01]),
        })],
    };

    let err = hb.marshal().unwrap_err();
    assert_eq!(Error::ErrHeartbeatParam, err);
}

#[test]
fn chunk_heartbeat_check() -> Result<()> {
    let hb = ChunkHeartbeat::default();
    hb.check()
}

///////////////////////////////////////////////////////////////////
//chunk_heartbeat_ack_test
///////////////////////////////////////////////////////////////////

#[test]
fn chunk_heartbeat_ack_unmarshal_marshal_success() -> Result<()> {
    let tests: Vec<(&str, Vec<u8>)> = vec![
        ("empty-info", vec![]),
        ("aligned-4", vec![0x01, 0x02, 0x03, 0x04]),
        ("non-aligned-5", vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
    ];

    for (name, info) in tests {
        let pp = heartbeat_info_param_bytes(&info);
        let encoded = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, &pp);

        let hb_ack = ChunkHeartbeatAck::unmarshal(&encoded)
            .unwrap_or_else(|e| panic!("unmarshal HeartbeatAck for {name}: {e}"));

        assert_eq!(
            CT_HEARTBEAT_ACK,
            hb_ack.header().typ,
            "chunk type for {name}"
        );
        assert_eq!(1, hb_ack.params.len(), "params length for {name}");
        let got = hb_ack.params[0]
            .as_any()
            .downcast_ref::<ParamHeartbeatInfo>()
            .unwrap_or_else(|| panic!("param type for {name}"));
        assert_eq!(
            Bytes::from(info.clone()),
            got.heartbeat_information,
            "heartbeat info for {name}"
        );

        let round_trip = hb_ack
            .marshal()
            .unwrap_or_else(|e| panic!("marshal HeartbeatAck (round-trip) for {name}: {e}"));
        assert_eq!(encoded, round_trip, "round-trip bytes for {name}");
    }
    Ok(())
}

#[test]
fn chunk_heartbeat_ack_unmarshal_empty_body() -> Result<()> {
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, &[]);

    let hb_ack = ChunkHeartbeatAck::unmarshal(&raw)?;
    assert!(hb_ack.params.is_empty());
    Ok(())
}

#[test]
fn chunk_heartbeat_ack_unmarshal_failure_wrong_chunk_type() {
    let pp = heartbeat_info_param_bytes(&[0x01, 0x02, 0x03, 0x04]);
    // wrong type on purpose
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT, &pp);

    let err = ChunkHeartbeatAck::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrChunkTypeNotHeartbeatAck, err);
}

#[test]
fn chunk_heartbeat_ack_unmarshal_failure_body_too_short() {
    // Less than a parameter header (TLV, 4 bytes) in the body.
    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, &[0xaa, 0xbb, 0xcc]);

    let err = ChunkHeartbeatAck::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatAckParams, err);
}

#[test]
fn chunk_heartbeat_ack_unmarshal_failure_truncated_param_body() {
    // Build a valid HeartbeatInfo TLV, then truncate it so the advertised
    // length is larger than the available bytes.
    let info = [0x11, 0x22, 0x33, 0x44];
    let pp = heartbeat_info_param_bytes(&info);
    assert!(pp.len() > PARAM_HEADER_LENGTH);

    let truncated = &pp[..pp.len() - 1];

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, truncated);

    let err = ChunkHeartbeatAck::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatAckParams, err);
}

#[test]
fn chunk_heartbeat_ack_unmarshal_failure_wrong_param_type() {
    // A TLV with a param type that is *not* heartbeatInfo but is otherwise valid.
    let body = [
        0x00, 0x02, // some param type != heartbeatInfo (which is 1 per RFC)
        0x00, 0x04, // param length
    ];

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, &body);

    let err = ChunkHeartbeatAck::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatAckNotHeartbeatInfo, err);
}

#[test]
fn chunk_heartbeat_ack_unmarshal_failure_trailing_non_zero() {
    let info = [0x01, 0x02, 0x03, 0x04];
    let mut body = heartbeat_info_param_bytes(&info).to_vec();
    // append a non-zero byte after the single parameter.
    body.push(0x01);

    let raw = heartbeat_chunk_bytes(CT_HEARTBEAT_ACK, &body);

    let err = ChunkHeartbeatAck::unmarshal(&raw).unwrap_err();
    assert_eq!(Error::ErrHeartbeatExtraNonZero, err);
}

#[test]
fn chunk_heartbeat_ack_marshal_failure_param_count() {
    // no params
    let hb_ack = ChunkHeartbeatAck::default();
    let err = hb_ack.marshal().unwrap_err();
    assert_eq!(Error::ErrHeartbeatAckParams, err);

    // too many params
    let hb_ack = ChunkHeartbeatAck {
        params: vec![heartbeat_info_param(&[]), heartbeat_info_param(&[])],
    };
    let err = hb_ack.marshal().unwrap_err();
    assert_eq!(Error::ErrHeartbeatAckParams, err);
}

/// Found by fuzzing: a FORWARD-TSN whose header declares no room for the new-cumulative-TSN, with
/// more bytes after it than the chunk owns, used to read past the end of the chunk and panic.
/// (`Packet::unmarshal` hands each chunk exactly its own bytes, so a packet could not trigger
/// this; the public chunk API could.)
#[test]
fn test_forward_tsn_shorter_than_its_fixed_part_is_rejected() {
    let raw = Bytes::from_static(&[0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x23, 0x30, 0x24]);
    assert!(ChunkForwardTsn::unmarshal(&raw).is_err());

    // The bytes after the declared length are not part of the chunk, whatever they look like.
    let raw = Bytes::from_static(&[
        0xc0, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07, // FORWARD-TSN, new cumulative TSN 7
        0xff, 0xff, 0xff, 0xff, // the start of some other chunk
    ]);
    let chunk = ChunkForwardTsn::unmarshal(&raw).unwrap();
    assert_eq!(chunk.new_cumulative_tsn, 7);
    assert!(chunk.streams.is_empty());
}
