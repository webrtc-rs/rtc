//! Ports of pion/transport v5.1.1 `packetio/buffer_test.go`. The goroutine, deadline and
//! allocation-counting tests have no counterpart in a poll-style buffer; the rest are
//! reproduced case for case.

use super::*;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
enum Key {
    Test,
    Reference,
    Nil,
    Extra,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Int(i32),
    Byte(u8),
    Bool(bool),
    Source(Arc<String>),
    Nil,
}

type Buf = Buffer<Key, Value>;

fn attr(key: Key, value: Value) -> Attribute<Key, Value> {
    Attribute { key, value }
}

fn read(
    buffer: &mut Buf,
    size: usize,
) -> (Result<usize, Error>, Vec<u8>, Vec<Attribute<Key, Value>>) {
    let mut payload = vec![0u8; size];
    let mut attributes = Vec::new();
    let result = buffer.read(&mut payload, &mut attributes);
    (result, payload, attributes)
}

/// pion TestBufferWraparound
#[test]
fn test_buffer_wraparound() {
    for offset in [11usize, 13] {
        for grow in [false, true] {
            let mut buffer = Buf::new();
            buffer.grow().unwrap();
            buffer.head = buffer.data.len() - offset;
            buffer.tail = buffer.head;
            let write = |buffer: &mut Buf, value: u8| {
                buffer
                    .write(
                        &[value, value, value],
                        &[attr(Key::Test, Value::Byte(value))],
                    )
                    .unwrap();
            };
            let read_one = |buffer: &mut Buf, value: u8| {
                let (result, payload, attributes) = read(buffer, 3);
                let n = result.unwrap();
                assert_eq!(
                    &payload[..n],
                    &[value, value, value],
                    "offset={offset} grow={grow}"
                );
                assert_eq!(attributes.get(&Key::Test), Some(&Value::Byte(value)));
            };
            for value in 0..4u8 {
                write(&mut buffer, value);
            }
            read_one(&mut buffer, 0);
            read_one(&mut buffer, 1);
            write(&mut buffer, 4);
            write(&mut buffer, 5); // Wrap the attribute ring.
            write(&mut buffer, 6); // Grow the wrapped attribute ring.
            if grow {
                buffer.grow().unwrap(); // Grow the wrapped byte ring.
            }
            for value in 2..=6u8 {
                read_one(&mut buffer, value);
            }
            assert_eq!(buffer.count(), 0);
            assert_eq!(buffer.size(), 0);
            for attributes in &buffer.attributes {
                assert!(attributes.is_empty());
            }
        }
    }
}

/// pion TestBufferLimitSize
#[test]
fn test_buffer_limit_size() {
    let mut buffer = Buf::new();
    buffer.set_limit_size(11);

    assert_eq!(buffer.size(), 0);

    // Write twice
    assert_eq!(buffer.write(&[0, 1], &[]), Ok(2));
    assert_eq!(buffer.size(), 4);

    assert_eq!(buffer.write(&[2, 3], &[]), Ok(2));
    assert_eq!(buffer.size(), 8);

    // Over capacity
    assert_eq!(buffer.write(&[4, 5], &[]), Err(Error::Full));
    assert_eq!(buffer.size(), 8);

    // Cheeky write at exact size.
    assert_eq!(buffer.write(&[6], &[]), Ok(1));
    assert_eq!(buffer.size(), 11);

    // Read once
    let (result, packet, _) = read(&mut buffer, 4);
    assert_eq!(result, Ok(2));
    assert_eq!(&packet[..2], &[0, 1]);
    assert_eq!(buffer.size(), 7);

    // Write once
    assert_eq!(buffer.write(&[7, 8], &[]), Ok(2));
    assert_eq!(buffer.size(), 11);

    // Over capacity
    assert_eq!(buffer.write(&[9, 10], &[]), Err(Error::Full));
    assert_eq!(buffer.size(), 11);

    // Read everything
    let (result, packet, _) = read(&mut buffer, 4);
    assert_eq!(result, Ok(2));
    assert_eq!(&packet[..2], &[2, 3]);
    assert_eq!(buffer.size(), 7);

    let (result, packet, _) = read(&mut buffer, 4);
    assert_eq!(result, Ok(1));
    assert_eq!(&packet[..1], &[6]);
    assert_eq!(buffer.size(), 4);

    let (result, packet, _) = read(&mut buffer, 4);
    assert_eq!(result, Ok(2));
    assert_eq!(&packet[..2], &[7, 8]);
    assert_eq!(buffer.size(), 0);

    // Nothing left.
    buffer.close();
}

/// pion TestBufferAttributes
#[test]
fn test_buffer_attributes() {
    let mut buffer = Buf::new();
    let reference = Arc::new("source".to_string());
    let mut input = vec![
        attr(Key::Test, Value::Int(42)),
        attr(Key::Reference, Value::Source(reference.clone())),
        attr(Key::Nil, Value::Nil),
    ];
    let mut payload = b"data".to_vec();
    for _ in 0..2 {
        assert_eq!(buffer.write(&payload, &input), Ok(payload.len()));
    }
    // The queue holds copies: scribbling over the inputs changes nothing.
    input.clear();
    payload.fill(0);
    assert_eq!(buffer.write(b"next", &[]), Ok(4));
    assert_eq!(buffer.size(), 12 + 3 * 2);

    let mut attributes = Vec::new();
    let n = buffer.read(&mut payload, &mut attributes).unwrap();
    assert_eq!(&payload[..n], b"data");
    assert_eq!(
        attributes,
        vec![
            attr(Key::Test, Value::Int(42)),
            attr(Key::Reference, Value::Source(reference.clone())),
            attr(Key::Nil, Value::Nil),
        ]
    );
    match attributes.get(&Key::Reference) {
        Some(Value::Source(s)) => assert!(Arc::ptr_eq(s, &reference)),
        other => panic!("reference attribute lost: {other:?}"),
    }
    attributes.set(Key::Test, Value::Int(99));
    assert!(input.is_empty());

    // The returned storage is reused and overwritten, not appended to.
    let n = buffer.read(&mut payload, &mut attributes).unwrap();
    assert_eq!(&payload[..n], b"data");
    assert_eq!(attributes.get(&Key::Test), Some(&Value::Int(42)));
    assert_eq!(buffer.size(), 6);
    let n = buffer.read(&mut payload, &mut attributes).unwrap();
    assert_eq!(&payload[..n], b"next");
    assert!(attributes.is_empty());
    assert_eq!(buffer.size(), 0);
    for slot in &buffer.attributes {
        assert!(slot.is_empty());
    }
}

/// pion TestBufferTruncationPreservesAttributes
#[test]
fn test_buffer_truncation_preserves_attributes() {
    for size in [0usize, 3, 6] {
        let mut buffer = Buf::new();
        buffer
            .write(b"packet", &[attr(Key::Test, Value::Int(42))])
            .unwrap();
        buffer.write(&[], &[]).unwrap();
        let (result, payload, attributes) = read(&mut buffer, size);
        let n = match result {
            Err(Error::ShortBuffer { copied }) => {
                assert!(size < 6, "size {size}");
                copied
            }
            Ok(n) => {
                assert!(size >= 6, "size {size}");
                n
            }
            Err(e) => panic!("size {size}: {e:?}"),
        };
        assert_eq!(&payload[..n], &b"packet"[..size]);
        assert_eq!(attributes.get(&Key::Test), Some(&Value::Int(42)));
        assert_eq!(buffer.count(), 1);
        assert_eq!(buffer.size(), 2);
        let (result, _, attributes) = read(&mut buffer, 0);
        assert_eq!(result, Ok(0));
        assert!(attributes.is_empty());
    }
}

/// pion TestBufferAttributeLimits
#[test]
fn test_buffer_attribute_limits() {
    let mut buffer = Buf::new();
    buffer.set_limit_size(4);
    buffer.set_limit_count(1);
    let mut input = vec![attr(Key::Test, Value::Int(42))];
    buffer.write(&[], &input).unwrap();
    input.set(Key::Extra, Value::Bool(true));
    assert_eq!(buffer.size(), 2); // Attributes do not change logical byte accounting.
    assert_eq!(buffer.write(&[], &[]), Err(Error::Full));
    assert_eq!(buffer.count(), 1);
    buffer.set_limit_count(0);
    buffer.write(&[], &input).unwrap();
    assert_eq!(buffer.size(), 4);
    assert_eq!(buffer.write(&[], &[]), Err(Error::Full));
    buffer.set_limit_size(1);
    for expected in [vec![attr(Key::Test, Value::Int(42))], input.clone()] {
        let (result, _, attributes) = read(&mut buffer, 0);
        assert_eq!(result, Ok(0));
        assert_eq!(attributes, expected);
    }
    assert_eq!(buffer.size(), 0);
    buffer.set_limit_size(usize::MAX);
    buffer.write(&vec![0u8; MIN_SIZE], &[]).unwrap();
}

/// pion TestBufferAttributeStorageCap
#[test]
fn test_buffer_attribute_storage_cap() {
    for limit in [128 * 1024, 0, 2 * MAX_SIZE] {
        let mut buffer = Buf::new();
        buffer.set_limit_size(limit);
        let capacity = if limit == 0 || (SIZE_HARD_LIMIT && limit >= MAX_SIZE) {
            MAX_SIZE - 1
        } else {
            limit
        };
        let payload = vec![0u8; 0x8000];
        let attributes = vec![attr(Key::Test, Value::Int(42))];
        let count = capacity / (payload.len() + 2);
        for _ in 0..count {
            buffer.write(&payload, &attributes).unwrap();
        }
        assert_eq!(
            buffer.write(&payload, &attributes),
            Err(Error::Full),
            "limit {limit}"
        );
        assert_eq!(buffer.count(), count, "limit {limit}");
        buffer.close();
        let mut out = vec![0u8; payload.len()];
        let mut got = Vec::new();
        for _ in 0..count {
            assert_eq!(buffer.read(&mut out, &mut got), Ok(payload.len()));
            assert_eq!(got, attributes);
        }
        assert_eq!(buffer.size(), 0);
    }
}

/// The poll-style half of pion's TestBufferAttributesDeadlineAndClose and
/// TestBufferConcurrentRead: close keeps queued packets readable, rejects writes, and reads
/// report EOF only once drained.
#[test]
fn test_buffer_close_drains_then_eof() {
    let mut buffer = Buf::new();
    let (result, _, _) = read(&mut buffer, 4);
    assert_eq!(result, Err(Error::Empty));
    buffer
        .write(b"data", &[attr(Key::Test, Value::Int(42))])
        .unwrap();
    buffer.close();
    buffer.close();
    assert_eq!(
        buffer.write(&[], &[attr(Key::Test, Value::Nil)]),
        Err(Error::Closed)
    );
    let (result, payload, attributes) = read(&mut buffer, 4);
    assert_eq!(result, Ok(4));
    assert_eq!(&payload, b"data");
    assert_eq!(attributes.get(&Key::Test), Some(&Value::Int(42)));
    let (result, _, attributes) = read(&mut buffer, 4);
    assert_eq!(result, Err(Error::Eof));
    assert!(attributes.is_empty());
    assert_eq!(buffer.count(), 0);
}

#[test]
fn test_buffer_packet_too_big() {
    let mut buffer = Buf::new();
    assert_eq!(
        buffer.write(&vec![0u8; 0x10000], &[]),
        Err(Error::PacketTooBig)
    );
    assert_eq!(buffer.write(&vec![0u8; 0xFFFF], &[]), Ok(0xFFFF));
}
