use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct TrackedReceivePayload {
    data: Vec<u8>,
    dropped: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for TrackedReceivePayload {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for TrackedReceivePayload {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn assert_receive_sack(
    receiver: &mut Association,
    cumulative_tsn: u32,
    gaps: &[(u16, u16)],
    window: u32,
) {
    let sack = receiver.create_selective_ack_chunk();
    assert_eq!(sack.cumulative_tsn_ack, cumulative_tsn);
    assert_eq!(sack.advertised_receiver_window_credit, window);
    assert_eq!(
        sack.gap_ack_blocks
            .iter()
            .map(|gap| (gap.start, gap.end))
            .collect::<Vec<_>>(),
        gaps
    );
}

#[test]
fn reading_unordered_messages_releases_backing_before_gap_is_filled() -> Result<()> {
    const PAYLOAD_SIZE: usize = 1024;
    const RECEIVE_WINDOW: u32 = (2 * PAYLOAD_SIZE) as u32;

    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = 0;
    receiver.max_receive_buffer_size = RECEIVE_WINDOW;
    let dropped = Arc::new(AtomicUsize::new(0));

    // Leave TSN 1 missing. Each later DATA is a complete unordered message,
    // so the application can read it without advancing the cumulative ACK.
    for (tsn, byte) in [(2, 0x41), (3, 0x42)] {
        let data = ChunkPayloadData {
            tsn,
            stream_identifier: 1,
            unordered: true,
            beginning_fragment: true,
            ending_fragment: true,
            payload_type: PayloadProtocolIdentifier::Binary,
            user_data: Bytes::from_owner(TrackedReceivePayload {
                data: vec![byte; PAYLOAD_SIZE],
                dropped: Arc::clone(&dropped),
            }),
            ..Default::default()
        };
        receiver.handle_data(&data)?;
    }
    // The incoming DATA values are gone; unread delivery owns the backing.
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_receive_sack(&mut receiver, 0, &[(2, 3)], 0);

    for (index, byte) in [0x41, 0x42].into_iter().enumerate() {
        let message = receiver.stream(1)?.read_sctp()?.unwrap();
        assert_eq!(message.ppi, PayloadProtocolIdentifier::Binary);
        assert_eq!(
            &message.to_payload(PAYLOAD_SIZE)?[..],
            &[byte; PAYLOAD_SIZE]
        );
        drop(message);
        assert_eq!(
            receiver.get_my_receiver_window_credit(),
            ((index + 1) * PAYLOAD_SIZE) as u32
        );
    }
    assert!(receiver.stream(1)?.read_sctp()?.is_none());
    receiver.assert_receive_accounting();
    assert_receive_sack(&mut receiver, 0, &[(2, 3)], RECEIVE_WINDOW);
    let dropped_after_read = dropped.load(Ordering::SeqCst);

    // A duplicate uses independent backing. Receipt metadata must still
    // suppress redelivery after the original payload has been released.
    let duplicate = ChunkPayloadData {
        tsn: 2,
        stream_identifier: 1,
        unordered: true,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: PayloadProtocolIdentifier::Binary,
        user_data: Bytes::from(vec![0x41; PAYLOAD_SIZE]),
        ..Default::default()
    };
    receiver.handle_data(&duplicate)?;
    assert!(receiver.stream(1)?.read_sctp()?.is_none());
    assert_receive_sack(&mut receiver, 0, &[(2, 3)], RECEIVE_WINDOW);
    assert_eq!(dropped.load(Ordering::SeqCst), dropped_after_read);

    // Filling the hole must cumulatively acknowledge the already-read TSNs
    // without delivering them again. This also proves the tracked owners
    // belong to receipt tracking if they survived the earlier reads.
    receiver.handle_data(&ChunkPayloadData {
        tsn: 1,
        user_data: Bytes::from_static(b"gap"),
        ..duplicate.clone()
    })?;
    assert_eq!(
        &receiver
            .stream(1)?
            .read_sctp()?
            .unwrap()
            .to_payload(PAYLOAD_SIZE)?[..],
        b"gap"
    );
    assert!(receiver.stream(1)?.read_sctp()?.is_none());
    assert_receive_sack(&mut receiver, 3, &[], RECEIVE_WINDOW);
    receiver.handle_data(&duplicate)?;
    assert!(receiver.stream(1)?.read_sctp()?.is_none());
    assert_receive_sack(&mut receiver, 3, &[], RECEIVE_WINDOW);
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(
        dropped_after_read, 2,
        "receipt tracking must release already-read payload backing before a lower TSN gap closes"
    );
    Ok(())
}
