use super::*;
use sansio::Protocol;
use shared::error::Result;

fn create_new_association_pair() -> Result<(usize, usize)> {
    Ok((0, 0))
}

fn close_association_pair(_client: usize, _server: usize) {}

//use std::io::Write;

/*
fn pr_ordered_unordered_test(channel_type: ChannelType, is_ordered: bool) -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    let mut sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 2000];

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, a1) = create_new_association_pair(&br, Arc::new(ca), Arc::new(cb)).await?;

    let cfg = Config {
        channel_type,
        reliability_parameter: 0,
        label: "data".to_string(),
        ..Default::default()
    };

    let dc0 = DataChannel::dial(&a0, 100, cfg.clone()).await?;
    bridge_process_at_least_one(&br).await;

    let existing_data_channels: Vec<DataChannel> = Vec::new();
    let dc1 = DataChannel::accept(&a1, Config::default(), &existing_data_channels).await?;
    bridge_process_at_least_one(&br).await;

    assert_eq!(dc0.config, cfg, "local config should match");
    assert_eq!(dc1.config, cfg, "remote config should match");

    dc0.commit_reliability_params();
    dc1.commit_reliability_params();

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = dc0
        .write_data_channel(&Bytes::from(sbuf.clone()), true)
        .await?;
    assert_eq!(sbuf.len(), n, "data length should match");

    sbuf[0..4].copy_from_slice(&2u32.to_be_bytes());
    let n = dc0
        .write_data_channel(&Bytes::from(sbuf.clone()), true)
        .await?;
    assert_eq!(sbuf.len(), n, "data length should match");

    if !is_ordered {
        sbuf[0..4].copy_from_slice(&3u32.to_be_bytes());
        let n = dc0
            .write_data_channel(&Bytes::from(sbuf.clone()), true)
            .await?;
        assert_eq!(sbuf.len(), n, "data length should match");
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    br.drop_offset(0, 0, 1).await; // drop the first packet on the wire
    if !is_ordered {
        br.reorder(0).await;
    } else {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bridge_process_at_least_one(&br).await;

    if !is_ordered {
        let (n, is_string) = dc1.read_data_channel(&mut rbuf[..]).await?;
        assert!(is_string, "should return isString being true");
        assert_eq!(sbuf.len(), n, "data length should match");
        assert_eq!(
            3,
            u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
            "data should match"
        );
    }

    let (n, is_string) = dc1.read_data_channel(&mut rbuf[..]).await?;
    assert!(is_string, "should return isString being true");
    assert_eq!(sbuf.len(), n, "data length should match");
    assert_eq!(
        2,
        u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
        "data should match"
    );

    dc0.close().await?;
    dc1.close().await?;
    bridge_process_at_least_one(&br).await;

    close_association_pair(&br, a0, a1).await;

    Ok(())
}
*/

#[test]
fn test_data_channel_channel_type_reliable_ordered() -> Result<()> {
    let mut sbuf = vec![0u8; 1000];

    let (a0, a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        reliability_parameter: 123,
        label: "data".to_string(),
        ..Default::default()
    };

    let mut dc0 = DataChannel::dial(cfg.clone(), a0, 100)?;

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    let mut dc1 = DataChannel::accept(
        DataChannelConfig::default(),
        a1,
        msg.stream_id,
        PayloadProtocolIdentifier::Dcep,
        &msg.payload,
    )?;

    assert_eq!(dc0.config, cfg, "local config should match");
    assert_eq!(dc1.config, cfg, "remote config should match");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let data_channel_message =
        DataChannel::get_data_channel_message(true, BytesMut::from(&sbuf[0..4]));
    dc0.handle_write(data_channel_message)?;
    assert_eq!(dc0.bytes_sent(), 4, "data length should match");

    sbuf[0..4].copy_from_slice(&2u32.to_be_bytes());
    let data_channel_message =
        DataChannel::get_data_channel_message(false, BytesMut::from(&sbuf[0..4]));
    dc0.handle_write(data_channel_message)?;
    assert_eq!(dc0.bytes_sent(), 8, "data length should match");

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    dc1.handle_read(msg)?;
    assert_eq!(dc1.bytes_received(), 4, "data length should match");
    let data_channel_message = dc1.poll_read().ok_or(Error::ErrAssociationNotExisted)?;
    assert!(
        data_channel_message.ppi == PayloadProtocolIdentifier::String
            || data_channel_message.ppi == PayloadProtocolIdentifier::StringEmpty
    );
    assert_eq!(
        4,
        data_channel_message.payload.len(),
        "data length should match"
    );
    assert_eq!(
        1,
        u32::from_be_bytes([
            data_channel_message.payload[0],
            data_channel_message.payload[1],
            data_channel_message.payload[2],
            data_channel_message.payload[3]
        ]),
        "data should match"
    );

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    dc1.handle_read(msg)?;
    assert_eq!(dc1.bytes_received(), 8, "data length should match");
    let data_channel_message = dc1.poll_read().ok_or(Error::ErrAssociationNotExisted)?;
    assert!(
        !(data_channel_message.ppi == PayloadProtocolIdentifier::String
            || data_channel_message.ppi == PayloadProtocolIdentifier::StringEmpty)
    );
    assert_eq!(
        4,
        data_channel_message.payload.len(),
        "data length should match"
    );
    assert_eq!(
        2,
        u32::from_be_bytes([
            data_channel_message.payload[0],
            data_channel_message.payload[1],
            data_channel_message.payload[2],
            data_channel_message.payload[3]
        ]),
        "data should match"
    );

    dc0.close()?;
    dc1.close()?;

    close_association_pair(a0, a1);

    Ok(())
}

/*
#[tokio::test]
async fn test_data_channel_channel_type_reliable_unordered() -> Result<()> {
    let mut sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 1500];

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, a1) = create_new_association_pair(&br, Arc::new(ca), Arc::new(cb)).await?;

    let cfg = Config {
        channel_type: ChannelType::ReliableUnordered,
        reliability_parameter: 123,
        label: "data".to_string(),
        ..Default::default()
    };

    let dc0 = DataChannel::dial(&a0, 100, cfg.clone()).await?;
    bridge_process_at_least_one(&br).await;

    let existing_data_channels: Vec<DataChannel> = Vec::new();
    let dc1 = DataChannel::accept(&a1, Config::default(), &existing_data_channels).await?;
    bridge_process_at_least_one(&br).await;

    assert_eq!(dc0.config, cfg, "local config should match");
    assert_eq!(dc1.config, cfg, "remote config should match");

    dc0.commit_reliability_params();
    dc1.commit_reliability_params();

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = dc0
        .write_data_channel(&Bytes::from(sbuf.clone()), true)
        .await?;
    assert_eq!(sbuf.len(), n, "data length should match");

    sbuf[0..4].copy_from_slice(&2u32.to_be_bytes());
    let n = dc0
        .write_data_channel(&Bytes::from(sbuf.clone()), true)
        .await?;
    assert_eq!(sbuf.len(), n, "data length should match");

    tokio::time::sleep(Duration::from_millis(100)).await;
    br.reorder(0).await; // reordering on the wire
    bridge_process_at_least_one(&br).await;

    let (n, is_string) = dc1.read_data_channel(&mut rbuf[..]).await?;
    assert!(is_string, "should return isString being true");
    assert_eq!(sbuf.len(), n, "data length should match");
    assert_eq!(
        2,
        u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
        "data should match"
    );

    let (n, is_string) = dc1.read_data_channel(&mut rbuf[..]).await?;
    assert!(is_string, "should return isString being true");
    assert_eq!(sbuf.len(), n, "data length should match");
    assert_eq!(
        1,
        u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
        "data should match"
    );

    dc0.close().await?;
    dc1.close().await?;
    bridge_process_at_least_one(&br).await;

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

#[cfg(not(target_os = "windows"))] // this times out in CI on windows.
#[tokio::test]
async fn test_data_channel_channel_type_partial_reliable_rexmit() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableRexmit, true).await
}

#[cfg(not(target_os = "windows"))] // this times out in CI on windows.
#[tokio::test]
async fn test_data_channel_channel_type_partial_reliable_rexmit_unordered() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableRexmitUnordered, false).await
}

#[cfg(not(target_os = "windows"))] // this times out in CI on windows.
#[tokio::test]
async fn test_data_channel_channel_type_partial_reliable_timed() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableTimed, true).await
}

#[cfg(not(target_os = "windows"))] // this times out in CI on windows.
#[tokio::test]
async fn test_data_channel_channel_type_partial_reliable_timed_unordered() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableTimedUnordered, false).await
}

//TODO: remove this conditional test
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test]
async fn test_data_channel_buffered_amount() -> Result<()> {
    let sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 1000];

    let n_cbs = Arc::new(AtomicUsize::new(0));

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, a1) = create_new_association_pair(&br, Arc::new(ca), Arc::new(cb)).await?;

    let dc0 = Arc::new(
        DataChannel::dial(
            &a0,
            100,
            Config {
                label: "data".to_owned(),
                ..Default::default()
            },
        )
        .await?,
    );
    bridge_process_at_least_one(&br).await;

    let existing_data_channels: Vec<DataChannel> = Vec::new();
    let dc1 = Arc::new(DataChannel::accept(&a1, Config::default(), &existing_data_channels).await?);
    bridge_process_at_least_one(&br).await;

    while dc0.buffered_amount() > 0 {
        bridge_process_at_least_one(&br).await;
    }

    let n = dc0.write(&Bytes::new()).await?;
    assert_eq!(n, 0, "data length should match");
    assert_eq!(dc0.buffered_amount(), 1, "incorrect bufferedAmount");

    let n = dc0.write(&Bytes::from_static(&[0])).await?;
    assert_eq!(n, 1, "data length should match");
    assert_eq!(dc0.buffered_amount(), 2, "incorrect bufferedAmount");

    bridge_process_at_least_one(&br).await;

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, 0, "received length should match");

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, 1, "received length should match");

    dc0.set_buffered_amount_low_threshold(1500);
    assert_eq!(
        dc0.buffered_amount_low_threshold(),
        1500,
        "incorrect bufferedAmountLowThreshold"
    );
    let n_cbs2 = Arc::clone(&n_cbs);
    dc0.on_buffered_amount_low(Box::new(move || {
        n_cbs2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }));

    // Write 10 1000-byte packets (total 10,000 bytes)
    for i in 0..10 {
        let n = dc0.write(&Bytes::from(sbuf.clone())).await?;
        assert_eq!(sbuf.len(), n, "data length should match");
        assert_eq!(
            sbuf.len() * (i + 1) + 2,
            dc0.buffered_amount(),
            "incorrect bufferedAmount"
        );
    }

    let dc1_cloned = Arc::clone(&dc1);
    tokio::spawn(async move {
        while let Ok(n) = dc1_cloned.read(&mut rbuf[..]).await {
            if n == 0 {
                break;
            }
            assert_eq!(n, rbuf.len(), "received length should match");
        }
    });

    let since = tokio::time::Instant::now();
    loop {
        br.tick().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        if tokio::time::Instant::now().duration_since(since) > Duration::from_millis(500) {
            break;
        }
    }

    dc0.close().await?;
    dc1.close().await?;
    bridge_process_at_least_one(&br).await;

    assert!(
        n_cbs.load(Ordering::SeqCst) > 0,
        "should make at least one callback"
    );

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//TODO: remove this conditional test
#[cfg(not(any(target_os = "macos", target_os = "windows")))] // this times out in CI on windows.
#[tokio::test]
async fn test_stats() -> Result<()> {
    let sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 1500];

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, a1) = create_new_association_pair(&br, Arc::new(ca), Arc::new(cb)).await?;

    let cfg = Config {
        channel_type: ChannelType::Reliable,
        reliability_parameter: 123,
        label: "data".to_owned(),
        ..Default::default()
    };

    let dc0 = DataChannel::dial(&a0, 100, cfg.clone()).await?;
    bridge_process_at_least_one(&br).await;

    let existing_data_channels: Vec<DataChannel> = Vec::new();
    let dc1 = DataChannel::accept(&a1, Config::default(), &existing_data_channels).await?;
    bridge_process_at_least_one(&br).await;

    let mut bytes_sent = 0;

    let n = dc0.write(&Bytes::from(sbuf.clone())).await?;
    assert_eq!(n, sbuf.len(), "data length should match");
    bytes_sent += n;

    assert_eq!(dc0.bytes_sent(), bytes_sent);
    assert_eq!(dc0.messages_sent(), 1);

    let n = dc0.write(&Bytes::from(sbuf.clone())).await?;
    assert_eq!(n, sbuf.len(), "data length should match");
    bytes_sent += n;

    assert_eq!(dc0.bytes_sent(), bytes_sent);
    assert_eq!(dc0.messages_sent(), 2);

    let n = dc0.write(&Bytes::from_static(&[0])).await?;
    assert_eq!(n, 1, "data length should match");
    bytes_sent += n;

    assert_eq!(dc0.bytes_sent(), bytes_sent);
    assert_eq!(dc0.messages_sent(), 3);

    let n = dc0.write(&Bytes::from_static(&[])).await?;
    assert_eq!(n, 0, "data length should match");
    bytes_sent += n;

    assert_eq!(dc0.bytes_sent(), bytes_sent);
    assert_eq!(dc0.messages_sent(), 4);

    bridge_process_at_least_one(&br).await;

    let mut bytes_read = 0;

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, sbuf.len(), "data length should match");
    bytes_read += n;

    assert_eq!(dc1.bytes_received(), bytes_read);
    assert_eq!(dc1.messages_received(), 1);

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, sbuf.len(), "data length should match");
    bytes_read += n;

    assert_eq!(dc1.bytes_received(), bytes_read);
    assert_eq!(dc1.messages_received(), 2);

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, 1, "data length should match");
    bytes_read += n;

    assert_eq!(dc1.bytes_received(), bytes_read);
    assert_eq!(dc1.messages_received(), 3);

    let n = dc1.read(&mut rbuf[..]).await?;
    assert_eq!(n, 0, "data length should match");
    bytes_read += n;

    assert_eq!(dc1.bytes_received(), bytes_read);
    assert_eq!(dc1.messages_received(), 4);

    dc0.close().await?;
    dc1.close().await?;
    bridge_process_at_least_one(&br).await;

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

#[tokio::test]
async fn test_poll_data_channel() -> Result<()> {
    let mut sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 1500];

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, a1) = create_new_association_pair(&br, Arc::new(ca), Arc::new(cb)).await?;

    let cfg = Config {
        channel_type: ChannelType::Reliable,
        reliability_parameter: 123,
        label: "data".to_string(),
        ..Default::default()
    };

    let dc0 = Arc::new(DataChannel::dial(&a0, 100, cfg.clone()).await?);
    bridge_process_at_least_one(&br).await;

    let existing_data_channels: Vec<DataChannel> = Vec::new();
    let dc1 = Arc::new(DataChannel::accept(&a1, Config::default(), &existing_data_channels).await?);
    bridge_process_at_least_one(&br).await;

    let mut poll_dc0 = PollDataChannel::new(dc0);
    let mut poll_dc1 = PollDataChannel::new(dc1);

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = poll_dc0
        .write(&Bytes::from(sbuf.clone()))
        .await
        .map_err(|e| Error::new(e.to_string()))?;
    assert_eq!(sbuf.len(), n, "data length should match");

    bridge_process_at_least_one(&br).await;

    let n = poll_dc1
        .read(&mut rbuf[..])
        .await
        .map_err(|e| Error::new(e.to_string()))?;
    assert_eq!(sbuf.len(), n, "data length should match");
    assert_eq!(
        1,
        u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
        "data should match"
    );

    poll_dc0.into_inner().close().await?;
    poll_dc1.into_inner().close().await?;
    bridge_process_at_least_one(&br).await;

    close_association_pair(&br, a0, a1).await;

    Ok(())
}
*/
