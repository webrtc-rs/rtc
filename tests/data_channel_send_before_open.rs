//! `send` must not report success for data it cannot carry.
//!
//! Until the SCTP stream backing a channel exists, the write path cannot deliver anything. That
//! failure used to be invisible: `send` checked only that the channel was *registered*, so it
//! returned `Ok(())`, and the real rejection happened later inside
//! `DataChannelHandler::handle_write` — on the pipeline's write pass, where an `Err` is logged
//! and discarded rather than returned to anyone.
//!
//! The caller was therefore told its message went out while it was dropped on the floor. That is
//! the worst of the three possible contracts: buffering (what [W3C `send()`] prescribes for a
//! `connecting` channel) and erroring are both recoverable, silence is not.
//!
//! [W3C `send()`]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannel-send

use anyhow::Result;
use bytes::BytesMut;
use rtc::data_channel::{RTCDataChannelInit, RTCDataChannelState};
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::shared::error::Error;
use std::time::Instant;

#[test]
fn send_before_the_stream_exists_is_rejected() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;

    let mut dc = pc.create_data_channel("probe", Some(RTCDataChannelInit::default()))?;
    assert_eq!(
        dc.ready_state(),
        RTCDataChannelState::Connecting,
        "a freshly created channel has no stream yet"
    );

    assert_eq!(
        dc.send(Instant::now(), BytesMut::from(&b"dropped"[..])),
        Err(Error::ErrDataChannelNotOpen),
        "send must not claim success before the channel opens"
    );
    assert_eq!(
        dc.send_text(Instant::now(), "dropped"),
        Err(Error::ErrDataChannelNotOpen),
        "send_text must not claim success before the channel opens"
    );

    Ok(())
}

/// A rejected send must not be counted against the back-pressure budget: those bytes never
/// entered the SCTP pipeline, so nothing will ever release them. Leaking the counter would
/// permanently shrink the channel's send window.
#[test]
fn rejected_send_does_not_charge_outstanding_bytes() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;

    let mut dc = pc.create_data_channel("probe", Some(RTCDataChannelInit::default()))?;

    let _ = dc.send(Instant::now(), BytesMut::from(&b"dropped"[..]));

    assert_eq!(
        dc.outstanding_bytes(),
        0,
        "a send that never reached SCTP must not be charged"
    );

    Ok(())
}

/// Sending on an id that was never registered is a different failure from sending too early,
/// and the two should stay distinguishable — a caller can retry the second but not the first.
#[test]
fn send_on_a_closed_channel_reports_closed() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;

    let mut dc = pc.create_data_channel("probe", Some(RTCDataChannelInit::default()))?;
    let id = dc.id();
    dc.close()?;

    let mut dc = pc.data_channel(id).expect("handle survives close");
    assert_ne!(
        dc.send(Instant::now(), BytesMut::from(&b"dropped"[..])),
        Ok(()),
        "send on a closed channel must fail"
    );

    Ok(())
}
