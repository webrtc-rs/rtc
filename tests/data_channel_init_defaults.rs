//! `RTCDataChannelInit`'s defaults must match what its documentation promises.
//!
//! `ordered` is the one that matters. A derived `Default` makes it `false`, so
//! `create_data_channel(label, None)` — the natural way to ask for a plain data channel —
//! would hand back an *unordered* one, contradicting both the field's own doc comment and
//! [W3C `RTCDataChannelInit`], where `ordered` is defined as `= true`.
//!
//! The consequence is not merely out-of-order application messages. Unordered chunks bypass
//! SCTP's ordered-delivery queue, so a first message can overtake the `DATA_CHANNEL_OPEN`
//! sent on the same stream; the peer then receives user data on a stream id it has not
//! accepted yet and drops it.
//!
//! [W3C `RTCDataChannelInit`]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit

use anyhow::Result;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use std::time::Instant;

#[test]
fn default_init_is_ordered() {
    assert!(
        RTCDataChannelInit::default().ordered,
        "the documented default for `ordered` is true"
    );
}

/// The default reaches the channel: passing `None` must not quietly opt out of ordering.
#[test]
fn channel_created_without_options_is_ordered() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;

    let dc = pc.create_data_channel("plain", None)?;

    assert!(
        dc.ordered(),
        "a channel created without options must be ordered"
    );

    Ok(())
}

/// Opting out still works — this is a default, not a policy.
#[test]
fn unordered_can_still_be_requested() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;

    let dc = pc.create_data_channel(
        "unordered",
        Some(RTCDataChannelInit {
            ordered: false,
            ..Default::default()
        }),
    )?;

    assert!(
        !dc.ordered(),
        "an explicit `ordered: false` must be honored"
    );

    Ok(())
}
