use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum RTCDataChannelEvent {
    OnOpen(RTCDataChannelId),
    OnBufferedAmountLow(RTCDataChannelId),
    OnBufferedAmountHigh(RTCDataChannelId),
    OnError(RTCDataChannelId),
    OnClosing(RTCDataChannelId),
    OnClose(RTCDataChannelId),
    OnMessage(RTCDataChannelId, RTCDataChannelMessage),
}

impl Default for RTCDataChannelEvent {
    fn default() -> Self {
        Self::OnOpen(Default::default())
    }
}
