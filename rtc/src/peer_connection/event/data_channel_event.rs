use crate::data_channel::RTCDataChannelId;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum RTCDataChannelEvent {
    OnOpen(RTCDataChannelId),
    OnError(RTCDataChannelId),
    OnClosing(RTCDataChannelId),
    OnClose(RTCDataChannelId),

    OnBufferedAmountLow(RTCDataChannelId),
    OnBufferedAmountHigh(RTCDataChannelId),
}

impl Default for RTCDataChannelEvent {
    fn default() -> Self {
        Self::OnOpen(Default::default())
    }
}
