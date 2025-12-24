use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::RTCDataChannelId;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub enum RTCDataChannelEvent {
    #[default]
    Unspecified,
    OnOpen(RTCDataChannelId),
    OnBufferedAmountLow(RTCDataChannelId),
    OnError(RTCDataChannelId),
    OnClosing(RTCDataChannelId),
    OnClose(RTCDataChannelId),
    OnMessage(RTCDataChannelId, RTCDataChannelMessage),
}
