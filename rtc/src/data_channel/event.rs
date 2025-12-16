use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::RTCDataChannelId;

#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone)]
pub enum RTCDataChannelEvent {
    #[default]
    Unspecified,
    OnOpen(RTCDataChannelId),
    OnBufferedAmountLow,
    OnError,
    OnClosing,
    OnClose,
    OnMessage(RTCDataChannelId, RTCDataChannelMessage),
}
