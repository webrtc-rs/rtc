#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone)]
pub enum RTCDataChannelEvent {
    #[default]
    OnOpen,
    OnBufferedAmountLow,
    OnError,
    OnClosing,
    OnClose,
    OnMessage,
}
