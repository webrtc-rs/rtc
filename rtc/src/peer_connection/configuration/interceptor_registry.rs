use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::rtp_sender::{RTCPFeedback, RtpCodecKind};
use interceptor::{Interceptor, ReceiverReportBuilder, Registry, SenderReportBuilder};
use shared::error::Result;

/// register_default_interceptors will register some useful interceptors.
/// If you want to customize which interceptors are loaded, you should copy the
/// code from this method and remove unwanted interceptors.
pub fn register_default_interceptors<P>(
    registry: Registry<P>,
    _media_engine: &mut MediaEngine,
) -> Result<Registry<impl Interceptor + use<P>>>
where
    P: Interceptor,
{
    //TODO: let registry = configure_nack(registry, media_engine);

    let registry = configure_rtcp_reports(registry);

    //TODO: let registry = configure_twcc_receiver_only(registry, media_engine)?;

    Ok(registry)
}

/// configure_rtcp_reports will setup everything necessary for generating Sender and Receiver Reports
pub fn configure_rtcp_reports<P>(registry: Registry<P>) -> Registry<impl Interceptor + use<P>>
where
    P: Interceptor,
{
    registry
        .with(ReceiverReportBuilder::new().build())
        .with(SenderReportBuilder::new().build())
}

/// configure_nack will setup everything necessary for handling generating/responding to nack messages.
pub fn configure_nack<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Registry<impl Interceptor + use<P>>
where
    P: Interceptor,
{
    media_engine.register_feedback(
        RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
    media_engine.register_feedback(
        RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: "pli".to_owned(),
        },
        RtpCodecKind::Video,
    );

    /*TODO:let generator = Box::new(Generator::builder());
    let responder = Box::new(Responder::builder());
    registry.add(responder);
    registry.add(generator);*/
    registry
}

/*
/// configure_twcc will setup everything necessary for adding
/// a TWCC header extension to outgoing RTP packets and generating TWCC reports.
pub fn configure_twcc(registry: Registry, media_engine: &mut MediaEngine) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RTPCodecType::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RTPCodecType::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Audio,
        None,
    )?;

    let sender = Box::new(Sender::builder());
    let receiver = Box::new(Receiver::builder());
    registry.add(sender);
    registry.add(receiver);
    Ok(registry)
}

/// configure_twcc_sender will setup everything necessary for adding
/// a TWCC header extension to outgoing RTP packets. This will allow the remote peer to generate TWCC reports.
pub fn configure_twcc_sender_only(
    mut registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Audio,
        None,
    )?;

    let sender = Box::new(Sender::builder());
    registry.add(sender);
    Ok(registry)
}

/// configure_twcc_receiver will setup everything necessary for generating TWCC reports.
pub fn configure_twcc_receiver_only(
    mut registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RTPCodecType::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RTPCodecType::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RTPCodecType::Audio,
        None,
    )?;

    let receiver = Box::new(Receiver::builder());
    registry.add(receiver);
    Ok(registry)
}
*/
