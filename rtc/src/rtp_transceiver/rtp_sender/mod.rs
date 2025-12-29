//TODO: #[cfg(test)]
//mod rtp_sender_test;

pub mod rtcp_parameters;
pub mod rtp_capabilities;
pub mod rtp_codec;
pub mod rtp_codec_parameters;
pub mod rtp_coding_parameters;
pub mod rtp_encoding_parameters;
pub mod rtp_header_extension_capability;
pub mod rtp_header_extension_parameters;
pub mod rtp_parameters;
pub mod rtp_receiver_parameters;
pub mod rtp_send_parameters;
pub mod set_parameter_options;

use crate::media_stream::track_local::TrackLocal;
use crate::media_stream::{RtxEncoding, TrackEncoding};
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::PayloadType;
use interceptor::stream_info::StreamInfo;
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;

/// RTPSender allows an application to control how a given Track is encoded and transmitted to a remote peer
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcrtpsender-interface
#[derive(Default, Debug, Clone)]
pub struct RTCRtpSender {
    pub(crate) track_encodings: Vec<TrackEncoding>,

    pub(crate) kind: RtpCodecKind,
    pub(crate) payload_type: PayloadType,
    receive_mtu: usize,
    enable_rtx: bool,

    /// a transceiver sender since we can just check the
    /// transceiver negotiation status
    pub(crate) negotiated: bool,

    pub(crate) id: String,

    /// The id of the initial track, even if we later change to a different
    /// track id should be use when negotiating.
    pub(crate) initial_track_id: Option<String>,
    /// AssociatedMediaStreamIds from the WebRTC specifications
    pub(crate) associated_media_stream_ids: Vec<String>,

    pub(crate) paused: bool,
}

impl RTCRtpSender {
    pub fn new(
        track: Option<TrackLocal>,
        kind: RtpCodecKind,
        start_paused: bool,
        receive_mtu: usize,
        enable_rtx: bool,
        media_engine: &MediaEngine,
    ) -> Self {
        let id = math_rand_alpha(32);

        let associated_media_stream_ids = track
            .as_ref()
            .map(|track| vec![track.stream_id().to_string()])
            .unwrap_or_default();

        let mut track_encodings = vec![];
        if let Some(track) = track {
            RTCRtpSender::add_encoding_internal(
                &mut track_encodings,
                track,
                enable_rtx,
                media_engine,
            );
        }

        Self {
            track_encodings,

            kind,
            payload_type: 0,
            receive_mtu,
            enable_rtx,

            negotiated: false,

            id,
            initial_track_id: None,
            associated_media_stream_ids,

            paused: start_paused,
        }
    }

    /// track returns the RTCRtpTransceiver track, or nil
    pub fn track(&self) -> Option<&TrackLocal> {
        self.track_encodings.first().map(|e| &e.track)
    }

    pub fn get_capabilities(&self, _kind: RtpCodecKind) -> RTCRtpCapabilities {
        //TODO:
        RTCRtpCapabilities::default()
    }

    pub fn set_parameters(&mut self, _parameters: RTCRtpSendParameters) {
        //TODO:
    }

    /// get_parameters describes the current configuration for the encoding and
    /// transmission of media on the sender's track.
    pub fn get_parameters(&self) -> RTCRtpSendParameters {
        /*TODO:
        let encodings = {
            let track_encodings = self.track_encodings.lock().await;
            let mut encodings = Vec::with_capacity(track_encodings.len());
            for e in track_encodings.iter() {
                encodings.push(RTCRtpEncodingParameters {
                    rid: e.track.rid().unwrap_or_default().into(),
                    ssrc: e.ssrc,
                    payload_type: self.payload_type,
                    rtx: RTCRtpRtxParameters {
                        ssrc: e.rtx.as_ref().map(|e| e.ssrc).unwrap_or_default(),
                    },
                });
            }

            encodings
        };

        let mut rtp_parameters = self
            .media_engine
            .get_rtp_parameters_by_kind(self.kind, RTCRtpTransceiverDirection::Sendonly);
        rtp_parameters.codecs = {
            let tr = self
                .rtp_transceiver
                .lock()
                .clone()
                .and_then(|t| t.upgrade());
            if let Some(t) = &tr {
                t.get_codecs().await
            } else {
                self.media_engine.get_codecs_by_kind(self.kind)
            }
        };

        RTCRtpSendParameters {
            rtp_parameters,
            encodings,
        }*/
        RTCRtpSendParameters {
            rtp_parameters: Default::default(),
            encodings: vec![],
            ..Default::default()
        }
    }

    /// replace_track replaces the track currently being used as the sender's source with a new TrackLocal.
    /// The new track must be of the same media kind (audio, video, etc) and switching the track should not
    /// require negotiation.
    pub fn replace_track(&mut self, track: Option<TrackLocal>) -> Result<()> {
        let track_encodings = &mut self.track_encodings;

        if let Some(t) = &track {
            if self.kind != t.kind() {
                return Err(Error::ErrRTPSenderNewTrackHasIncorrectKind);
            }

            // cannot replace simulcast envelope
            if track_encodings.len() > 1 {
                return Err(Error::ErrRTPSenderNewTrackHasIncorrectEnvelope);
            }

            let _encoding = track_encodings
                .first_mut()
                .ok_or(Error::ErrRTPSenderNewTrackHasIncorrectEnvelope)?;

            /*if self.has_sent() {
                encoding.track.unbind(&encoding.context).await?;
            }

            self.seq_trans.reset_offset();
            self.rtx_seq_trans.reset_offset();


            let mid = self
                .rtp_transceiver
                .lock()
                .clone()
                .and_then(|t| t.upgrade())
                .and_then(|t| t.mid());

            let new_context = TrackLocalContext {
                id: encoding.context.id.clone(),
                params: self
                    .media_engine
                    .get_rtp_parameters_by_kind(t.kind(), RTCRtpTransceiverDirection::Sendonly),
                ssrc: encoding.context.ssrc,
                write_stream: encoding.context.write_stream.clone(),
                paused: self.paused.clone(),
                mid,
            };

            match t.bind(&new_context).await {
                Err(err) => {
                    // Re-bind the original track
                    encoding.track.bind(&encoding.context).await?;

                    Err(err)
                }
                Ok(codec) => {
                    // Codec has changed
                    encoding.context.params.codecs = vec![codec];
                    encoding.track = Arc::clone(t);
                    Ok(())
                }
            }
             */
            Ok(())
        } else {
            /*if self.has_sent() {
                for encoding in track_encodings.drain(..) {
                    encoding.track.unbind(&encoding.context).await?;
                }
            } else {
                track_encodings.clear();
            }
            */
            Ok(())
        }
    }

    /// AddEncoding adds an encoding to RTPSender. Used by simulcast senders.
    pub fn add_encoding(&mut self, track: TrackLocal, media_engine: &MediaEngine) -> Result<()> {
        if track.rid().is_none() {
            return Err(Error::ErrRTPSenderRidNil);
        }

        /*
        if self.has_stopped {
            return Err(Error::ErrRTPSenderStopped);
        }

        if self.has_sent {
            return Err(Error::ErrRTPSenderSendAlreadyCalled);
        }*/

        let base_track = self
            .track_encodings
            .first()
            .map(|e| &e.track)
            .ok_or(Error::ErrRTPSenderNoBaseEncoding)?;
        if base_track.rid().is_none() {
            return Err(Error::ErrRTPSenderNoBaseEncoding);
        }

        if base_track.id() != track.id()
            || base_track.stream_id() != track.stream_id()
            || base_track.kind() != track.kind()
        {
            return Err(Error::ErrRTPSenderBaseEncodingMismatch);
        }

        if self
            .track_encodings
            .iter()
            .any(|e| e.track.rid() == track.rid())
        {
            return Err(Error::ErrRTPSenderRIDCollision);
        }

        RTCRtpSender::add_encoding_internal(
            &mut self.track_encodings,
            track,
            self.enable_rtx,
            media_engine,
        );

        Ok(())
    }

    fn add_encoding_internal(
        track_encodings: &mut Vec<TrackEncoding>,
        track: TrackLocal,
        enable_rtx: bool,
        media_engine: &MediaEngine,
    ) {
        let ssrc = rand::random::<u32>();

        let create_rtx_stream = enable_rtx
            && media_engine
                .get_codecs_by_kind(track.kind())
                .iter()
                .any(|codec| matches!(codec.rtp_codec.mime_type.split_once("/"), Some((_, "rtx"))));

        let rtx = if create_rtx_stream {
            let ssrc = rand::random::<u32>();
            Some(RtxEncoding {
                stream_info: StreamInfo::default(),
                ssrc,
            })
        } else {
            None
        };
        let encoding = TrackEncoding {
            track,
            stream_info: StreamInfo::default(),
            ssrc,
            rtx,
        };

        track_encodings.push(encoding);
    }

    pub(crate) fn is_negotiated(&self) -> bool {
        self.negotiated
    }

    pub(crate) fn set_negotiated(&mut self) {
        self.negotiated = true;
    }
    /*
                pub(crate) fn set_rtp_transceiver(&self, rtp_transceiver: Option<Weak<RTCRtpTransceiver>>) {
                    if let Some(t) = rtp_transceiver.as_ref().and_then(|t| t.upgrade()) {
                        self.set_paused(!t.direction().has_send());
                    }
                    let mut tr = self.rtp_transceiver.lock();
                    *tr = rtp_transceiver;
                }

                pub(crate) fn set_paused(&self, paused: bool) {
                    self.paused.store(paused, Ordering::SeqCst);
                }

                /// transport returns the currently-configured DTLSTransport
                /// if one has not yet been configured
                pub fn transport(&self) -> Arc<RTCDtlsTransport> {
                    Arc::clone(&self.transport)
                }
    */

    /*
                /// send Attempts to set the parameters controlling the sending of media.
                pub async fn send(&self, parameters: &RTCRtpSendParameters) -> Result<()> {
                    if self.has_sent() {
                        return Err(Error::ErrRTPSenderSendAlreadyCalled);
                    }
                    let mut track_encodings = self.track_encodings.lock().await;
                    if track_encodings.is_empty() {
                        return Err(Error::ErrRTPSenderTrackRemoved);
                    }

                    let mid = self
                        .rtp_transceiver
                        .lock()
                        .clone()
                        .and_then(|t| t.upgrade())
                        .and_then(|t| t.mid());

                    for (idx, encoding) in track_encodings.iter_mut().enumerate() {
                        let write_stream = Arc::new(InterceptorToTrackLocalWriter::new(self.paused.clone()));
                        encoding.context.params = self.media_engine.get_rtp_parameters_by_kind(
                            encoding.track.kind(),
                            RTCRtpTransceiverDirection::Sendonly,
                        );
                        encoding.context.ssrc = parameters.encodings[idx].ssrc;
                        encoding.context.write_stream = Arc::clone(&write_stream) as _;
                        encoding.context.mid = mid.to_owned();

                        let codec = encoding.track.bind(&encoding.context).await?;
                        encoding.stream_info = create_stream_info(
                            self.id.clone(),
                            parameters.encodings[idx].ssrc,
                            codec.payload_type,
                            codec.capability.clone(),
                            &parameters.rtp_parameters.header_extensions,
                            None,
                        );
                        encoding.context.params.codecs = vec![codec.clone()];

                        let srtp_writer = Arc::clone(&encoding.srtp_stream) as Arc<dyn RTPWriter + Send + Sync>;
                        let rtp_writer = self
                            .interceptor
                            .bind_local_stream(&encoding.stream_info, srtp_writer)
                            .await;

                        *write_stream.interceptor_rtp_writer.lock().await = Some(rtp_writer);

                        if let (Some(rtx), Some(rtx_codec)) = (
                            &encoding.rtx,
                            codec_rtx_search(&codec, &parameters.rtp_parameters.codecs),
                        ) {
                            let rtx_info = AssociatedStreamInfo {
                                ssrc: parameters.encodings[idx].ssrc,
                                payload_type: codec.payload_type,
                            };

                            let rtx_stream_info = create_stream_info(
                                self.id.clone(),
                                parameters.encodings[idx].rtx.ssrc,
                                rtx_codec.payload_type,
                                rtx_codec.capability.clone(),
                                &parameters.rtp_parameters.header_extensions,
                                Some(rtx_info),
                            );

                            let rtx_srtp_writer =
                                Arc::clone(&rtx.srtp_stream) as Arc<dyn RTPWriter + Send + Sync>;
                            // ignore the rtp writer, only interceptors can write to the stream
                            self.interceptor
                                .bind_local_stream(&rtx_stream_info, rtx_srtp_writer)
                                .await;

                            *rtx.stream_info.lock().await = rtx_stream_info;

                            self.receive_rtcp_for_rtx(rtx.rtcp_interceptor.clone());
                        }
                    }

                    self.send_called.send_replace(true);
                    Ok(())
                }

                /// starts a routine that reads the rtx rtcp stream
                /// These packets aren't exposed to the user, but we need to process them
                /// for TWCC
                fn receive_rtcp_for_rtx(&self, rtcp_reader: Arc<dyn RTCPReader + Send + Sync>) {
                    let receive_mtu = self.receive_mtu;
                    let stop_called_signal = self.internal.stop_called_signal.clone();
                    let stop_called_rx = self.internal.stop_called_rx.clone();

                    tokio::spawn(async move {
                        let attrs = Attributes::new();
                        let mut b = vec![0u8; receive_mtu];
                        while !stop_called_signal.load(Ordering::SeqCst) {
                            select! {
                                r = rtcp_reader.read(&mut b, &attrs) => {
                                    if r.is_err() {
                                        break
                                    }
                                },
                                _ = stop_called_rx.notified() => break,
                            }
                        }
                    });
                }

                /// stop irreversibly stops the RTPSender
                pub async fn stop(&self) -> Result<()> {
                    if self.stop_called_signal.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    self.stop_called_signal.store(true, Ordering::SeqCst);
                    self.stop_called_tx.notify_waiters();

                    if !self.has_sent() {
                        return Ok(());
                    }

                    self.replace_track(None).await?;

                    let track_encodings = self.track_encodings.lock().await;
                    for encoding in track_encodings.iter() {
                        self.interceptor
                            .unbind_local_stream(&encoding.stream_info)
                            .await;

                        encoding.srtp_stream.close().await?;

                        if let Some(rtx) = &encoding.rtx {
                            let rtx_stream_info = rtx.stream_info.lock().await;
                            self.interceptor.unbind_local_stream(&rtx_stream_info).await;

                            rtx.srtp_stream.close().await?;
                        }
                    }

                    Ok(())
                }

                /// read reads incoming RTCP for this RTPReceiver
                pub async fn read(
                    &self,
                    b: &mut [u8],
                ) -> Result<(Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>, Attributes)> {
                    tokio::select! {
                        _ = self.wait_for_send() => {
                            let rtcp_interceptor = {
                                let track_encodings = self.track_encodings.lock().await;
                                track_encodings.first().map(|e|e.rtcp_interceptor.clone())
                            }.ok_or(Error::ErrInterceptorNotBind)?;
                            let a = Attributes::new();
                            tokio::select! {
                                _ = self.internal.stop_called_rx.notified() => Err(Error::ErrClosedPipe),
                                result = rtcp_interceptor.read(b, &a) => Ok(result?),
                            }
                        }
                        _ = self.internal.stop_called_rx.notified() => Err(Error::ErrClosedPipe),
                    }
                }

                /// read_rtcp is a convenience method that wraps Read and unmarshals for you.
                pub async fn read_rtcp(
                    &self,
                ) -> Result<(Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>, Attributes)> {
                    let mut b = vec![0u8; self.receive_mtu];
                    let (pkts, attributes) = self.read(&mut b).await?;

                    Ok((pkts, attributes))
                }

                /// ReadSimulcast reads incoming RTCP for this RTPSender for given rid
                pub async fn read_simulcast(
                    &self,
                    b: &mut [u8],
                    rid: &str,
                ) -> Result<(Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>, Attributes)> {
                    tokio::select! {
                        _ = self.wait_for_send() => {
                            let rtcp_interceptor = {
                                let track_encodings = self.track_encodings.lock().await;
                                track_encodings.iter().find(|e| e.track.rid() == Some(rid)).map(|e| e.rtcp_interceptor.clone())
                            }.ok_or(Error::ErrRTPSenderNoTrackForRID)?;
                            let a = Attributes::new();
                            tokio::select! {
                                _ = self.internal.stop_called_rx.notified() => Err(Error::ErrClosedPipe),
                                result = rtcp_interceptor.read(b, &a) => Ok(result?),
                            }
                        }
                        _ = self.internal.stop_called_rx.notified() => Err(Error::ErrClosedPipe),
                    }
                }

                /// ReadSimulcastRTCP is a convenience method that wraps ReadSimulcast and unmarshal for you
                pub async fn read_rtcp_simulcast(
                    &self,
                    rid: &str,
                ) -> Result<(Vec<Box<dyn rtcp::packet::Packet + Send + Sync>>, Attributes)> {
                    let mut b = vec![0u8; self.receive_mtu];
                    let (pkts, attributes) = self.read_simulcast(&mut b, rid).await?;

                    Ok((pkts, attributes))
                }

                /// Enables overriding outgoing `RTP` packets' `sequence number`s.
                ///
                /// Must be called once before any data sent or never called at all.
                ///
                /// # Errors
                ///
                /// Errors if this [`RTCRtpSender`] has started to send data or sequence
                /// transforming has been already enabled.
                pub fn enable_seq_transformer(&self) -> Result<()> {
                    self.seq_trans.enable()?;
                    self.rtx_seq_trans.enable()
                }

                /// Will asynchronously block/wait until send() has been called
                ///
                /// Note that it could return if underlying channel is closed,
                /// however this shouldn't happen as we have a reference to self
                /// which again owns the underlying channel.
                pub async fn wait_for_send(&self) {
                    let mut watch = self.send_called.subscribe();
                    let _ = watch.wait_for(|r| *r).await;
                }

                /// has_sent tells if data has been ever sent for this instance
                pub(crate) fn has_sent(&self) -> bool {
                    *self.send_called.borrow()
                }

                /// has_stopped tells if stop has been called
                pub(crate) async fn has_stopped(&self) -> bool {
                    self.stop_called_signal.load(Ordering::SeqCst)
                }
    */
    pub(crate) fn initial_track_id(&self) -> &Option<String> {
        &self.initial_track_id
    }

    pub(crate) fn set_initial_track_id(&mut self, id: String) -> Result<()> {
        if self.initial_track_id.is_some() {
            return Err(Error::ErrSenderInitialTrackIdAlreadySet);
        }

        self.initial_track_id = Some(id);

        Ok(())
    }

    pub(crate) fn associate_media_stream_id(&mut self, id: String) -> bool {
        if self.associated_media_stream_ids.contains(&id) {
            return false;
        }

        self.associated_media_stream_ids.push(id);

        true
    }

    pub(crate) fn associated_media_stream_ids(&self) -> &[String] {
        &self.associated_media_stream_ids
    }
}
