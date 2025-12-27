use interceptor::Attributes;
use std::collections::VecDeque;

use crate::media::rtp_transceiver::rtp_codec::{
    RTCRtpCodecParameters, RTCRtpParameters, RTPCodecType,
};
use crate::media::rtp_transceiver::{PayloadType, SSRC};

/// TrackRemote represents a single inbound source of media
#[derive(Clone)]
pub struct TrackRemote {
    tid: usize,

    id: String,
    stream_id: String,

    receive_mtu: usize,
    payload_type: PayloadType,
    kind: RTPCodecType,
    ssrc: SSRC,
    codec: RTCRtpCodecParameters,
    pub(crate) params: RTCRtpParameters,
    rid: String,

    //media_engine: Arc<MediaEngine>,
    //receiver: Option<RTCRtpReceiver>,
    peeked: VecDeque<(rtp::packet::Packet, Attributes)>,
}

impl std::fmt::Debug for TrackRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackRemote")
            .field("id", &self.id)
            .field("stream_id", &self.stream_id)
            .field("payload_type", &self.payload_type)
            .field("kind", &self.kind)
            .field("ssrc", &self.ssrc)
            .field("codec", &self.codec)
            .field("params", &self.params)
            .field("rid", &self.rid)
            .finish()
    }
}

impl TrackRemote {
    pub(crate) fn new(
        receive_mtu: usize,
        kind: RTPCodecType,
        ssrc: SSRC,
        rid: String,
        //receiver: Weak<RTPReceiverInternal>,
    ) -> Self {
        TrackRemote {
            tid: 0, //TODO: randomize it
            id: Default::default(),
            stream_id: Default::default(),
            receive_mtu,
            payload_type: Default::default(),
            kind,
            ssrc,
            codec: Default::default(),
            params: Default::default(),
            rid,
            peeked: VecDeque::new(),
        }
    }

    pub fn tid(&self) -> usize {
        self.tid
    }

    /// id is the unique identifier for this Track. This should be unique for the
    /// stream, but doesn't have to globally unique. A common example would be 'audio' or 'video'
    /// and StreamID would be 'desktop' or 'webcam'
    pub fn id(&self) -> &str {
        self.id.as_ref()
    }

    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    /// stream_id is the group this track belongs too. This must be unique
    pub fn stream_id(&self) -> &str {
        self.stream_id.as_str()
    }

    pub fn set_stream_id(&mut self, stream_id: String) {
        self.stream_id = stream_id;
    }

    /// rid gets the RTP Stream ID of this Track
    /// With Simulcast you will have multiple tracks with the same ID, but different RID values.
    /// In many cases a TrackRemote will not have an RID, so it is important to assert it is non-zero
    pub fn rid(&self) -> &str {
        self.rid.as_str()
    }

    /// payload_type gets the PayloadType of the track
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    pub fn set_payload_type(&mut self, payload_type: PayloadType) {
        self.payload_type = payload_type;
    }

    /// kind gets the Kind of the track
    pub fn kind(&self) -> RTPCodecType {
        self.kind
    }

    pub fn set_kind(&mut self, kind: RTPCodecType) {
        self.kind = kind;
    }

    /// ssrc gets the SSRC of the track
    pub fn ssrc(&self) -> SSRC {
        self.ssrc
    }

    pub fn set_ssrc(&mut self, ssrc: SSRC) {
        self.ssrc = ssrc;
    }

    /// msid gets the Msid of the track
    pub fn msid(&self) -> String {
        format!("{} {}", self.stream_id(), self.id())
    }

    /// codec gets the Codec of the track
    pub fn codec(&self) -> &RTCRtpCodecParameters {
        &self.codec
    }

    pub fn set_codec(&mut self, codec: RTCRtpCodecParameters) {
        self.codec = codec;
    }

    pub fn params(&self) -> &RTCRtpParameters {
        &self.params
    }

    pub fn set_params(&mut self, params: RTCRtpParameters) {
        self.params = params;
    }

    /*
    /// Reads data from the track.
    ///
    /// **Cancel Safety:** This method is not cancel safe. Dropping the resulting [`Future`] before
    /// it returns [`std::task::Poll::Ready`] will cause data loss.
    pub fn read(&self, b: &mut [u8]) -> Result<(rtp::packet::Packet, Attributes)> {
        {
            // Internal lock scope
            let mut internal = self.internal.lock().await;
            if let Some((pkt, attributes)) = internal.peeked.pop_front() {
                self.check_and_update_track(&pkt).await?;

                return Ok((pkt, attributes));
            }
        };

        let receiver = match self.receiver.as_ref().and_then(|r| r.upgrade()) {
            Some(r) => r,
            None => return Err(Error::ErrRTPReceiverNil),
        };

        let (pkt, attributes) = receiver.read_rtp(b, self.tid).await?;
        self.check_and_update_track(&pkt).await?;
        Ok((pkt, attributes))
    }

    /// check_and_update_track checks payloadType for every incoming packet
    /// once a different payloadType is detected the track will be updated
    pub(crate) async fn check_and_update_track(&self, pkt: &rtp::packet::Packet) -> Result<()> {
        let payload_type = pkt.header.payload_type;
        if payload_type != self.payload_type() {
            let p = self
                .media_engine
                .get_rtp_parameters_by_payload_type(payload_type)
                .await?;

            if let Some(receiver) = &self.receiver {
                if let Some(receiver) = receiver.upgrade() {
                    self.kind.store(receiver.kind as u8, Ordering::SeqCst);
                }
            }
            self.payload_type.store(payload_type, Ordering::SeqCst);
            {
                let mut codec = self.codec.lock();
                *codec = if let Some(codec) = p.codecs.first() {
                    codec.clone()
                } else {
                    return Err(Error::ErrCodecNotFound);
                };
            }
            {
                let mut params = self.params.lock();
                *params = p;
            }
        }

        Ok(())
    }

    /// read_rtp is a convenience method that wraps Read and unmarshals for you.
    pub async fn read_rtp(&self) -> Result<(rtp::packet::Packet, Attributes)> {
        let mut b = vec![0u8; self.receive_mtu];
        let (pkt, attributes) = self.read(&mut b).await?;

        Ok((pkt, attributes))
    }

    /// peek is like Read, but it doesn't discard the packet read
    pub(crate) async fn peek(&self, b: &mut [u8]) -> Result<(rtp::packet::Packet, Attributes)> {
        let (pkt, a) = self.read(b).await?;

        // this might overwrite data if somebody peeked between the Read
        // and us getting the lock.  Oh well, we'll just drop a packet in
        // that case.
        {
            let mut internal = self.internal.lock().await;
            internal.peeked.push_back((pkt.clone(), a.clone()));
        }
        Ok((pkt, a))
    }

    /// Set the initially peeked data for this track.
    ///
    /// This is useful when a track is first created to populate data read from the track in the
    /// process of identifying the track as part of simulcast probing. Using this during other
    /// parts of the track's lifecycle is probably an error.
    pub(crate) async fn prepopulate_peeked_data(
        &self,
        data: VecDeque<(rtp::packet::Packet, Attributes)>,
    ) {
        let mut internal = self.internal.lock().await;
        internal.peeked = data;
    }

    pub(crate) async fn fire_onmute(&self) {
        let on_mute = self.handlers.on_mute.load();

        if let Some(f) = on_mute.as_ref() {
            (f.lock().await)().await
        };
    }

    pub(crate) async fn fire_onunmute(&self) {
        let on_unmute = self.handlers.on_unmute.load();

        if let Some(f) = on_unmute.as_ref() {
            (f.lock().await)().await
        };
    }*/
}
