use std::collections::HashMap;

use bytes::BytesMut;
use shared::marshal::{Marshal, MarshalSize};

use super::*;
use shared::error::flatten_errs;

/// TrackLocalStaticRTP  is a TrackLocal that has a pre-set codec and accepts RTP Packets.
/// If you wish to send a media.Sample use TrackLocalStaticSample
#[derive(Debug)]
pub struct TrackLocalStaticRTP {
    codec: RTCRtpCodecCapability,
    id: String,
    rid: Option<String>,
    stream_id: String,
}

impl TrackLocalStaticRTP {
    /// returns a TrackLocalStaticRTP without rid.
    pub fn new(codec: RTCRtpCodecCapability, id: String, stream_id: String) -> Self {
        TrackLocalStaticRTP {
            codec,
            id,
            rid: None,
            stream_id,
        }
    }

    /// returns a TrackLocalStaticRTP with rid.
    pub fn new_with_rid(
        codec: RTCRtpCodecCapability,
        id: String,
        rid: String,
        stream_id: String,
    ) -> Self {
        TrackLocalStaticRTP {
            codec,
            id,
            rid: Some(rid),
            stream_id,
        }
    }

    /// codec gets the Codec of the track
    pub fn codec(&self) -> RTCRtpCodecCapability {
        self.codec.clone()
    }

    pub async fn any_binding_paused(&self) -> bool {
        let bindings = self.bindings.lock().await;
        bindings
            .iter()
            .any(|b| b.sender_paused.load(Ordering::SeqCst))
    }

    pub async fn all_binding_paused(&self) -> bool {
        let bindings = self.bindings.lock().await;
        bindings
            .iter()
            .all(|b| b.sender_paused.load(Ordering::SeqCst))
    }

    /// write_rtp_with_extensions writes a RTP Packet to the TrackLocalStaticRTP
    /// If one PeerConnection fails the packets will still be sent to
    /// all PeerConnections. The error message will contain the ID of the failed
    /// PeerConnections so you can remove them
    ///
    /// If the RTCRtpSender direction is such that no packets should be sent, any call to this
    /// function are blocked internally. Care must be taken to not increase the sequence number
    /// while the sender is paused. While the actual _sending_ is blocked, the receiver will
    /// miss out when the sequence number "rolls over", which in turn will break SRTP.
    ///
    /// Extensions that are already configured on the packet are overwritten by extensions in
    /// `extensions`.
    pub fn write_rtp_with_extensions(
        &self,
        p: &rtp::packet::Packet,
        extensions: &[rtp::extension::HeaderExtension],
    ) -> Result<usize> {
        let attr = Attributes::new();
        self.write_rtp_with_extensions_attributes(p, extensions, &attr)
    }

    pub fn write_rtp_with_extensions_attributes(
        &self,
        p: &rtp::packet::Packet,
        extensions: &[rtp::extension::HeaderExtension],
        attr: &Attributes,
    ) -> Result<usize> {
        let mut n = 0;
        let mut write_errs = vec![];
        let mut pkt = p.clone();

        let bindings = {
            let bindings = self.bindings.lock().await;
            bindings.clone()
        };
        // Prepare the extensions data
        let extension_data: HashMap<_, _> = extensions
            .iter()
            .flat_map(|extension| {
                let buf = {
                    let mut buf = BytesMut::with_capacity(extension.marshal_size());
                    buf.resize(extension.marshal_size(), 0);
                    if let Err(err) = extension.marshal_to(&mut buf) {
                        write_errs.push(Error::Util(err));
                        return None;
                    }

                    buf.freeze()
                };

                Some((extension.uri(), buf))
            })
            .collect();

        for b in bindings.into_iter() {
            if b.is_sender_paused() {
                // See caveat in function doc.
                continue;
            }
            pkt.header.ssrc = b.ssrc;
            pkt.header.payload_type = b.payload_type;

            for ext in b.hdr_ext_ids.iter() {
                let payload = ext.payload.to_owned();
                if let Err(err) = pkt.header.set_extension(ext.id, payload) {
                    write_errs.push(Error::Rtp(err));
                }
            }

            for (uri, data) in extension_data.iter() {
                if let Some(id) = b
                    .params
                    .header_extensions
                    .iter()
                    .find(|ext| &ext.uri == uri)
                    .map(|ext| ext.id)
                {
                    if let Err(err) = pkt.header.set_extension(id as u8, data.clone()) {
                        write_errs.push(Error::Rtp(err));
                        continue;
                    }
                }
            }

            match b.write_stream.write_rtp_with_attributes(&pkt, attr).await {
                Ok(m) => {
                    n += m;
                }
                Err(err) => {
                    write_errs.push(err);
                }
            }
        }

        flatten_errs(write_errs)?;
        Ok(n)
    }
}

impl TrackLocal for TrackLocalStaticRTP {
    /// id is the unique identifier for this Track. This should be unique for the
    /// stream, but doesn't have to globally unique. A common example would be 'audio' or 'video'
    /// and StreamID would be 'desktop' or 'webcam'
    fn id(&self) -> &str {
        self.id.as_str()
    }

    /// RID is the RTP Stream ID for this track.
    fn rid(&self) -> Option<&str> {
        self.rid.as_deref()
    }

    /// stream_id is the group this track belongs too. This must be unique
    fn stream_id(&self) -> &str {
        self.stream_id.as_str()
    }

    /// kind controls if this TrackLocal is audio or video
    fn kind(&self) -> RTPCodecType {
        if self.codec.mime_type.starts_with("audio/") {
            RTPCodecType::Audio
        } else if self.codec.mime_type.starts_with("video/") {
            RTPCodecType::Video
        } else {
            RTPCodecType::Unspecified
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TrackLocalWriter for TrackLocalStaticRTP {
    /// `write_rtp_with_attributes` writes a RTP Packet to the TrackLocalStaticRTP
    /// If one PeerConnection fails the packets will still be sent to
    /// all PeerConnections. The error message will contain the ID of the failed
    /// PeerConnections so you can remove them
    ///
    /// If the RTCRtpSender direction is such that no packets should be sent, any call to this
    /// function are blocked internally. Care must be taken to not increase the sequence number
    /// while the sender is paused. While the actual _sending_ is blocked, the receiver will
    /// miss out when the sequence number "rolls over", which in turn will break SRTP.
    fn write_rtp_with_attributes(
        &self,
        pkt: &rtp::packet::Packet,
        attr: &Attributes,
    ) -> Result<usize> {
        self.write_rtp_with_extensions_attributes(pkt, &[], attr)
    }

    /// write writes a RTP Packet as a buffer to the TrackLocalStaticRTP
    /// If one PeerConnection fails the packets will still be sent to
    /// all PeerConnections. The error message will contain the ID of the failed
    /// PeerConnections so you can remove them
    fn write(&self, mut b: &[u8]) -> Result<usize> {
        let pkt = rtp::packet::Packet::unmarshal(&mut b)?;
        self.write_rtp(&pkt)?;
        Ok(b.len())
    }
}
