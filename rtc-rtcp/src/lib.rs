#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! Package rtcp implements encoding and decoding of RTCP packets according to RFCs 3550 and 5506.
//!
//! RTCP is a sister protocol of the Real-time Transport Protocol (RTP). Its basic functionality
//! and packet structure is defined in RFC 3550. RTCP provides out-of-band statistics and control
//! information for an RTP session. It partners with RTP in the delivery and packaging of multimedia data,
//! but does not transport any media data itself.
//!
//! The primary function of RTCP is to provide feedback on the quality of service (QoS)
//! in media distribution by periodically sending statistics information such as transmitted octet
//! and packet counts, packet loss, packet delay variation, and round-trip delay time to participants
//! in a streaming multimedia session. An application may use this information to control quality of
//! service parameters, perhaps by limiting flow, or using a different codec.
//!
//! Decoding RTCP packets:
//!```nobuild
//!     let pkt = rtcp::unmarshal(&rtcp_data).unwrap();
//!
//!     if let Some(e) = pkt
//!          .as_any()
//!          .downcast_ref::<PictureLossIndication>()
//!      {
//!
//!      }
//!     else if let Some(e) = packet
//!          .as_any()
//!          .downcast_ref::<Goodbye>(){}
//!     ....
//!```
//!
//! Encoding RTCP packets:
//!```nobuild
//!     let pkt = PictureLossIndication{
//!         sender_ssrc: sender_ssrc,
//!         media_ssrc: media_ssrc
//!     };
//!
//!     let pli_data = pkt.marshal().unwrap();
//!     // ...
//!```

/// Compound RTCP packets — the several reports that share one datagram.
pub mod compound_packet;
/// Extended reports (XR, [RFC 3611]): loss/discard run lengths, receipt times and per-block
/// statistics.
///
/// [RFC 3611]: https://datatracker.ietf.org/doc/html/rfc3611
pub mod extended_report;
/// The BYE packet, by which a source announces it is leaving.
pub mod goodbye;
/// The four-byte header common to every RTCP packet.
pub mod header;
/// The [`Packet`] trait every RTCP packet type implements.
pub mod packet;
/// Payload-specific feedback (PT 206): PLI, FIR, SLI and REMB.
pub mod payload_feedbacks;
/// An unparsed packet, used for types this crate does not model.
pub mod raw_packet;
/// The Receiver Report (RR), which reports reception quality back to a sender.
pub mod receiver_report;
/// The reception report block carried inside SR and RR packets.
pub mod reception_report;
/// The Sender Report (SR), which carries a sender's timing and packet counts.
pub mod sender_report;
/// The SDES packet, which carries CNAME and other source metadata.
pub mod source_description;
/// Transport-specific feedback (PT 205): NACK and transport-wide congestion control.
pub mod transport_feedbacks;
mod util;

pub use header::Header;
pub use packet::Packet;
