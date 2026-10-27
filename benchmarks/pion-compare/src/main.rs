mod dtls;
mod sctp;

use bytes::{Bytes, BytesMut};
use rtc_rtp::codec::h264::H264Payloader;
use rtc_rtp::codec::vp8::Vp8Payloader;
use rtc_rtp::packet::Packet;
use rtc_rtp::packetizer::Payloader;
use rtc_srtp::context::Context;
use rtc_srtp::protection_profile::ProtectionProfile;
use rtc_stun::attributes::*;
use rtc_stun::fingerprint::FINGERPRINT;
use rtc_stun::integrity::MessageIntegrity;
use rtc_stun::message::*;
use rtc_stun::xoraddr::XorMappedAddress;
use shared::marshal::{Marshal, Unmarshal};
use std::alloc::{GlobalAlloc, Layout};

// The allocator the counting wrapper forwards to.
#[cfg(feature = "mimalloc")]
static BACKING: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(not(feature = "mimalloc"))]
static BACKING: std::alloc::System = std::alloc::System;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { BACKING.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { BACKING.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(n, Ordering::Relaxed);
        unsafe { BACKING.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

static ONLY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn bench(name: &str, bytes: usize, mut f: impl FnMut(u64)) {
    if let Some(Some(only)) = ONLY.get() {
        if !name.contains(only.as_str()) {
            return;
        }
    }
    // warm up, then size the loop to ~1s
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for i in 0..n {
            f(i);
        }
        if t.elapsed() > Duration::from_millis(200) || n > 1 << 30 {
            let per = t.elapsed().as_secs_f64() / n as f64;
            n = ((1.0 / per) as u64).max(1);
            break;
        }
        n *= 4;
    }
    let (a0, b0) = (ALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
    let t = Instant::now();
    for i in 0..n {
        f(i);
    }
    let el = t.elapsed();
    let (a1, b1) = (ALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
    let ns = el.as_nanos() as f64 / n as f64;
    let mbs = if bytes > 0 { format!(" {:.0} MB/s", bytes as f64 / ns * 1000.0) } else { String::new() };
    println!(
        "{:<34} {:>9.0} ns/op {:>5} B/op {:>3} allocs/op{}",
        name,
        ns,
        (b1 - b0) as u64 / n,
        (a1 - a0) as u64 / n,
        mbs
    );
}

fn main() {
    // `microbench [offer.sdp] [--backend ring|aws-lc-rs]`
    let mut sdp_path = concat!(env!("CARGO_MANIFEST_DIR"), "/data/offer.sdp").to_owned();
    let mut backend = "ring".to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" => backend = args.next().expect("--backend needs a value"),
            // Run only the benchmarks whose name contains this text (handy under a profiler).
            "--only" => {
                let _ = ONLY.set(Some(args.next().expect("--only needs a value")));
            }
            _ => sdp_path = arg,
        }
    }
    let provider: std::sync::Arc<dyn crypto::RTCCryptoProvider> = match backend.as_str() {
        "ring" => std::sync::Arc::new(crypto::providers::RingProvider::new()),
        #[cfg(feature = "aws-lc-rs")]
        "aws-lc-rs" => std::sync::Arc::new(crypto::providers::AwsLcRsProvider::new()),
        other => panic!("unknown or disabled backend {other:?}"),
    };
    let payload = Bytes::from((0..1188u32).map(|i| i as u8).collect::<Vec<u8>>());
    let mut pkt = Packet {
        header: rtc_rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number: 1000,
            timestamp: 90000,
            ssrc: 0x1234,
            extension: true,
            extension_profile: 0xBEDE,
            ..Default::default()
        },
        payload: payload.clone(),
    };
    pkt.header.set_extension(1, Bytes::from_static(&[1, 2, 3])).unwrap();
    pkt.header.set_extension(2, Bytes::from_static(&[4, 5])).unwrap();
    pkt.header.set_extension(3, Bytes::from_static(&[6])).unwrap();
    let raw: Bytes = pkt.marshal().unwrap().freeze();

    // pion's `Packet.Unmarshal` fills a caller-provided struct whose fields are subslices of the
    // input — no copy, no reference count. The like-for-like Rust call is the borrowed
    // `PacketView`, which is the same thing: fields plus slices of the datagram, with the header
    // and every extension element validated. The owning, reference-counted forms follow.
    bench("rtp unmarshal 1200B", raw.len(), |_| {
        let view = rtc_rtp::packet::PacketView::parse(black_box(&raw)).unwrap();
        black_box((view.ssrc(), view.payload().len(), view.extension(2)));
    });
    let mut reused = Packet::default();
    bench("rtp unmarshal reuse (Bytes) 1200B", raw.len(), |_| {
        reused.unmarshal_reuse(black_box(&raw)).unwrap();
        black_box(&reused);
    });
    bench("rtp unmarshal fresh 1200B", raw.len(), |_| {
        let mut b = raw.clone();
        black_box(Packet::unmarshal(&mut b).unwrap());
    });
    let mut buf = vec![0u8; 1500];
    bench("rtp marshal 1200B", raw.len(), |_| {
        black_box(pkt.marshal_to(&mut buf).unwrap());
    });

    let key: Vec<u8> = (0..16).collect();
    let salt: Vec<u8> = vec![0; 14];
    let mut enc = Context::new(&key, &salt, ProtectionProfile::Aes128CmHmacSha1_80, None, None, provider.crypto()).unwrap();
    let mut scratch = raw.to_vec();
    // pion's `EncryptRTP(dst, ...)` appends to a caller-provided buffer; `encrypt_rtp_into` is the
    // like-for-like call. The allocating `encrypt_rtp` is reported too.
    let mut dst = BytesMut::with_capacity(2048);
    bench("srtp cm-hmac-80 encrypt 1200B", raw.len(), |i| {
        scratch[2..4].copy_from_slice(&(i as u16).to_be_bytes());
        dst.clear();
        enc.encrypt_rtp_into(&mut dst, &scratch).unwrap();
        black_box(&dst);
    });
    bench("srtp cm-hmac-80 encrypt alloc 1200B", raw.len(), |i| {
        scratch[2..4].copy_from_slice(&(i as u16).to_be_bytes());
        black_box(enc.encrypt_rtp(&scratch).unwrap());
    });
    // encrypted stream for decrypt bench
    let mut e2 = Context::new(&key, &salt, ProtectionProfile::Aes128CmHmacSha1_80, None, None, provider.crypto()).unwrap();
    let encrypted: Vec<BytesMut> = (0..65000u32)
        .map(|i| {
            let mut p = pkt.clone();
            p.header.sequence_number = i as u16;
            e2.encrypt_rtp(&p.marshal().unwrap()).unwrap()
        })
        .collect();
    let mut dec = Context::new(&key, &salt, ProtectionProfile::Aes128CmHmacSha1_80, None, None, provider.crypto()).unwrap();
    bench("srtp cm-hmac-80 decrypt 1200B", raw.len(), |i| {
        let idx = (i as usize) % encrypted.len();
        if idx == 0 && i > 0 {
            dec = Context::new(&key, &salt, ProtectionProfile::Aes128CmHmacSha1_80, None, None, provider.crypto()).unwrap();
        }
        dst.clear();
        dec.decrypt_rtp_into(&mut dst, &encrypted[idx]).unwrap();
        black_box(&dst);
    });
    let gsalt: Vec<u8> = vec![0; 12];
    let mut genc = Context::new(&key, &gsalt, ProtectionProfile::AeadAes128Gcm, None, None, provider.crypto()).unwrap();
    bench("srtp gcm-128 encrypt 1200B", raw.len(), |i| {
        scratch[2..4].copy_from_slice(&(i as u16).to_be_bytes());
        dst.clear();
        genc.encrypt_rtp_into(&mut dst, &scratch).unwrap();
        black_box(&dst);
    });

    // STUN
    let mut m = Message::default();
    let xa = XorMappedAddress { ip: "203.0.113.9".parse().unwrap(), port: 54321 };
    let integ = MessageIntegrity::new_short_term_integrity_with_provider("pass".to_owned(), provider.crypto());
    m.build(&[Box::new(TransactionId::new()), Box::new(BINDING_SUCCESS), Box::new(xa), Box::new(integ), Box::new(FINGERPRINT)]).unwrap();
    let sraw = m.raw.clone();
    // pion decodes into one reused `Message`; so do we.
    let mut mm = Message::default();
    bench("stun decode+getters+integrity", sraw.len(), |_| {
        mm.raw.clear();
        mm.raw.extend_from_slice(&sraw);
        mm.decode().unwrap();
        let mut x = XorMappedAddress::default();
        x.get_from(&mm).unwrap();
        black_box(MessageIntegrity::check(&mut mm, b"pass", provider.crypto()).is_ok());
        black_box(FINGERPRINT.check(&mm).is_ok());
    });
    let mut built = Message::default();
    bench("stun build binding request", 0, |_| {
        let integ = MessageIntegrity::new_short_term_integrity_with_provider("pass".to_owned(), provider.crypto());
        let username = rtc_stun::textattrs::TextAttribute::new(ATTR_USERNAME, "ab:cd".to_owned());
        built
            .build_with(&[&TransactionId::new(), &BINDING_REQUEST, &username, &integ, &FINGERPRINT])
            .unwrap();
        black_box(&built);
    });

    // SDP
    let sdp = std::fs::read_to_string(&sdp_path).unwrap();
    bench("sdp unmarshal ~chrome offer", sdp.len(), |_| {
        let mut c = std::io::Cursor::new(sdp.as_bytes());
        black_box(rtc_sdp::SessionDescription::unmarshal(&mut c).unwrap());
    });
    let parsed = rtc_sdp::SessionDescription::unmarshal(&mut std::io::Cursor::new(sdp.as_bytes())).unwrap();
    bench("sdp marshal", sdp.len(), |_| {
        black_box(parsed.marshal());
    });
    bench("sdp codec map", 0, |_| {
        black_box(parsed.codec_map());
    });

    // RTCP compound
    use rtc_rtcp::{packet, receiver_report::*, reception_report::*, sender_report::*, source_description::*, payload_feedbacks::receiver_estimated_maximum_bitrate::*};
    let sr = SenderReport { ssrc: 1, ntp_time: 2, rtp_time: 3, packet_count: 4, octet_count: 5, reports: vec![ReceptionReport { ssrc: 9, ..Default::default() }], ..Default::default() };
    let sd = SourceDescription { chunks: vec![SourceDescriptionChunk { source: 1, items: vec![SourceDescriptionItem { sdes_type: SdesType::SdesCname, text: Bytes::from_static(b"cname") }] }] };
    let remb = ReceiverEstimatedMaximumBitrate { sender_ssrc: 1, bitrate: 1e6, ssrcs: vec![1, 2] };
    let pk: Vec<Box<dyn rtc_rtcp::Packet>> = vec![Box::new(sr), Box::new(sd), Box::new(remb)];
    let cp: Bytes = packet::marshal(&pk).unwrap().freeze();
    let _ = ReceiverReport::default();
    bench("rtcp unmarshal SR+SDES+REMB", cp.len(), |_| {
        let mut b = cp.clone();
        black_box(packet::unmarshal(&mut b).unwrap());
    });

    let mut frame = vec![0u8; 30000];
    for (i, b) in frame.iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    frame[0] = 0x10;
    let fb = Bytes::from(frame.clone());
    let mut vp8 = Vp8Payloader::default();
    bench("vp8 payload 30KB mtu1200", fb.len(), |_| {
        black_box(vp8.payload(1200, &fb).unwrap());
    });
    let mut annexb = vec![0, 0, 0, 1, 0x65];
    annexb.extend_from_slice(&frame);
    let ab = Bytes::from(annexb);
    let mut h264 = H264Payloader::default();
    bench("h264 payload 30KB mtu1200", ab.len(), |_| {
        black_box(h264.payload(1200, &ab).unwrap());
    });

    let dtls_cfg = dtls::Configs::new();
    bench("dtls handshake ecdsa-p256 gcm", 0, |_| {
        black_box(dtls::Pair::connect(&dtls_cfg));
    });
    let mut pair = dtls::Pair::connect(&dtls_cfg);
    let record = vec![0x5au8; 1200];
    bench("dtls app data 1200B", record.len(), |_| pair.send(&record));

    let mut assoc = sctp::Association1::new(1200);
    bench("sctp message 1200B", 1200, |_| assoc.transfer());
    let mut assoc = sctp::Association1::new(100);
    bench("sctp message 100B", 100, |_| assoc.transfer());
}
