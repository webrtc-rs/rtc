package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/sdp/v3"
	"github.com/pion/srtp/v3"
	"github.com/pion/stun/v4"
)

func report(name string, bytes int, f func(b *testing.B)) {
	r := testing.Benchmark(f)
	ns := float64(r.NsPerOp())
	mbs := ""
	if bytes > 0 {
		mbs = fmt.Sprintf(" %.0f MB/s", float64(bytes)/ns*1000)
	}
	fmt.Printf("%-34s %9.0f ns/op %5d B/op %3d allocs/op%s\n", name, ns, r.AllocedBytesPerOp(), r.AllocsPerOp(), mbs)
}

func main() {
	payload := make([]byte, 1188)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: 1000, Timestamp: 90000, SSRC: 0x1234, Extension: true, ExtensionProfile: 0xBEDE}, Payload: payload}
	_ = pkt.SetExtension(1, []byte{1, 2, 3})
	_ = pkt.SetExtension(2, []byte{4, 5})
	_ = pkt.SetExtension(3, []byte{6})
	raw, _ := pkt.Marshal()

	report("rtp unmarshal 1200B", len(raw), func(b *testing.B) {
		var p rtp.Packet
		for i := 0; i < b.N; i++ {
			_ = p.Unmarshal(raw)
		}
	})
	report("rtp unmarshal fresh 1200B", len(raw), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var p rtp.Packet
			_ = p.Unmarshal(raw)
		}
	})
	report("rtp marshal 1200B", len(raw), func(b *testing.B) {
		buf := make([]byte, 1500)
		for i := 0; i < b.N; i++ {
			_, _ = pkt.MarshalTo(buf)
		}
	})

	key := make([]byte, 16)
	salt := make([]byte, 14)
	for i := range key {
		key[i] = byte(i)
	}
	ctxE, _ := srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80)
	report("srtp cm-hmac-80 encrypt 1200B", len(raw), func(b *testing.B) {
		dst := make([]byte, 0, 1500)
		h := &rtp.Header{}
		_, _ = h.Unmarshal(raw)
		for i := 0; i < b.N; i++ {
			h.SequenceNumber = uint16(i)
			_, _ = ctxE.EncryptRTP(dst[:0], raw, h)
		}
	})
	report("srtp cm-hmac-80 encrypt alloc 1200B", len(raw), func(b *testing.B) {
		h := &rtp.Header{}
		_, _ = h.Unmarshal(raw)
		for i := 0; i < b.N; i++ {
			h.SequenceNumber = uint16(i)
			_, _ = ctxE.EncryptRTP(nil, raw, h)
		}
	})
	ctxP, _ := srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80)
	enc := make([][]byte, 0, 100000)
	{
		h := &rtp.Header{}
		_, _ = h.Unmarshal(raw)
		for i := 0; i < 65000; i++ {
			h.SequenceNumber = uint16(i)
			p := &rtp.Packet{Header: *h, Payload: payload}
			rb, _ := p.Marshal()
			e, _ := ctxP.EncryptRTP(nil, rb, nil)
			enc = append(enc, e)
		}
	}
	report("srtp cm-hmac-80 decrypt 1200B", len(raw), func(b *testing.B) {
		ctxD, _ := srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80)
		dst := make([]byte, 0, 1500)
		for i := 0; i < b.N; i++ {
			_, _ = ctxD.DecryptRTP(dst[:0], enc[i%len(enc)], nil)
			if i%len(enc) == len(enc)-1 {
				ctxD, _ = srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80)
			}
		}
	})
	ctxG, _ := srtp.CreateContext(key, salt[:12], srtp.ProtectionProfileAeadAes128Gcm)
	report("srtp gcm-128 encrypt 1200B", len(raw), func(b *testing.B) {
		dst := make([]byte, 0, 1500)
		h := &rtp.Header{}
		_, _ = h.Unmarshal(raw)
		for i := 0; i < b.N; i++ {
			h.SequenceNumber = uint16(i)
			_, _ = ctxG.EncryptRTP(dst[:0], raw, h)
		}
	})

	// STUN
	m, _ := stun.Build(stun.BindingSuccess, stun.TransactionID, &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.9"), Port: 54321}, stun.NewShortTermIntegrity("pass"), stun.Fingerprint)
	sraw := append([]byte(nil), m.Raw...)
	report("stun decode+getters+integrity", len(sraw), func(b *testing.B) {
		mm := &stun.Message{}
		var xa stun.XORMappedAddress
		for i := 0; i < b.N; i++ {
			mm.Raw = append(mm.Raw[:0], sraw...)
			_ = mm.Decode()
			_ = xa.GetFrom(mm)
			_ = stun.NewShortTermIntegrity("pass").Check(mm)
			_ = stun.Fingerprint.Check(mm)
		}
	})
	report("stun build binding request", 0, func(b *testing.B) {
		mm := &stun.Message{}
		for i := 0; i < b.N; i++ {
			_ = mm.Build(stun.TransactionID, stun.BindingRequest, stun.NewUsername("ab:cd"), stun.NewShortTermIntegrity("pass"), stun.Fingerprint)
		}
	})

	// SDP
	sdpBytes, _ := os.ReadFile(os.Args[1])
	sdpStr := string(sdpBytes)
	report("sdp unmarshal ~chrome offer", len(sdpStr), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var s sdp.SessionDescription
			_ = s.UnmarshalString(sdpStr)
		}
	})
	var parsed sdp.SessionDescription
	_ = parsed.UnmarshalString(sdpStr)
	report("sdp marshal", len(sdpStr), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = parsed.Marshal()
		}
	})
	report("sdp codec map", 0, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = parsed.GetCodecMap()
		}
	})

	// RTCP compound
	sr := rtcp.SenderReport{SSRC: 1, NTPTime: 2, RTPTime: 3, PacketCount: 4, OctetCount: 5, Reports: []rtcp.ReceptionReport{{SSRC: 9}}}
	sd := rtcp.NewCNAMESourceDescription(1, "cname")
	remb := rtcp.ReceiverEstimatedMaximumBitrate{SenderSSRC: 1, Bitrate: 1e6, SSRCs: []uint32{1, 2}}
	cp, _ := rtcp.Marshal([]rtcp.Packet{&sr, sd, &remb})
	report("rtcp unmarshal SR+SDES+REMB", len(cp), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = rtcp.Unmarshal(cp)
		}
	})

	frame := make([]byte, 30000)
	for i := range frame {
		frame[i] = byte(i * 7)
	}
	frame[0] = 0x10
	report("vp8 payload 30KB mtu1200", len(frame), func(b *testing.B) {
		p := codecs.VP8Payloader{}
		for i := 0; i < b.N; i++ {
			_ = p.Payload(1200, frame)
		}
	})
	annexb := append([]byte{0, 0, 0, 1, 0x65}, frame...)
	report("h264 payload 30KB mtu1200", len(annexb), func(b *testing.B) {
		p := codecs.H264Payloader{}
		for i := 0; i < b.N; i++ {
			_ = p.Payload(1200, annexb)
		}
	})
	_ = hex.EncodeToString

	benchDTLS()
	benchSCTP()
}
