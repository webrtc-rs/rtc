// Command soak-pion is the pion half of the soak harness (see ../README.md): one WebRTC peer that
// sends audio, video and data and logs what it receives as JSONL.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

const (
	reportEvery      = 5 * time.Second
	patientICEFailed = 240 * time.Second // the abuse profile's longest outage is 120 s, a trace's stall 78 s
)

type signalMsg struct {
	SDP        webrtc.SessionDescription `json:"sdp"`
	Candidates []webrtc.ICECandidateInit `json:"candidates"`
}

func writeFrame(c net.Conn, m signalMsg) error { return writeJSONFrame(c, m) }

func readFrame(c net.Conn) (m signalMsg, err error) { return m, readJSONFrame(c, &m) }

func writeJSONFrame(c net.Conn, m any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, err = c.Write(append(n[:], b...))
	return err
}

func readJSONFrame(c net.Conn, m any) error {
	var n [4]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return err
	}
	b := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	return json.Unmarshal(b, m)
}

// rendezvous: the offerer listens on addr and the answerer dials it; each sends one framed message.
func rendezvous(role, addr string) (net.Conn, error) {
	if role == "offerer" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		defer ln.Close()
		return ln.Accept()
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil || time.Now().After(deadline) {
			return c, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func main() {
	role := flag.String("role", "offerer", "offerer or answerer")
	addr := flag.String("signal", "127.0.0.1:7100", "rendezvous address (the offerer listens)")
	minutes := flag.Float64("minutes", 1, "how long to run once connected")
	out := flag.String("out", "pion.jsonl", "JSONL file to append to")
	id := flag.String("id", "", "peer id (default pion-<role>)")
	profile := flag.String("profile", "call", "call; abuse: hostile connections and traffic next to the call; trace: the call over a recorded link (patient ICE)")
	seed := flag.Uint64("seed", 1, "seed of the abuse profile's schedule")
	only := flag.String("only", "", "abuse profile: only these attack classes (comma separated)")
	flag.Parse()
	if *profile != "call" && *profile != "abuse" && *profile != "trace" {
		fmt.Fprintln(os.Stderr, "soak-pion: --profile is call, abuse or trace")
		os.Exit(2)
	}
	if *id == "" {
		*id = "pion-" + *role
	}
	log, err := newLogger(*out, *id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *profile == "abuse" {
		log.event("seed", fmt.Sprintf("profile abuse seed %d", *seed))
	}
	ab := abuseOpts{enabled: *profile == "abuse", seed: *seed, only: *only, out: *out, signal: *addr}
	if err := run(log, *role, *addr, *id, time.Duration(*minutes*float64(time.Minute)), *profile != "call", ab); err != nil {
		log.event("error", err.Error())
		fmt.Fprintln(os.Stderr, "soak-pion:", err)
		os.Exit(1)
	}
}

var (
	opusCap = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"}
	vp8Cap  = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000,
		RTCPFeedback: []webrtc.RTCPFeedback{{Type: "nack"}, {Type: "nack", Parameter: "pli"}}}
)

// newPeerConnection builds a peer connection with the soak's codecs, header extension and the
// library's default interceptors, over loopback host candidates only.
// A patient one lets ICE ride out a long outage (the measured call of the abuse profile, whose
// network goes down for up to two minutes, and of the trace profile, whose recorded links stall
// for over a minute) instead of failing after 25 s.
func newPeerConnection(patient bool) (*webrtc.PeerConnection, error) {
	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opusCap, PayloadType: 111}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: vp8Cap, PayloadType: 96}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, err
	}
	if err := me.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: audioLevelURI}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return nil, err
	}
	se := webrtc.SettingEngine{}
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetIncludeLoopbackCandidate(true)
	se.SetInterfaceFilter(func(n string) bool { return n == "lo" || n == "lo0" })
	if patient {
		se.SetICETimeouts(5*time.Second, patientICEFailed, 2*time.Second)
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se))
	return api.NewPeerConnection(webrtc.Configuration{})
}

// patient: ICE rides out long outages (the abuse and trace profiles).
func run(log *logger, role, addr, id string, dur time.Duration, patient bool, ab abuseOpts) error {
	pc, err := newPeerConnection(patient)
	if err != nil {
		return err
	}
	defer pc.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	failed := make(chan struct{})
	connected := make(chan struct{})
	var once sync.Once
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) { log.event("ice_state", s.String()) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		switch s {
		case webrtc.PeerConnectionStateConnected:
			once.Do(func() { close(connected) })
		case webrtc.PeerConnectionStateFailed:
			close(failed)
		}
	})

	audio, err := webrtc.NewTrackLocalStaticRTP(opusCap, "audio", "soak")
	if err != nil {
		return err
	}
	video, err := webrtc.NewTrackLocalStaticRTP(vp8Cap, "video", "soak")
	if err != nil {
		return err
	}
	var keyframe atomic.Bool
	audioSender, err := pc.AddTrack(audio)
	if err != nil {
		return err
	}
	videoSender, err := pc.AddTrack(video)
	if err != nil {
		return err
	}
	go drainRTCP(audioSender, nil)
	go drainRTCP(videoSender, &keyframe)

	stats := map[string]*recvStats{}
	var statsMu sync.Mutex
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		media := tr.Kind().String()
		rs := newRecvStats(log, media, tr.Codec().ClockRate)
		statsMu.Lock()
		stats[media] = rs
		statsMu.Unlock()
		for {
			p, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			if rs.onPacket(time.Now(), p.SequenceNumber, p.Timestamp, p.Marker) {
				_ = pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(tr.SSRC())}})
			}
		}
	})

	dcs := &dcState{lat: make(chan float64, 4096)}
	neg, dcID := true, uint16(1)
	dc, err := pc.CreateDataChannel("soak", &webrtc.DataChannelInit{Negotiated: &neg, ID: &dcID})
	if err != nil {
		return err
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) { onData(dcs, m) })
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })

	remotePorts, err := negotiate(pc, role, addr)
	if err != nil {
		return err
	}
	select {
	case <-connected:
	case <-time.After(60 * time.Second):
		return fmt.Errorf("not connected after 60 s")
	case <-ctx.Done():
		return nil
	}
	log.event("join", "connected")
	runCtx, stop := context.WithTimeout(ctx, dur)
	defer stop()
	if ab.enabled {
		defer startAbuse(runCtx, ab, role, id, remotePorts).stop()
	}
	go sendAudio(runCtx, log, audio, audioSender)
	go sendVideo(runCtx, log, video, &keyframe)
	go func() {
		select {
		case <-opened:
			sendData(runCtx, dc, dcs)
		case <-runCtx.Done():
		}
	}()

	proc := &procSampler{}
	tick := time.NewTicker(reportEvery)
	defer tick.Stop()
	report := func() {
		now := time.Now()
		nack, pli, rtt := map[string]uint32{}, map[string]uint32{}, map[string]any{}
		for _, s := range pc.GetStats() {
			switch v := s.(type) {
			case webrtc.InboundRTPStreamStats:
				nack[v.Kind], pli[v.Kind] = v.NACKCount, v.PLICount
			case webrtc.RemoteInboundRTPStreamStats:
				if v.RoundTripTime > 0 {
					rtt[v.Kind] = round1(v.RoundTripTime * 1000)
				}
			}
		}
		statsMu.Lock()
		for media, rs := range stats {
			r, ok := rtt[media]
			if !ok {
				r = nil
			}
			log.emit("recv", id+"-"+media, rs.snapshot(now, nack[media], pli[media], r))
		}
		statsMu.Unlock()
		log.emit("proc", id, proc.sample())
		var window []float64
		for drained := false; !drained; {
			select {
			case v := <-dcs.lat:
				window = append(window, v)
			default:
				drained = true
			}
		}
		log.emit("dc", id, map[string]any{"sent": dcs.sent.Load(), "recv": dcs.recv.Load(),
			"lat_ms_p50": percentile(window, 50), "lat_ms_p99": percentile(window, 99)})
	}
	for {
		select {
		case <-tick.C:
			report()
		case <-failed:
			report()
			return fmt.Errorf("peer connection failed")
		case <-runCtx.Done():
			report()
			log.event("leave", "done")
			return nil
		}
	}
}

func negotiate(pc *webrtc.PeerConnection, role, addr string) ([]uint16, error) {
	var cands []webrtc.ICECandidateInit
	var mu sync.Mutex
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			mu.Lock()
			cands = append(cands, c.ToJSON())
			mu.Unlock()
		}
	})
	conn, err := rendezvous(role, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local := func(d webrtc.SessionDescription, err error) (signalMsg, error) {
		if err != nil {
			return signalMsg{}, err
		}
		gathered := webrtc.GatheringCompletePromise(pc)
		if err := pc.SetLocalDescription(d); err != nil {
			return signalMsg{}, err
		}
		<-gathered
		mu.Lock()
		defer mu.Unlock()
		return signalMsg{SDP: *pc.LocalDescription(), Candidates: cands}, nil
	}
	apply := func(m signalMsg) error {
		if err := pc.SetRemoteDescription(m.SDP); err != nil {
			return err
		}
		for _, c := range m.Candidates {
			if err := pc.AddICECandidate(c); err != nil {
				return err
			}
		}
		return nil
	}
	if role == "offerer" {
		m, err := local(pc.CreateOffer(nil))
		if err != nil {
			return nil, err
		}
		if err := writeFrame(conn, m); err != nil {
			return nil, err
		}
		ans, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		return candidatePorts(ans.Candidates), apply(ans)
	}
	offer, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if err := apply(offer); err != nil {
		return nil, err
	}
	m, err := local(pc.CreateAnswer(nil))
	if err != nil {
		return nil, err
	}
	return candidatePorts(offer.Candidates), writeFrame(conn, m)
}

// candidatePorts are the ports of signaled candidate lines
// ("candidate:1 1 udp 2130706431 127.0.0.1 40000 typ host").
func candidatePorts(cs []webrtc.ICECandidateInit) []uint16 {
	var ports []uint16
	for _, c := range cs {
		if f := strings.Fields(c.Candidate); len(f) > 5 {
			if n, err := strconv.ParseUint(f[5], 10, 16); err == nil {
				ports = append(ports, uint16(n))
			}
		}
	}
	return ports
}
