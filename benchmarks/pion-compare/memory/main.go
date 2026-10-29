package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

func used() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse + m.StackInuse
}

func newPC() *webrtc.PeerConnection {
	se := webrtc.SettingEngine{}
	se.SetICEMulticastDNSMode(0)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		panic(err)
	}
	return pc
}

func main() {
	pairs := 200
	if len(os.Args) > 1 {
		pairs, _ = strconv.Atoi(os.Args[1])
	}
	// warm
	func() {
		a, b := newPC(), newPC()
		connect(a, b)
		a.Close()
		b.Close()
	}()
	base := used()
	var all []*webrtc.PeerConnection
	var idle []*webrtc.PeerConnection
	for i := 0; i < pairs*2; i++ {
		idle = append(idle, newPC())
	}
	idleBytes := used() - base
	for i := 0; i < pairs; i++ {
		a, b := idle[2*i], idle[2*i+1]
		connect(a, b)
		all = append(all, a, b)
	}
	connBytes := used() - base
	fmt.Printf("pion memory_per_connection: pairs=%d idle=%.1f KiB/pc connected+datachannel=%.1f KiB/pc\n",
		pairs, float64(idleBytes)/float64(2*pairs)/1024, float64(connBytes)/float64(2*pairs)/1024)
	runtime.KeepAlive(all)
}

func connect(a, b *webrtc.PeerConnection) {
	var wg sync.WaitGroup
	wg.Add(2)
	b.OnDataChannel(func(d *webrtc.DataChannel) { d.OnOpen(func() { wg.Done() }) })
	dc, err := a.CreateDataChannel("d", nil)
	if err != nil {
		panic(err)
	}
	dc.OnOpen(func() { wg.Done() })
	a.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = b.AddICECandidate(c.ToJSON())
		}
	})
	b.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = a.AddICECandidate(c.ToJSON())
		}
	})
	offer, _ := a.CreateOffer(nil)
	_ = a.SetLocalDescription(offer)
	_ = b.SetRemoteDescription(offer)
	ans, _ := b.CreateAnswer(nil)
	_ = b.SetLocalDescription(ans)
	_ = a.SetRemoteDescription(ans)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		panic("connect timeout")
	}
}
