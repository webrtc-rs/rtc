// A TURN load generator: it allocates relays on a server, and for each sends packets to a local
// echo peer through the relay, waiting for the echoes to come back through it. It reports what got
// through and how long it took; the server's CPU is measured by whoever runs it (run.py).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func main() {
	server := flag.String("server", "127.0.0.1:3478", "TURN server")
	user := flag.String("user", "user", "username")
	pass := flag.String("pass", "pass", "password")
	relays := flag.Int("relays", 20, "allocations")
	packets := flag.Int("packets", 5000, "packets per allocation")
	size := flag.Int("size", 1200, "payload bytes")
	window := flag.Int("window", 32, "packets in flight per allocation")
	flag.Parse()

	var delivered atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *relays; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				panic(err)
			}
			defer conn.Close()
			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: *server,
				TURNServerAddr: *server,
				Conn:           conn,
				Username:       *user,
				Password:       *pass,
				Realm:          "webrtc.rs",
				LoggerFactory:  logging.NewDefaultLoggerFactory(),
			})
			if err != nil {
				panic(err)
			}
			defer client.Close()
			if err := client.Listen(); err != nil {
				panic(err)
			}
			relay, err := client.Allocate()
			if err != nil {
				fmt.Fprintln(os.Stderr, "allocate:", err)
				return
			}
			defer relay.Close()

			// The peer echoes whatever reaches it back to the relay.
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				panic(err)
			}
			defer peer.Close()
			go func() {
				buf := make([]byte, 2048)
				for {
					n, from, err := peer.ReadFrom(buf)
					if err != nil {
						return
					}
					_, _ = peer.WriteTo(buf[:n], from)
				}
			}()

			payload := make([]byte, *size)
			credits := make(chan struct{}, *window)
			for j := 0; j < *window; j++ {
				credits <- struct{}{}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 2048)
				for got := 0; got < *packets; got++ {
					_ = relay.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, _, err := relay.ReadFrom(buf); err != nil {
						return
					}
					delivered.Add(1)
					credits <- struct{}{}
				}
			}()
			for j := 0; j < *packets; j++ {
				select {
				case <-credits:
				case <-done:
					return
				}
				if _, err := relay.WriteTo(payload, peer.LocalAddr()); err != nil {
					return
				}
			}
			<-done
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	total := int64(*relays) * int64(*packets)
	fmt.Printf("delivered=%d of %d elapsed=%.3fs rate=%.0f pkt/s\n", delivered.Load(), total, elapsed.Seconds(), float64(delivered.Load())/elapsed.Seconds())
}
