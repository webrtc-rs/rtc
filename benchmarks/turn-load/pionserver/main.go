// A pion/turn server for the benchmark: one UDP listener, long-term credentials, relays on
// 127.0.0.1. Run it exactly as the Rust example is run, so the load generator sees the same thing.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pion/turn/v5"
)

func main() {
	port := flag.Int("port", 3478, "UDP port")
	user := flag.String("user", "user", "username")
	pass := flag.String("pass", "pass", "password")
	flag.Parse()

	conn, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		panic(err)
	}
	const realm = "webrtc.rs"
	key := turn.GenerateAuthKey(*user, realm, *pass)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == *user {
				return ra.Username, key, true
			}
			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("ready")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = server.Close()
}
