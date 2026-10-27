// pion/turn protocol oracle. Modes:
//   (default) read JSONL {"in": hex} on stdin; classify the datagram the way a TURN peer does
//             (STUN message, ChannelData, or neither) and report what pion's proto package finds.
//   -gen      print hex of a family of well-formed messages (seeds for mutation).
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun/v4"

	"turn-oracle/proto"
)

type rec struct {
	In    string            `json:"in"`
	Kind  string            `json:"kind"`                // stun | chandata | none
	Err   string            `json:"err,omitempty"`       // decode failed
	Attrs map[string]string `json:"attrs,omitempty"`     // stun: attribute -> "absent" | "err" | "ok <value>"
	Num   int               `json:"num,omitempty"`       // chandata
	Data  string            `json:"data,omitempty"`      // chandata payload hex
	ReEnc string            `json:"reenc,omitempty"`     // chandata re-encoded hex
}

func addr(ip net.IP, port int) string { return fmt.Sprintf("%s:%d", ip.String(), port) }

func attrs(m *stun.Message) map[string]string {
	out := map[string]string{}
	set := func(name string, has bool, f func() (string, error)) {
		if !has {
			out[name] = "absent"
			return
		}
		v, err := f()
		if err != nil {
			out[name] = "err"
			return
		}
		out[name] = "ok " + v
	}
	set("channel-number", m.Contains(stun.AttrChannelNumber), func() (string, error) {
		var n proto.ChannelNumber
		err := n.GetFrom(m)
		return n.String(), err
	})
	set("lifetime", m.Contains(stun.AttrLifetime), func() (string, error) {
		var l proto.Lifetime
		err := l.GetFrom(m)
		return fmt.Sprintf("%d", int64(l.Duration/time.Second)), err
	})
	set("data", m.Contains(stun.AttrData), func() (string, error) {
		var d proto.Data
		err := d.GetFrom(m)
		return hex.EncodeToString(d), err
	})
	set("even-port", m.Contains(stun.AttrEvenPort), func() (string, error) {
		var e proto.EvenPort
		err := e.GetFrom(m)
		return fmt.Sprintf("%v", e.ReservePort), err
	})
	set("requested-transport", m.Contains(stun.AttrRequestedTransport), func() (string, error) {
		var r proto.RequestedTransport
		err := r.GetFrom(m)
		return fmt.Sprintf("%d", r.Protocol), err
	})
	set("requested-family", m.Contains(stun.AttrRequestedAddressFamily), func() (string, error) {
		var f proto.RequestedAddressFamily
		err := f.GetFrom(m)
		return fmt.Sprintf("%d", byte(f)), err
	})
	set("reservation-token", m.Contains(stun.AttrReservationToken), func() (string, error) {
		var t proto.ReservationToken
		err := t.GetFrom(m)
		return hex.EncodeToString(t), err
	})
	set("dont-fragment", m.Contains(stun.AttrDontFragment), func() (string, error) {
		var d proto.DontFragment
		return "", d.GetFrom(m)
	})
	set("peer-address", m.Contains(stun.AttrXORPeerAddress), func() (string, error) {
		var a proto.PeerAddress
		err := a.GetFrom(m)
		return addr(a.IP, a.Port), err
	})
	set("relayed-address", m.Contains(stun.AttrXORRelayedAddress), func() (string, error) {
		var a proto.RelayedAddress
		err := a.GetFrom(m)
		return addr(a.IP, a.Port), err
	})
	set("connection-id", m.Contains(stun.AttrConnectionID), func() (string, error) {
		var c proto.ConnectionID
		err := c.GetFrom(m)
		return fmt.Sprintf("%d", uint32(c)), err
	})
	return out
}

func analyze(raw []byte) rec {
	out := rec{In: hex.EncodeToString(raw)}
	switch {
	case stun.IsMessage(raw):
		out.Kind = "stun"
		m := &stun.Message{Raw: append([]byte(nil), raw...)}
		if err := m.Decode(); err != nil {
			out.Err = "decode"
			return out
		}
		out.Attrs = attrs(m)
	case proto.IsChannelData(raw):
		out.Kind = "chandata"
		c := &proto.ChannelData{Raw: append([]byte(nil), raw...)}
		if err := c.Decode(); err != nil {
			out.Err = "decode"
			return out
		}
		out.Num = int(c.Number)
		out.Data = hex.EncodeToString(c.Data)
		c.Encode()
		out.ReEnc = hex.EncodeToString(c.Raw)
	default:
		out.Kind = "none"
	}
	return out
}

func build(setters ...stun.Setter) []byte {
	m := new(stun.Message)
	all := append([]stun.Setter{stun.NewTransactionIDSetter([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})}, setters...)
	if err := m.Build(all...); err != nil {
		panic(err)
	}
	return m.Raw
}

func generate() {
	emit := func(b []byte) { fmt.Println(hex.EncodeToString(b)) }
	typ := func(method stun.Method, class stun.MessageClass) stun.Setter {
		return stun.NewType(method, class)
	}
	v4 := net.IPv4(203, 0, 113, 9).To4()
	v6 := net.ParseIP("2001:db8::7")
	emit(build(typ(stun.MethodAllocate, stun.ClassRequest), proto.RequestedTransport{Protocol: proto.ProtoUDP}))
	emit(build(typ(stun.MethodAllocate, stun.ClassRequest), proto.RequestedTransport{Protocol: proto.ProtoTCP}, proto.EvenPort{ReservePort: true}))
	emit(build(typ(stun.MethodAllocate, stun.ClassRequest), proto.RequestedTransport{Protocol: proto.ProtoUDP}, proto.ReservationToken([]byte{1, 2, 3, 4, 5, 6, 7, 8})))
	emit(build(typ(stun.MethodAllocate, stun.ClassRequest), proto.RequestedTransport{Protocol: proto.ProtoUDP}, proto.RequestedFamilyIPv6, proto.DontFragment{}, proto.Lifetime{Duration: 600 * time.Second}))
	emit(build(typ(stun.MethodAllocate, stun.ClassSuccessResponse), proto.RelayedAddress{IP: v4, Port: 49152}, proto.Lifetime{Duration: 600 * time.Second}))
	emit(build(typ(stun.MethodAllocate, stun.ClassSuccessResponse), proto.RelayedAddress{IP: v6, Port: 49152}))
	emit(build(typ(stun.MethodRefresh, stun.ClassRequest), proto.Lifetime{Duration: 0}))
	emit(build(typ(stun.MethodCreatePermission, stun.ClassRequest), proto.PeerAddress{IP: v4, Port: 5000}, proto.PeerAddress{IP: v6, Port: 5001}))
	emit(build(typ(stun.MethodChannelBind, stun.ClassRequest), proto.ChannelNumber(0x4001), proto.PeerAddress{IP: v4, Port: 5000}))
	emit(build(typ(stun.MethodSend, stun.ClassIndication), proto.PeerAddress{IP: v4, Port: 5000}, proto.Data([]byte("hello"))))
	emit(build(typ(stun.MethodData, stun.ClassIndication), proto.PeerAddress{IP: v6, Port: 5000}, proto.Data(make([]byte, 33))))
	emit(build(typ(stun.MethodConnect, stun.ClassRequest), proto.PeerAddress{IP: v4, Port: 5000}))
	emit(build(typ(stun.MethodConnect, stun.ClassSuccessResponse), proto.ConnectionID(0xdeadbeef)))
	emit(build(typ(stun.MethodConnectionBind, stun.ClassRequest), proto.ConnectionID(1)))
	emit(build(typ(stun.MethodConnectionAttempt, stun.ClassIndication), proto.ConnectionID(7), proto.PeerAddress{IP: v4, Port: 80}))
	for _, payload := range [][]byte{{}, {1}, {1, 2, 3, 4}, make([]byte, 5), make([]byte, 100)} {
		c := &proto.ChannelData{Data: payload, Number: 0x4000}
		c.Encode()
		emit(c.Raw)
		c = &proto.ChannelData{Data: payload, Number: 0x7fff}
		c.Encode()
		emit(c.Raw)
	}
}

func main() {
	gen := flag.Bool("gen", false, "emit seeds")
	flag.Parse()
	if *gen {
		generate()
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var in struct {
			In string `json:"in"`
		}
		if json.Unmarshal(sc.Bytes(), &in) != nil {
			continue
		}
		raw, err := hex.DecodeString(in.In)
		if err != nil {
			continue
		}
		b, _ := json.Marshal(analyze(raw))
		w.Write(b)
		w.WriteByte('\n')
	}
}
