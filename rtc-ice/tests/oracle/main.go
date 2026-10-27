// pion/ice candidate oracle. Modes:
//   (default) read JSONL {"in": text} on stdin; UnmarshalCandidate with pion and report.
//   -gen      print a family of candidate lines (seeds for mutation), one per line, JSON strings.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pion/ice/v4"
)

type rec struct {
	In         string `json:"in"`
	Err        bool   `json:"err,omitempty"`
	Type       string `json:"type,omitempty"`
	Network    string `json:"network,omitempty"`
	Address    string `json:"addr,omitempty"`
	Port       int    `json:"port,omitempty"`
	Priority   uint32 `json:"prio,omitempty"`
	Component  uint16 `json:"comp,omitempty"`
	Foundation string `json:"found,omitempty"`
	RelAddr    string `json:"raddr,omitempty"`
	RelPort    int    `json:"rport,omitempty"`
	TCPType    string `json:"tcp,omitempty"`
	Marshal    string `json:"marshal,omitempty"`
}

func analyze(in string) rec {
	out := rec{In: in}
	c, err := ice.UnmarshalCandidate(in)
	if err != nil {
		out.Err = true
		return out
	}
	out.Type = c.Type().String()
	out.Network = c.NetworkType().String()
	out.Address = c.Address()
	out.Port = c.Port()
	out.Priority = c.Priority()
	out.Component = c.Component()
	out.Foundation = c.Foundation()
	if r := c.RelatedAddress(); r != nil {
		out.RelAddr = r.Address
		out.RelPort = r.Port
	}
	out.TCPType = c.TCPType().String()
	out.Marshal = c.Marshal()
	return out
}

var seeds = []string{
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ host",
	"candidate:1052353102 1 udp 1675624447 192.0.2.2 8080 typ host",
	"647372371 1 udp 1694498815 198.51.100.20 5002 typ srflx raddr 10.0.0.5 rport 5000",
	"647372371 1 udp 1694498815 198.51.100.20 5002 typ srflx raddr 10.0.0.5 rport 5000 generation 0 ufrag abcd network-id 1 network-cost 50",
	"2564940738 1 udp 41885695 203.0.113.9 3478 typ relay raddr 198.51.100.20 rport 5002",
	"1587339311 1 udp 1845501695 10.1.2.3 60000 typ prflx raddr 0.0.0.0 rport 0",
	"1052353102 1 tcp 1675624447 192.0.2.1 8080 typ host tcptype passive",
	"1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active",
	"1052353102 1 tcp 2128609279 192.168.0.196 9 typ host tcptype so",
	"1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype INVALID",
	"1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active generation 0",
	"1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active empty-value-1  empty-value-2 ",
	"1052353102 1 tcp 2128609279 192.168.0.196 0 typ host",
	"3052353102 2 udp 2122252543 2001:db8::1 9000 typ host",
	"3052353102 1 udp 2122252543 fe80::1%eth0 9000 typ host",
	"842163049 1 udp 1677722111 2001:db8::7 54321 typ srflx raddr 2001:db8::1 rport 9000",
	"4207374051 1 udp 2113937151 e8d2d1b5-5e0e-4d7a-9b54-0a9a0c7e2f4a.local 52001 typ host",
	" 1 udp 2113937151 192.0.2.4 5000 typ host",
	"abc 1 udp 2113937151 192.0.2.4 5000 typ host",
	"1052353102 1 UDP 1675624447 192.0.2.2 8080 typ host",
	"1052353102 1 TCP 1675624447 192.0.2.2 8080 typ host tcptype ACTIVE",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ HOST",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ host raddr 10.0.0.1 rport 1",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ srflx",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ srflx raddr 10.0.0.1",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ srflx rport 7",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ relay raddr 10.0.0.1 rport 7 ext1 v1 ext2 v2",
	"1052353102 1 udp 4294967295 192.0.2.2 65535 typ host",
	"1052353102 65535 udp 1 192.0.2.2 1 typ host",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ host   generation   2",
	"1052353102\t1\tudp\t1675624447\t192.0.2.2\t8080\ttyp\thost",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 typ",
	"1052353102 1 udp 1675624447 192.0.2.2 8080",
	"1052353102 1 udp 1675624447 192.0.2.2",
	"1052353102 1 udp",
	"1052353102",
	"",
	"candidate:",
	"1052353102 1 sctp 1675624447 192.0.2.2 8080 typ host",
	"1052353102 0 udp 1675624447 192.0.2.2 8080 typ host",
	"1052353102 1 udp 1675624447 not-an-ip 8080 typ host",
	"1052353102 1 udp 1675624447 192.0.2.2 notaport typ host",
	"1052353102 1 udp 1675624447 192.0.2.2 8080 type host",
	"1052353102 1 udp 99999999999 192.0.2.2 8080 typ host",
	"1052353102 1 udp -5 192.0.2.2 8080 typ host",
	"1052353102 1 udp 1675624447 192.0.2.2 -1 typ host",
	"1052353102 1 udp 1675624447 192.0.2.2 70000 typ host",
}

func main() {
	gen := flag.Bool("gen", false, "emit seeds")
	flag.Parse()
	if *gen {
		for _, s := range seeds {
			b, _ := json.Marshal(s)
			fmt.Println(string(b))
		}
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
		b, _ := json.Marshal(analyze(in.In))
		w.Write(b)
		w.WriteByte('\n')
	}
}
