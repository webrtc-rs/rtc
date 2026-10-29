// dnsmessage oracle for rtc-mdns. Modes:
//   (default) read JSONL {"in": hex} on stdin; Unpack with golang.org/x/net/dns/dnsmessage
//             (what pion/mdns uses) and report what it found plus the bytes a Pack produces.
//   -gen      print hex of a family of well-formed messages (seeds for mutation).
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/dns/dnsmessage"
)

type rec struct {
	In        string   `json:"in"`
	Err       string   `json:"err,omitempty"` // "unpack" when Unpack failed
	ID        uint16   `json:"id,omitempty"`
	Bits      uint16   `json:"bits,omitempty"`
	Questions []string `json:"q,omitempty"` // "name type class"
	Answers   []string `json:"an,omitempty"`
	Auths     []string `json:"ns,omitempty"`
	Adds      []string `json:"ar,omitempty"`
	Repack    string   `json:"repack,omitempty"` // hex of Pack(), or "err"
}

func bits(h dnsmessage.Header) uint16 {
	var b uint16 = uint16(h.OpCode)<<11 | uint16(h.RCode)
	if h.Response {
		b |= 1 << 15
	}
	if h.Authoritative {
		b |= 1 << 10
	}
	if h.Truncated {
		b |= 1 << 9
	}
	if h.RecursionDesired {
		b |= 1 << 8
	}
	if h.RecursionAvailable {
		b |= 1 << 7
	}
	return b
}

func res(r dnsmessage.Resource) string {
	return fmt.Sprintf("%s %d %d %d", r.Header.Name.String(), r.Header.Type, r.Header.Class, r.Header.TTL)
}

func analyze(raw []byte) rec {
	out := rec{In: hex.EncodeToString(raw)}
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		out.Err = "unpack"
		return out
	}
	out.ID = m.Header.ID
	out.Bits = bits(m.Header)
	for _, q := range m.Questions {
		out.Questions = append(out.Questions, fmt.Sprintf("%s %d %d", q.Name.String(), q.Type, q.Class))
	}
	for _, r := range m.Answers {
		out.Answers = append(out.Answers, res(r))
	}
	for _, r := range m.Authorities {
		out.Auths = append(out.Auths, res(r))
	}
	for _, r := range m.Additionals {
		out.Adds = append(out.Adds, res(r))
	}
	if packed, err := m.Pack(); err != nil {
		out.Repack = "err"
	} else {
		out.Repack = hex.EncodeToString(packed)
	}
	return out
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func hdr(n string, t dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: name(n), Type: t, Class: dnsmessage.ClassINET, TTL: 120}
}

func generate() {
	emit := func(m dnsmessage.Message) {
		b, err := m.Pack()
		if err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(b))
	}
	q := func(n string, t dnsmessage.Type) dnsmessage.Question {
		return dnsmessage.Question{Name: name(n), Type: t, Class: dnsmessage.ClassINET}
	}
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR, dnsmessage.TypeSRV, dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypeNS, dnsmessage.TypeSOA, dnsmessage.TypeCNAME, dnsmessage.TypeALL} {
		emit(dnsmessage.Message{Questions: []dnsmessage.Question{q("host.local.", t)}})
	}
	emit(dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{q("host.local.", dnsmessage.TypeA), q("other.example.com.", dnsmessage.TypeAAAA)}})
	answers := []dnsmessage.Resource{
		{Header: hdr("host.local.", dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 7}}},
		{Header: hdr("host.local.", dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0xd, 0xb8, 15: 1}}},
		{Header: hdr("_svc._tcp.local.", dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: name("inst._svc._tcp.local.")}},
		{Header: hdr("inst._svc._tcp.local.", dnsmessage.TypeSRV), Body: &dnsmessage.SRVResource{Priority: 1, Weight: 2, Port: 8080, Target: name("host.local.")}},
		{Header: hdr("inst._svc._tcp.local.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{"a=b", "path=/", ""}}},
		{Header: hdr("local.", dnsmessage.TypeMX), Body: &dnsmessage.MXResource{Pref: 10, MX: name("mail.local.")}},
		{Header: hdr("local.", dnsmessage.TypeNS), Body: &dnsmessage.NSResource{NS: name("ns.local.")}},
		{Header: hdr("alias.local.", dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: name("host.local.")}},
		{Header: hdr("local.", dnsmessage.TypeSOA), Body: &dnsmessage.SOAResource{NS: name("ns.local."), MBox: name("admin.local."), Serial: 1, Refresh: 2, Retry: 3, Expire: 4, MinTTL: 5}},
		{Header: hdr("host.local.", dnsmessage.Type(65280)), Body: &dnsmessage.UnknownResource{Type: dnsmessage.Type(65280), Data: []byte{1, 2, 3, 4}}},
	}
	for _, a := range answers {
		emit(dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{a}})
	}
	emit(dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Questions: []dnsmessage.Question{q("host.local.", dnsmessage.TypeA)}, Answers: answers[:4]})
	emit(dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: answers[:3], Authorities: answers[5:7], Additionals: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name("."), Type: dnsmessage.TypeOPT, Class: 4096}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}}},
	}})
	emit(dnsmessage.Message{Header: dnsmessage.Header{ID: 7, OpCode: 2, RCode: dnsmessage.RCodeNameError, RecursionDesired: true, RecursionAvailable: true, Truncated: true}})
}

func main() {
	gen := flag.Bool("gen", false, "emit seed messages")
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
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
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
