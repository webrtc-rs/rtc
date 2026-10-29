// pion/stun oracle. Modes:
//   (default) read JSONL {"in": hex} on stdin; decode with pion and report.
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

	"github.com/pion/stun/v4"
)

type rec struct {
	In     string            `json:"in"`
	Err    string            `json:"err,omitempty"`
	Typ    string            `json:"typ,omitempty"`
	Len    int               `json:"len,omitempty"`
	TID    string            `json:"tid,omitempty"`
	Attrs  [][2]string       `json:"attrs,omitempty"`
	FP     string            `json:"fp,omitempty"`  // fingerprint check: "ok" or "err"
	MI     string            `json:"mi,omitempty"`  // short-term integrity check with key "pass"
	Typed  map[string]string `json:"typed,omitempty"`
	ReEnc  string            `json:"reenc,omitempty"`
}

func ok(err error) string {
	if err == nil {
		return "ok"
	}
	return "err"
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
		var r rec
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		raw, _ := hex.DecodeString(r.In)
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.Err = fmt.Sprintf("PANIC: %v", p)
				}
			}()
			analyze(&r, raw)
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}

func analyze(r *rec, raw []byte) {
	m := &stun.Message{Raw: append([]byte(nil), raw...)}
	if err := m.Decode(); err != nil {
		r.Err = err.Error()
		return
	}
	r.Typ = fmt.Sprintf("%04x", m.Type.Value())
	r.Len = int(m.Length)
	r.TID = hex.EncodeToString(m.TransactionID[:])
	for _, a := range m.Attributes {
		r.Attrs = append(r.Attrs, [2]string{fmt.Sprintf("%04x", uint16(a.Type)), hex.EncodeToString(a.Value)})
	}
	r.FP = ok(stun.Fingerprint.Check(m))
	r.MI = ok(stun.NewShortTermIntegrity("pass").Check(m))
	r.Typed = map[string]string{}
	var xa stun.XORMappedAddress
	if err := xa.GetFrom(m); err == nil {
		r.Typed["xor-mapped"] = (&net.UDPAddr{IP: xa.IP, Port: xa.Port}).String()
	} else if m.Contains(stun.AttrXORMappedAddress) {
		r.Typed["xor-mapped"] = "err"
	}
	var ma stun.MappedAddress
	if err := ma.GetFrom(m); err == nil {
		r.Typed["mapped"] = (&net.UDPAddr{IP: ma.IP, Port: ma.Port}).String()
	} else if m.Contains(stun.AttrMappedAddress) {
		r.Typed["mapped"] = "err"
	}
	var ec stun.ErrorCodeAttribute
	if err := ec.GetFrom(m); err == nil {
		r.Typed["error"] = fmt.Sprintf("%d %s", ec.Code, hex.EncodeToString(ec.Reason))
	} else if m.Contains(stun.AttrErrorCode) {
		r.Typed["error"] = "err"
	}
	var u stun.Username
	if m.Contains(stun.AttrUsername) {
		r.Typed["username"] = ok(u.GetFrom(m)) + ":" + hex.EncodeToString([]byte(u))
	}
	var re stun.Realm
	if m.Contains(stun.AttrRealm) {
		r.Typed["realm"] = ok(re.GetFrom(m)) + ":" + hex.EncodeToString([]byte(re))
	}
	var no stun.Nonce
	if m.Contains(stun.AttrNonce) {
		r.Typed["nonce"] = ok(no.GetFrom(m)) + ":" + hex.EncodeToString([]byte(no))
	}
	var sw stun.Software
	if m.Contains(stun.AttrSoftware) {
		r.Typed["software"] = ok(sw.GetFrom(m)) + ":" + hex.EncodeToString([]byte(sw))
	}
	var ua stun.UnknownAttributes
	if m.Contains(stun.AttrUnknownAttributes) {
		err := ua.GetFrom(m)
		s := ok(err)
		for _, a := range ua {
			s += fmt.Sprintf(",%04x", uint16(a))
		}
		r.Typed["unknown"] = s
	}
	// Re-encoding the decoded message must reproduce the same bytes.
	m2 := &stun.Message{}
	m2.Type = m.Type
	m2.TransactionID = m.TransactionID
	m2.WriteHeader()
	for _, a := range m.Attributes {
		m2.Add(a.Type, a.Value)
	}
	r.ReEnc = hex.EncodeToString(m2.Raw)
}

func generate() {
	emit := func(m *stun.Message, err error) {
		if err != nil {
			return
		}
		fmt.Println(hex.EncodeToString(m.Raw))
	}
	id := stun.TransactionID
	addr := &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.9"), Port: 54321}
	addr6 := &stun.XORMappedAddress{IP: net.ParseIP("2001:db8::7"), Port: 3478}
	emit(stun.Build(stun.BindingRequest, id))
	emit(stun.Build(stun.BindingRequest, id, stun.Fingerprint))
	emit(stun.Build(stun.BindingRequest, id, stun.NewUsername("ab:cd"), stun.NewSoftware("pion"), stun.NewShortTermIntegrity("pass"), stun.Fingerprint))
	emit(stun.Build(stun.BindingSuccess, id, addr, stun.NewShortTermIntegrity("pass"), stun.Fingerprint))
	emit(stun.Build(stun.BindingSuccess, id, addr6))
	emit(stun.Build(stun.BindingSuccess, id, &stun.MappedAddress{IP: net.ParseIP("198.51.100.1"), Port: 9}))
	emit(stun.Build(stun.NewType(stun.MethodBinding, stun.ClassErrorResponse), id, stun.ErrorCodeAttribute{Code: 401, Reason: []byte("Unauthorized")}, stun.NewRealm("example.org"), stun.NewNonce("nonce-1")))
	emit(stun.Build(stun.NewType(stun.MethodBinding, stun.ClassErrorResponse), id, stun.CodeBadRequest, stun.UnknownAttributes{stun.AttrPriority, stun.AttrUseCandidate}))
	emit(stun.Build(stun.NewType(stun.MethodAllocate, stun.ClassRequest), id, stun.NewUsername("user"), stun.NewRealm("r"), stun.NewNonce("n"), stun.NewLongTermIntegrity("user", "r", "p")))
	emit(stun.Build(stun.BindingRequest, id,
		stun.RawAttribute{Type: stun.AttrPriority, Value: []byte{0, 0, 0, 0x6e}},
		stun.RawAttribute{Type: stun.AttrUseCandidate},
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}}))
	for _, name := range []string{"", "a", "ab", "abc", "abcd", "abcde"} {
		emit(stun.Build(stun.BindingRequest, id, stun.NewUsername(name), stun.NewSoftware(name)))
	}
}
