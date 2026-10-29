// Reads JSONL {"profile","op","in"(hex)}; runs pion/srtp with a fixed master key and salt.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pion/srtp/v3"
)

type rec struct {
	Profile int    `json:"profile"`
	Op      string `json:"op"`
	In      string `json:"in"`
	Err     string `json:"err,omitempty"`
	Out     string `json:"out,omitempty"`
}

func keys(p srtp.ProtectionProfile) (key, salt []byte) {
	kl, _ := p.KeyLen()
	sl, _ := p.SaltLen()
	key = make([]byte, kl)
	for i := range key {
		key[i] = byte(i)
	}
	salt = make([]byte, sl)
	for i := range salt {
		salt[i] = byte(0x10 + i)
	}
	return
}

func main() {
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
			p := srtp.ProtectionProfile(r.Profile)
			key, salt := keys(p)
			ctx, err := srtp.CreateContext(key, salt, p)
			if err != nil {
				r.Err = "ctx: " + err.Error()
				return
			}
			var out []byte
			switch r.Op {
			case "enc_rtp":
				out, err = ctx.EncryptRTP(nil, raw, nil)
			case "dec_rtp":
				out, err = ctx.DecryptRTP(nil, raw, nil)
			case "enc_rtcp":
				out, err = ctx.EncryptRTCP(nil, raw, nil)
			case "dec_rtcp":
				out, err = ctx.DecryptRTCP(nil, raw, nil)
			}
			if err != nil {
				r.Err = err.Error()
				return
			}
			r.Out = hex.EncodeToString(out)
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}
