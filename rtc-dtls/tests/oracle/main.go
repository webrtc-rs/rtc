// Reads JSONL {"in": hex}; parses with pion/dtls recordlayer and re-marshals.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type rec struct {
	In  string `json:"in"`
	Err string `json:"err,omitempty"`
	Out string `json:"out,omitempty"`
	Typ int    `json:"typ,omitempty"`
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
			var rl recordlayer.RecordLayer
			if err := rl.Unmarshal(raw); err != nil {
				r.Err = err.Error()
				return
			}
			r.Typ = int(rl.Header.ContentType)
			out, err := rl.Marshal()
			if err != nil {
				r.Err = "marshal: " + err.Error()
				return
			}
			r.Out = hex.EncodeToString(out)
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}
