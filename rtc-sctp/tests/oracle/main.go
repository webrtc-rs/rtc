// Reads JSONL {"in": hex} on stdin and runs pion/sctp's packet parser + marshaller.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pion/sctp"
)

type rec struct {
	In     string   `json:"in"`
	Err    string   `json:"err,omitempty"`
	Chunks []string `json:"chunks,omitempty"`
	Out    string   `json:"out,omitempty"`
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
			chunks, out, err := sctp.OracleRun(raw)
			if err != nil {
				r.Err = err.Error()
				return
			}
			r.Chunks = chunks
			r.Out = hex.EncodeToString(out)
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}
