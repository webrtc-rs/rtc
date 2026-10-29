// Reads JSONL {"in": hex}; reports whether pion/datachannel parses and re-marshals it.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pion/datachannel"
)

type rec struct {
	In  string `json:"in"`
	Err string `json:"err,omitempty"`
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
			if datachannel.TryMarshalUnmarshal(raw) == 0 {
				r.Err = "rejected"
			}
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}
