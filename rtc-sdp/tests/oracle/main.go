// Reads JSONL {"in": base64} from stdin, writes {"in","err"?,"out"?} per line using pion/sdp.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/pion/sdp/v3"
)

type rec struct {
	In  string `json:"in"`
	Err string `json:"err,omitempty"`
	Out string `json:"out,omitempty"`
	// Codecs is GetCodecMap() as sorted Codec.String() lines.
	Codecs []string `json:"codecs,omitempty"`
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
		raw, _ := base64.StdEncoding.DecodeString(r.In)
		var sd sdp.SessionDescription
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.Err = fmt.Sprintf("PANIC: %v", p)
				}
			}()
			if err := sd.UnmarshalString(string(raw)); err != nil {
				r.Err = err.Error()
				return
			}
			out, err := sd.Marshal()
			if err != nil {
				r.Err = "marshal: " + err.Error()
				return
			}
			r.Out = base64.StdEncoding.EncodeToString(out)
			m := sd.GetCodecMap()
			pts := make([]int, 0, len(m))
			for pt := range m {
				pts = append(pts, int(pt))
			}
			sort.Ints(pts)
			for _, pt := range pts {
				r.Codecs = append(r.Codecs, m[uint8(pt)].String())
			}
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}
