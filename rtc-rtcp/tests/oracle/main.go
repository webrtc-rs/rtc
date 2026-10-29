// Reads JSONL {"in": hex} on stdin; writes {"in","err"?,"out"?,"pkts"?} using pion/rtcp.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/pion/rtcp"
)

type rec struct {
	In   string   `json:"in"`
	Err  string   `json:"err,omitempty"`
	Out  string   `json:"out,omitempty"`
	Pkts []string `json:"pkts,omitempty"` // Go type name per packet
	// Tcc is the parsed content of the first packet when it is a transport-wide CC feedback.
	Tcc *tccRec `json:"tcc,omitempty"`
}

type tccRec struct {
	Sender uint32     `json:"sender"`
	Media  uint32     `json:"media"`
	Base   uint16     `json:"base"`
	Count  uint16     `json:"count"`
	Ref    uint32     `json:"ref"`
	Fb     uint8      `json:"fb"`
	Chunks []string   `json:"chunks"`
	Deltas [][2]int64 `json:"deltas"`
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
			pkts, err := rtcp.Unmarshal(raw)
			if err != nil {
				r.Err = err.Error()
				return
			}
			for _, p := range pkts {
				r.Pkts = append(r.Pkts, reflect.TypeOf(p).Elem().Name())
			}
			if tcc, ok := pkts[0].(*rtcp.TransportLayerCC); ok {
				rec := &tccRec{Sender: tcc.SenderSSRC, Media: tcc.MediaSSRC, Base: tcc.BaseSequenceNumber,
					Count: tcc.PacketStatusCount, Ref: tcc.ReferenceTime, Fb: tcc.FbPktCount, Chunks: []string{}, Deltas: [][2]int64{}}
				for _, c := range tcc.PacketChunks {
					b, _ := c.Marshal()
					rec.Chunks = append(rec.Chunks, hex.EncodeToString(b))
				}
				for _, d := range tcc.RecvDeltas {
					rec.Deltas = append(rec.Deltas, [2]int64{int64(d.Type), d.Delta})
				}
				r.Tcc = rec
			}
			out, err := rtcp.Marshal(pkts)
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
