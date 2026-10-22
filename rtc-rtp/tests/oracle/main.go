// Reads JSONL {"k","op","mtu","in"(hex)} on stdin and runs pion/rtp. Writes the same line plus
// "err" and "out" (hex list) / packet fields.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/rtp/codecs/av1/obu"
)

// av1WellFormed walks the frame's OBUs and reports whether every header and size is valid.
func av1WellFormed(p []byte) bool {
	for off := 0; off < len(p); {
		h, err := obu.ParseOBUHeader(p[off:])
		if err != nil {
			return false
		}
		off += h.Size()
		size := len(p) - off
		if h.HasSizeField {
			v, n, err := obu.ReadLeb128(p[off:])
			if err != nil {
				return false
			}
			off += int(n)
			size = int(v)
		}
		if size > len(p)-off {
			return false
		}
		off += size
	}
	return true
}

type rec struct {
	K    string   `json:"k"`
	Op   string   `json:"op"`
	Mtu  int      `json:"mtu"`
	In   string   `json:"in"`
	Err  string   `json:"err,omitempty"`
	Out  []string `json:"out,omitempty"`
	Head *bool    `json:"head,omitempty"`
	Tail *bool    `json:"tail,omitempty"`
	Pkt  *pktRec  `json:"pkt,omitempty"`
	// Stream is the OBU stream pion's own AV1 depacketizer rebuilds from pion's payloads.
	Stream *string `json:"stream,omitempty"`
	// Malformed marks an AV1 frame whose OBUs do not parse cleanly; pion stops at the first bad one.
	Malformed bool `json:"malformed,omitempty"`
}

type pktRec struct {
	Version   uint8             `json:"version"`
	Padding   bool              `json:"padding"`
	Ext       bool              `json:"ext"`
	Marker    bool              `json:"marker"`
	PT        uint8             `json:"pt"`
	Seq       uint16            `json:"seq"`
	TS        uint32            `json:"ts"`
	SSRC      uint32            `json:"ssrc"`
	CSRC      []uint32          `json:"csrc"`
	ExtProf   uint16            `json:"ext_profile"`
	Exts      map[string]string `json:"exts"`
	Payload   string            `json:"payload"`
	PadSize   uint8             `json:"pad_size"`
	Marshaled string            `json:"marshaled"`
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	trace := os.Getenv("TRACE") != ""
	for sc.Scan() {
		var r rec
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if trace {
			w.Flush()
			os.Stderr.WriteString(sc.Text() + "\n")
		}
		in, _ := hex.DecodeString(r.In)
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.Err = fmt.Sprintf("PANIC: %v", p)
				}
			}()
			run(&r, in)
		}()
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
}

type depack interface {
	Unmarshal([]byte) ([]byte, error)
}

type headChecker interface{ IsPartitionHead([]byte) bool }

func run(r *rec, in []byte) {
	switch r.Op {
	case "unmarshal":
		if r.K == "Packet" {
			var p rtp.Packet
			if err := p.Unmarshal(in); err != nil {
				r.Err = err.Error()
				return
			}
			pr := &pktRec{Version: p.Version, Padding: p.Padding, Ext: p.Extension, Marker: p.Marker,
				PT: p.PayloadType, Seq: p.SequenceNumber, TS: p.Timestamp, SSRC: p.SSRC, CSRC: p.CSRC,
				ExtProf: p.ExtensionProfile, Exts: map[string]string{}, Payload: hx(p.Payload), PadSize: p.PaddingSize}
			ids := p.GetExtensionIDs()
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				pr.Exts[fmt.Sprint(id)] = hx(p.GetExtension(id))
			}
			if m, err := p.Marshal(); err == nil {
				pr.Marshaled = hx(m)
			} else {
				pr.Marshaled = "ERR:" + err.Error()
			}
			r.Pkt = pr
			return
		}
		var d depack
		switch r.K {
		case "H264Packet":
			d = &codecs.H264Packet{}
		case "VP8Packet":
			d = &codecs.VP8Packet{}
		case "VP9Packet":
			d = &codecs.VP9Packet{}
		case "OpusPacket":
			d = &codecs.OpusPacket{}
		case "H265Depacketizer":
			d = &codecs.H265Depacketizer{}
		case "AV1Depacketizer":
			d = &codecs.AV1Depacketizer{}
		case "AV1Packet":
			d = &codecs.AV1Packet{}
		case "H266Depacketizer":
			d = &codecs.H266Depacketizer{}
		default:
			r.Err = "SKIP: unknown kind " + r.K
			return
		}
		out, err := d.Unmarshal(in)
		if err != nil {
			r.Err = err.Error()
			return
		}
		r.Out = []string{hx(out)}
		if hc, ok := d.(headChecker); ok {
			h := hc.IsPartitionHead(in)
			r.Head = &h
		}
	case "payload":
		var pl interface {
			Payload(mtu uint16, payload []byte) [][]byte
		}
		switch r.K {
		case "H264Payloader":
			pl = &codecs.H264Payloader{}
		case "VP8Payloader":
			pl = &codecs.VP8Payloader{EnablePictureID: true}
		case "VP9Payloader":
			pl = &codecs.VP9Payloader{InitialPictureIDFn: func() uint16 { return 0x1234 }}
		case "OpusPayloader":
			pl = &codecs.OpusPayloader{}
		case "G711Payloader":
			pl = &codecs.G711Payloader{}
		case "G722Payloader":
			pl = &codecs.G722Payloader{}
		case "H265Payloader":
			pl = &codecs.H265Payloader{}
		case "AV1Payloader":
			pl = &codecs.AV1Payloader{}
		case "H266Packetizer":
			pl = &codecs.H266Packetizer{}
		default:
			r.Err = "SKIP: unknown kind " + r.K
			return
		}
		outs := pl.Payload(uint16(r.Mtu), in)
		r.Out = []string{}
		for _, o := range outs {
			r.Out = append(r.Out, hx(o))
		}
		if r.K == "AV1Payloader" {
			r.Malformed = !av1WellFormed(in)
			d := &codecs.AV1Depacketizer{}
			var stream []byte
			ok := true
			for _, o := range outs {
				b, err := d.Unmarshal(o)
				if err != nil {
					ok = false
					break
				}
				stream = append(stream, b...)
			}
			if ok {
				s := hx(stream)
				r.Stream = &s
			}
		}
	}
}
