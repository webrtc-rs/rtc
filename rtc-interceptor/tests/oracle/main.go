// pion/interceptor NACK oracle: random packet-arrival sequences run through pion's receive log
// (receive_log.go, copied verbatim apart from its two internal imports) and its RTP send buffer
// (internal/rtpbuffer, reduced to the sequence numbers it is keyed by), recording every answer.
//
//	go run . [-n rows] [-seed s] > ../data/pion_nack_golden.jsonl
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

// sendBuffer is pion's rtpbuffer.RTPBuffer with the packet replaced by its sequence number.
type sendBuffer struct {
	packets      []int32 // -1: empty
	size         uint16
	highestAdded uint16
	started      bool
}

func newSendBuffer(size uint16) *sendBuffer {
	b := &sendBuffer{packets: make([]int32, size), size: size}
	for i := range b.packets {
		b.packets[i] = -1
	}
	return b
}

func (r *sendBuffer) add(seq uint16) {
	if !r.started {
		r.packets[seq%r.size] = int32(seq)
		r.highestAdded = seq
		r.started = true
		return
	}
	diff := seq - r.highestAdded
	if diff == 0 {
		return
	} else if diff < uint16SizeHalf {
		for i := r.highestAdded + 1; i != seq; i++ {
			r.packets[i%r.size] = -1
		}
		r.highestAdded = seq
	}
	r.packets[seq%r.size] = int32(seq)
}

func (r *sendBuffer) get(seq uint16) int32 {
	diff := r.highestAdded - seq
	if diff >= uint16SizeHalf {
		return -1
	}
	if diff >= r.size {
		return -1
	}
	pkt := r.packets[seq%r.size]
	if pkt != -1 && uint16(pkt) != seq {
		return -1
	}
	return pkt
}

type row struct {
	Kind string   `json:"k"`
	Size uint16   `json:"size"`
	Ops  []string `json:"ops"`
	Out  []string `json:"out"`
}

// arrivals yields sequence numbers the way a lossy, reordering network delivers them.
func arrivals(rng *rand.Rand, n int) []uint16 {
	base := uint16(rng.Intn(1 << 16))
	if rng.Intn(3) == 0 {
		base = uint16(65535 - rng.Intn(40)) // start close to the wrap
	}
	out := make([]uint16, 0, n)
	next := base
	for len(out) < n {
		switch r := rng.Intn(100); {
		case r < 62: // in order
			out = append(out, next)
			next++
		case r < 72: // a gap: packets lost
			next += uint16(1 + rng.Intn(6))
			out = append(out, next)
			next++
		case r < 82: // a late packet
			out = append(out, next-uint16(1+rng.Intn(12)))
		case r < 90: // a duplicate
			if len(out) > 0 {
				out = append(out, out[len(out)-1-rng.Intn(min(len(out), 4))])
			}
		case r < 94: // a long gap
			next += uint16(20 + rng.Intn(3000))
			out = append(out, next)
			next++
		case r < 96: // a jump over half the sequence space (a stream restart)
			next += uint16(1<<15 + rng.Intn(1<<14))
			out = append(out, next)
			next++
		default: // an arbitrary number
			out = append(out, uint16(rng.Intn(1<<16)))
		}
	}
	return out
}

// summary describes a list of sequence numbers compactly: how many, an FNV-1a hash of all of them,
// and the first few. A single "missing" answer can run to thousands of numbers.
func summary(ns []uint16) string {
	h := uint32(2166136261)
	for _, n := range ns {
		for _, b := range [2]byte{byte(n >> 8), byte(n)} {
			h = (h ^ uint32(b)) * 16777619
		}
	}
	first := ns
	if len(first) > 6 {
		first = first[:6]
	}
	parts := make([]string, len(first))
	for i, n := range first {
		parts[i] = strconv.Itoa(int(n))
	}
	return fmt.Sprintf("n=%d h=%08x first=%s", len(ns), h, strings.Join(parts, ","))
}

func receiveRow(rng *rand.Rand, size uint16) row {
	log, err := newReceiveLog(size)
	if err != nil {
		panic(err)
	}
	r := row{Kind: "recv", Size: size}
	seqs := arrivals(rng, 40+rng.Intn(200))
	last := seqs[0]
	for _, s := range seqs {
		r.Ops = append(r.Ops, "a:"+strconv.Itoa(int(s)))
		log.add(s)
		r.Out = append(r.Out, "")
		last = s
		switch rng.Intn(6) {
		case 0:
			skip := uint16([]int{0, 0, 1, 2, 5, 10}[rng.Intn(6)])
			r.Ops = append(r.Ops, "m:"+strconv.Itoa(int(skip)))
			r.Out = append(r.Out, summary(log.missingSeqNumbers(skip, make([]uint16, size))))
		case 1:
			q := last - uint16(rng.Intn(int(size)+8)) + uint16(rng.Intn(4))
			r.Ops = append(r.Ops, "g:"+strconv.Itoa(int(q)))
			if log.get(q) {
				r.Out = append(r.Out, "1")
			} else {
				r.Out = append(r.Out, "0")
			}
		}
	}
	r.Ops = append(r.Ops, "m:0")
	r.Out = append(r.Out, summary(log.missingSeqNumbers(0, make([]uint16, size))))
	return r
}

func sendRow(rng *rand.Rand, size uint16) row {
	buf := newSendBuffer(size)
	r := row{Kind: "send", Size: size}
	for _, s := range arrivals(rng, 40+rng.Intn(200)) {
		r.Ops = append(r.Ops, "a:"+strconv.Itoa(int(s)))
		buf.add(s)
		r.Out = append(r.Out, "")
		if rng.Intn(3) == 0 {
			q := s - uint16(rng.Intn(int(size)+8)) + uint16(rng.Intn(4))
			r.Ops = append(r.Ops, "g:"+strconv.Itoa(int(q)))
			r.Out = append(r.Out, strconv.Itoa(int(buf.get(q))))
		}
	}
	return r
}

func main() {
	n := flag.Int("n", 2400, "rows")
	seed := flag.Int64("seed", 0x6e61636b, "seed")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	recvSizes := []uint16{64, 128, 256, 512, 1024, 2048, 32768}
	sendSizes := []uint16{1, 2, 4, 8, 64, 256, 1024, 32768}
	enc := json.NewEncoder(os.Stdout)
	for i := 0; i < *n; i++ {
		var r row
		if i%2 == 0 {
			r = receiveRow(rng, recvSizes[rng.Intn(len(recvSizes))])
		} else {
			r = sendRow(rng, sendSizes[rng.Intn(len(sendSizes))])
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
