package main

import (
	"fmt"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// benchSCTPMessage writes msgLen-byte messages on one reliable ordered stream and reads each back
// on the other association before writing the next, as the Rust side's `transfer` does.
func benchSCTPMessage(msgLen int) {
	a, b := newPipe()
	lf := logging.NewDefaultLoggerFactory()
	type res struct {
		a   *sctp.Association
		err error
	}
	ch := make(chan res)
	go func() {
		s, err := sctp.Server(sctp.Config{NetConn: b, LoggerFactory: lf})
		ch <- res{s, err}
	}()
	c, err := sctp.Client(sctp.Config{NetConn: a, LoggerFactory: lf})
	if err != nil {
		panic(err)
	}
	r := <-ch
	if r.err != nil {
		panic(r.err)
	}
	cs, err := c.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		panic(err)
	}
	msg := make([]byte, msgLen)
	buf := make([]byte, msgLen)
	var ss *sctp.Stream
	report(fmt.Sprintf("sctp message %dB", msgLen), msgLen, func(tb *testing.B) {
		for i := 0; i < tb.N; i++ {
			if _, err := cs.Write(msg); err != nil {
				panic(err)
			}
			if ss == nil {
				if ss, err = r.a.AcceptStream(); err != nil {
					panic(err)
				}
			}
			if _, err := ss.Read(buf); err != nil {
				panic(err)
			}
		}
	})
	_ = c.Close()
	_ = r.a.Close()
}

func benchSCTP() {
	benchSCTPMessage(1200)
	benchSCTPMessage(100)
}
