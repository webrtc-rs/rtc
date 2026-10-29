package main

import (
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func dtlsConnect(cfg *dtls.Config) (*dtls.Conn, *dtls.Conn) {
	a, b := newPipe()
	ch := make(chan *dtls.Conn)
	go func() {
		s, err := dtls.Server(b, a.name, cfg)
		if err != nil || s.Handshake() != nil {
			panic("dtls server handshake")
		}
		ch <- s
	}()
	c, err := dtls.Client(a, b.name, cfg)
	if err != nil || c.Handshake() != nil {
		panic("dtls client handshake")
	}
	return c, <-ch
}

func benchDTLS() {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		panic(err)
	}
	cfg := &dtls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	report("dtls handshake ecdsa-p256 gcm", 0, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c, s := dtlsConnect(cfg)
			_ = c.Close()
			_ = s.Close()
		}
	})
	c, s := dtlsConnect(cfg)
	record := make([]byte, 1200)
	buf := make([]byte, 2000)
	report("dtls app data 1200B", len(record), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := c.Write(record); err != nil {
				panic(err)
			}
			if _, err := s.Read(buf); err != nil {
				panic(err)
			}
		}
	})
}
