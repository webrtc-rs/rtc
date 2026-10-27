package main

// An in-memory, lossless, buffered datagram pipe with read deadlines: the Go counterpart of the
// zero-latency wire the Rust side drives by hand. Shared by the DTLS and SCTP benchmarks.

import (
	"errors"
	"net"
	"sync"
	"time"
)

type addr string

func (a addr) Network() string { return "mem" }
func (a addr) String() string  { return string(a) }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// memConn is one end of a lossless, buffered, in-memory datagram pipe.
type memConn struct {
	in, out chan []byte
	name    addr
	peer    addr
	mu      sync.Mutex
	rd      time.Time
	closed  chan struct{}
	once    sync.Once
	wake    chan struct{}
}

func newPipe() (*memConn, *memConn) {
	ab, ba := make(chan []byte, 4096), make(chan []byte, 4096)
	a := &memConn{in: ba, out: ab, name: "a", peer: "b", closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	b := &memConn{in: ab, out: ba, name: "b", peer: "a", closed: make(chan struct{}), wake: make(chan struct{}, 1)}
	return a, b
}

func (c *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		d := c.rd
		c.mu.Unlock()
		var t <-chan time.Time
		var tm *time.Timer
		if !d.IsZero() {
			w := time.Until(d)
			if w <= 0 {
				return 0, nil, timeoutErr{}
			}
			tm = time.NewTimer(w)
			t = tm.C
		}
		select {
		case b := <-c.in:
			if tm != nil { tm.Stop() }
			return copy(p, b), c.peer, nil
		case <-t:
			return 0, nil, timeoutErr{}
		case <-c.wake:
			if tm != nil { tm.Stop() }
		case <-c.closed:
			if tm != nil { tm.Stop() }
			return 0, nil, errors.New("closed")
		}
	}
}

func (c *memConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := append([]byte(nil), p...)
	select {
	case c.out <- b:
		return len(p), nil
	case <-c.closed:
		return 0, errors.New("closed")
	}
}
func (c *memConn) Close() error                  { c.once.Do(func() { close(c.closed) }); return nil }
func (c *memConn) LocalAddr() net.Addr           { return c.name }
func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	select { case c.wake <- struct{}{}: default: }
	return nil
}
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func (c *memConn) RemoteAddr() net.Addr { return c.peer }

// Write and Read make the pipe usable as a net.Conn (pion/sctp wants one).
func (c *memConn) Write(p []byte) (int, error) { return c.WriteTo(p, nil) }
func (c *memConn) Read(p []byte) (int, error) { n, _, err := c.ReadFrom(p); return n, err }
