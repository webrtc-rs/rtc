package main

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

// cpuTime is this process's user+system CPU time so far.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func iceAgent() *ice.Agent {
	interval := 20 * time.Millisecond
	a, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost},
		IncludeLoopback:  true,
		InterfaceFilter:  func(name string) bool { return name == "lo0" || name == "lo" },
		CheckInterval:    &interval,
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	})
	if err != nil {
		panic(err)
	}
	return a
}

func iceConnect() (*ice.Agent, *ice.Agent) {
	a, b := iceAgent(), iceAgent()
	link := func(from, to *ice.Agent) {
		_ = from.OnCandidate(func(c ice.Candidate) {
			if c != nil {
				_ = to.AddRemoteCandidate(c)
			}
		})
	}
	link(a, b)
	link(b, a)
	_ = a.GatherCandidates()
	_ = b.GatherCandidates()
	au, ap, _ := a.GetLocalUserCredentials()
	bu, bp, _ := b.GetLocalUserCredentials()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		if _, err := b.Accept(ctx, au, ap); err != nil {
			panic(err)
		}
		close(done)
	}()
	if _, err := a.Dial(ctx, bu, bp); err != nil {
		panic(err)
	}
	<-done
	return a, b
}

// benchICE reports CPU time per session: the wall time of a pion session is its check timer, so
// the cost that matters (and that the Rust side's virtual clock cannot hide) is CPU.
func benchICE() {
	r := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			a, c := iceConnect()
			_ = a.Close()
			_ = c.Close()
		}
	})
	// testing.Benchmark gives wall time; measure CPU separately over a fixed count.
	const n = 20
	start := cpuTime()
	for i := 0; i < n; i++ {
		a, c := iceConnect()
		_ = a.Close()
		_ = c.Close()
	}
	cpu := (cpuTime() - start) / n
	fmt.Printf("%-34s %9d ns/op %5d B/op %3d allocs/op\n", "ice connect, one host pair", cpu.Nanoseconds(), r.AllocedBytesPerOp(), r.AllocsPerOp())
}
