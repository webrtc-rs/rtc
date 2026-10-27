package main

import (
	"testing"

	"github.com/pion/interceptor/pkg/twcc"
)

// benchInterceptor runs pion's own TWCC recorder benchmarks (`BenchmarkRecord` and
// `BenchmarkRecordAndBuildFeedbackPacket` in pkg/twcc/twcc_test.go) under the names the Rust side uses.
func benchInterceptor() {
	report("twcc record", 0, func(b *testing.B) {
		recorder := twcc.NewRecorder(5000)
		arrival := int64(0)
		seq := uint16(0)
		for i := 0; i < b.N; i++ {
			arrival += 1000
			recorder.Record(5000, seq, arrival)
			seq++
		}
	})
	report("twcc record 100 + build feedback", 0, func(b *testing.B) {
		recorder := twcc.NewRecorder(5000)
		arrival := int64(0)
		seq := uint16(0)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 100; j++ {
				arrival += 1000
				recorder.Record(5000, seq, arrival)
				seq++
			}
			_ = recorder.BuildFeedbackPacket()
		}
	})
}
