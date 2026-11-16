package main

// bench_test.go — benchmark scanning atas corpus gencorpus (opsional).
//
//	go run ./tools/gencorpus -o /tmp/sh2bench/corpus.jsonl -n 1500 -big 3
//	SH2_CORPUS=/tmp/sh2bench/corpus.jsonl go test -run '^$' -bench ScanCorpus -benchtime 1x
//
// Tanpa SH2_CORPUS benchmark di-skip (CI tetap cepat).

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func loadCorpusBodies(tb testing.TB, limit int) []string {
	path := os.Getenv("SH2_CORPUS")
	if path == "" {
		tb.Skip("SH2_CORPUS tidak di-set")
	}
	f, err := os.Open(path)
	if err != nil {
		tb.Skip(err)
	}
	defer f.Close()
	var bodies []string
	_, err = forEachLine(f, 256<<20, nil, func(line []byte) {
		if len(bodies) >= limit {
			return
		}
		var r httpxRecord
		if json.Unmarshal(line, &r) == nil && r.Body != "" && !looksBinary(r.Body) {
			bodies = append(bodies, r.Body)
		}
	})
	if err != nil {
		tb.Fatal(err)
	}
	return bodies
}

func BenchmarkScanCorpus(b *testing.B) {
	bodies := loadCorpusBodies(b, 1<<30)
	total := 0
	for _, s := range bodies {
		total += len(s)
	}
	b.SetBytes(int64(total))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for _, s := range bodies {
			n += len(scanContent("x", s))
		}
		if n == 0 {
			b.Fatal("tidak ada temuan")
		}
	}
}

// BenchmarkScanSmallJS: satu bundle ±200 KB tanpa secret (jalur paling sering).
func BenchmarkScanSmallJS(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 200<<10 {
		sb.WriteString(`function r(e,t){return e.dispatch(t)}var ab=12345;"state":"qwmzpe",n.render(t,{props:!0});t.exports={id:"3f2a9c1e-4b7d-4e2a-9c1e-3f2a9c1e4b7d",v:"1.2.3"};if(a&&b.fetch)throw new Error("fetch failed");` + "\n")
	}
	s := sb.String()
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanContent("x", s)
	}
}
