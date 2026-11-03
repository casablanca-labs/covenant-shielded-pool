package poolaction

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestMeasureBlocks compiles the measurement-only variants and writes their
// counts (POOL_ACTION_MEASURE_BLOCKS=FILE). Compile only; skipped otherwise.
func TestMeasureBlocks(t *testing.T) {
	defer protectedPanic(t)
	path := os.Getenv("POOL_ACTION_MEASURE_BLOCKS")
	if path == "" {
		protectedSkip(t, "set POOL_ACTION_MEASURE_BLOCKS=FILE to measure")
	}
	variants := []struct {
		name string
		omit []Clause
	}{
		{"complete", nil},
		{"no-packet (the pad digest hash and the pad)", []Clause{measureOmitPacket}},
		{"no-rcm (the output rcm hashes)", []Clause{measureOmitRcmHash}},
		{"no-rk (memo: no-rk)", []Clause{measureOmitRk}},
		{"no-packet-no-rk (memo: neither)", []Clause{measureOmitPacket, measureOmitRk}},
		{"no-membership", []Clause{measureOmitMembership}},
	}
	type row struct {
		Variant        string   `json:"variant"`
		Omitted        []Clause `json:"omitted"`
		Constraints    int      `json:"constraints"`
		CompileSeconds float64  `json:"compileSeconds"`
	}
	var rows []row
	for _, v := range variants {
		start := time.Now()
		ccs, err := Compile(v.omit...)
		if err != nil {
			protectedFatal(t, err)
		}
		rows = append(rows, row{v.name, v.omit, ccs.GetNbConstraints(), time.Since(start).Seconds()})
		ccs = nil
		Release()
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		protectedFatal(t, err)
	}
}
