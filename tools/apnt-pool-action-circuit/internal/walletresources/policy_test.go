package walletresources

import (
	"math"
	"testing"
)

func TestFixedBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want uint64
	}{
		{"peak", peakBytes, 9_069_789_184},
		{"margin", marginBytes, 2_267_447_296},
		{"required", requiredBytes, 11_337_236_480},
		{"minimum-total", minimumTotalBytes, 17_179_869_184},
		{"headroom", headroomBytes, 536_870_912},
		{"minimum-remaining", minimumRemainingBytes, 10_800_365_568},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %d, want %d", tc.got, tc.want)
			}
		})
	}
}

func TestCheckedArithmetic(t *testing.T) {
	const max = math.MaxUint64
	for _, tc := range []struct {
		name       string
		operation  func(uint64, uint64) (uint64, code)
		a, b, want uint64
		wantCode   code
	}{
		{"add-zero", checkedAdd, 0, 0, 0, ""},
		{"add-policy", checkedAdd, 9_069_789_184, 2_267_447_296, 11_337_236_480, ""},
		{"add-boundary", checkedAdd, max - 1, 1, max, ""},
		{"add-max-zero", checkedAdd, max, 0, max, ""},
		{"add-overflow", checkedAdd, max, 1, 0, "pool-wallet-prover-sample-invalid"},
		{"add-overflow-adjacent", checkedAdd, max - 5, 6, 0, "pool-wallet-prover-sample-invalid"},
		{"sub-zero", checkedSub, 0, 0, 0, ""},
		{"sub-policy", checkedSub, 11_337_236_480, 536_870_912, 10_800_365_568, ""},
		{"sub-max-zero", checkedSub, max, 0, max, ""},
		{"sub-equal", checkedSub, max, max, 0, ""},
		{"sub-underflow", checkedSub, 0, 1, 0, "pool-wallet-prover-sample-invalid"},
		{"sub-underflow-adjacent", checkedSub, max - 1, max, 0, "pool-wallet-prover-sample-invalid"},
		{"mul-zero-left", checkedMul, 0, max, 0, ""},
		{"mul-zero-right", checkedMul, max, 0, 0, ""},
		{"mul-normal", checkedMul, 17, 19, 323, ""},
		{"mul-policy", checkedMul, 16, 1_073_741_824, 17_179_869_184, ""},
		{"mul-boundary", checkedMul, max, 1, max, ""},
		{"mul-near-boundary", checkedMul, 9_223_372_036_854_775_807, 2, 18_446_744_073_709_551_614, ""},
		{"mul-overflow", checkedMul, 9_223_372_036_854_775_808, 2, 0, "pool-wallet-prover-sample-invalid"},
		{"mul-max-overflow", checkedMul, max, max, 0, "pool-wallet-prover-sample-invalid"},
		{"ceil-zero", checkedCeilDiv, 0, 4, 0, ""},
		{"ceil-policy", checkedCeilDiv, 9_069_789_184, 4, 2_267_447_296, ""},
		{"ceil-remainder-one", checkedCeilDiv, 9, 4, 3, ""},
		{"ceil-remainder-two", checkedCeilDiv, 10, 4, 3, ""},
		{"ceil-remainder-three", checkedCeilDiv, 11, 4, 3, ""},
		{"ceil-below-divisor", checkedCeilDiv, 1, 4, 1, ""},
		{"ceil-max-unit", checkedCeilDiv, max, 1, max, ""},
		{"ceil-max-two", checkedCeilDiv, max, 2, 9_223_372_036_854_775_808, ""},
		{"ceil-max-max", checkedCeilDiv, max, max, 1, ""},
		{"ceil-max-adjacent", checkedCeilDiv, max, max - 1, 2, ""},
		{"ceil-zero-divisor", checkedCeilDiv, 7, 0, 0, "pool-wallet-prover-sample-invalid"},
		{"ceil-zero-over-zero", checkedCeilDiv, 0, 0, 0, "pool-wallet-prover-sample-invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, resultCode := tc.operation(tc.a, tc.b)
			if got != tc.want || resultCode != tc.wantCode {
				t.Fatalf("got (%d, %q), want (%d, %q)", got, resultCode, tc.want, tc.wantCode)
			}
		})
	}
}

func TestConsumerCodes(t *testing.T) {
	want := [...]string{
		"pool-wallet-prover-platform",
		"pool-wallet-prover-host-role",
		"pool-wallet-prover-installation",
		"pool-wallet-prover-measurement",
		"pool-wallet-prover-context",
		"pool-wallet-prover-family-blocked",
		"pool-wallet-prover-busy",
		"pool-wallet-prover-probe-unavailable",
		"pool-wallet-prover-sample-invalid",
		"pool-wallet-prover-sample-stale",
		"pool-wallet-prover-memory",
		"pool-wallet-prover-pressure",
		"pool-wallet-prover-swap-growth",
		"pool-wallet-prover-headroom",
		"pool-wallet-prover-budget",
		"pool-wallet-prover-disconnected",
		"pool-wallet-prover-cancelled",
		"pool-wallet-prover-launch",
		"pool-wallet-prover-protocol",
		"pool-wallet-prover-work-failed",
		"pool-wallet-prover-cleanup",
	}
	got := consumerCodes()
	if len(got) != len(want) {
		t.Fatalf("code count %d, want %d", len(got), len(want))
	}
	for i, value := range want {
		t.Run(value, func(t *testing.T) {
			recognized, resultCode := recognizeCode(value)
			if string(got[i]) != value || string(recognized) != value || resultCode != "" {
				t.Fatalf("code-set mismatch at %d: %q, %q, %q", i, got[i], recognized, resultCode)
			}
		})
	}
	got[0] = "synthetic-private-diagnostic"
	for _, value := range []string{
		"", "pool-wallet-prover-", "pool-wallet-prover-platform-extra",
		"pool-wallet-prover-platform\x00", " pool-wallet-prover-memory",
		"pool-wallet-prover-memory ", "POOL-WALLET-PROVER-MEMORY",
		string(got[0]), "pool-wallet-prover-synthetic-private-diagnostic",
	} {
		t.Run("unknown", func(t *testing.T) {
			recognized, resultCode := recognizeCode(value)
			if recognized != "" || resultCode != "pool-wallet-prover-protocol" {
				t.Fatalf("unknown code echoed or accepted: (%q, %q)", recognized, resultCode)
			}
		})
	}
	recognized, resultCode := recognizeCode("pool-wallet-prover-platform")
	if recognized != "pool-wallet-prover-platform" || resultCode != "" {
		t.Fatal("changing a returned copy changed recognition authority")
	}
}
