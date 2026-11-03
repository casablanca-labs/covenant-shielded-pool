// Package walletresources contains inactive consumer resource arithmetic only.
// These constants neither admit work nor qualify a machine.
package walletresources

import "math"

// peakBytes is inherited from three child observations on a 48 GiB host.
// The margin and headroom are uncalibrated; minimumTotalBytes means 16 GiB.
const (
	peakBytes             uint64 = 9_069_789_184
	marginBytes           uint64 = 2_267_447_296
	requiredBytes         uint64 = 11_337_236_480
	minimumTotalBytes     uint64 = 17_179_869_184
	headroomBytes         uint64 = 536_870_912
	minimumRemainingBytes uint64 = 10_800_365_568
)

func checkedAdd(a, b uint64) (uint64, code) {
	if a > math.MaxUint64-b {
		return 0, codeSampleInvalid
	}
	return a + b, ""
}

func checkedSub(a, b uint64) (uint64, code) {
	if b > a {
		return 0, codeSampleInvalid
	}
	return a - b, ""
}

func checkedMul(a, b uint64) (uint64, code) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, codeSampleInvalid
	}
	return a * b, ""
}

func checkedCeilDiv(a, b uint64) (uint64, code) {
	if b == 0 {
		return 0, codeSampleInvalid
	}
	quotient := a / b
	if a%b != 0 {
		return checkedAdd(quotient, 1)
	}
	return quotient, ""
}
