package walletresources

import "math"

// Raw availability is not policy validity, ownership, freshness or admission.
const (
	probeAbsent = iota
	probeAvailable
	probeReadError
	probeShort
	probeOversized
	probeOverflow
	probeInvalidShape
)

type probeRawCall struct {
	Result, Errno                                    int64
	Count, Unit, Required, Capacity, Kind, Attempted uint64 // Kind: zero-result, byte-result, declared-width.
}
type probeRawMemory struct {
	Total, Page, Free, Inactive, Speculative, Purgeable    uint64
	SwapTotal, SwapAvailable, SwapUsed, SwapPage, Swapouts uint64
	Pressure                                               int64 // Unclassified native integer, including negative values.
}
type probeRawProcess struct {
	PID, UID, PGID, Status, Seconds, Micros, RSS             uint64
	AfterPID, AfterUID, AfterPGID, AfterSeconds, AfterMicros uint64
}
type probeRaw struct {
	Memory  probeRawMemory
	Process probeRawProcess
	// total, swap, pressure, page, VM, BSD before, task, BSD after, host release.
	Calls [9]probeRawCall
}

func (c probeRawCall) availability() int {
	switch {
	case c.Attempted == 0:
		return probeAbsent
	case c.Errno != 0 || (c.Kind == 1 && c.Result <= 0) || (c.Kind != 1 && c.Result != 0):
		return probeReadError
	case c.Attempted != 1 || c.Kind > 2 || c.Unit == 0 || c.Required > c.Capacity:
		return probeInvalidShape
	case c.Count > math.MaxUint64/c.Unit:
		return probeOverflow
	case c.Count*c.Unit < c.Required:
		return probeShort
	case c.Count*c.Unit > c.Capacity:
		return probeOversized
	default:
		return probeAvailable
	}
}
