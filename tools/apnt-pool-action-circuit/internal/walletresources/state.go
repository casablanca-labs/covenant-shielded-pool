package walletresources

type resourcePhase uint8
type pressureLevel uint8

const (
	phaseInitial resourcePhase = iota + 1
	phaseFinal
	phaseRunning
)
const (
	pressureNormal pressureLevel = iota + 1
	pressureWarning
	pressureCritical
)

// Typed policy inputs only: no OS enum mapping, freshness or source authority.
type resourceSample struct {
	total, available, rss, swapUsed, swapouts uint64
	pressure                                  pressureLevel
}

// Value copies retain the original baseline. A policy result grants no work.
type resourceState struct {
	total, budget, swapBase, swapoutsBase uint64
	trip                                  code
}

func clampedDifference(a, b uint64) uint64 {
	// checkedSub's zero on underflow implements this policy's explicit clamp.
	difference, _ := checkedSub(a, b)
	return difference
}

// Initial requires zero state; final/running select policy, not a launch phase.
// Qualification and temporal sequencing belong to the later native monitor.
func (s resourceState) evaluate(p resourcePhase, v resourceSample) (resourceState, code) {
	if s.trip != "" {
		if _, c := recognizeCode(string(s.trip)); c != "" {
			s.trip = c
		}
		return s, s.trip
	}
	c := code("")
	if p < phaseInitial || p > phaseRunning ||
		(p == phaseInitial && s != (resourceState{})) || (p != phaseInitial && s.total == 0) {
		c = codeProtocol
	} else if v.total == 0 || v.available > v.total ||
		v.pressure < pressureNormal || v.pressure > pressureCritical ||
		(p != phaseInitial && (v.total != s.total || v.swapouts < s.swapoutsBase)) {
		c = codeSampleInvalid
	}
	budget := uint64(0)
	if c == "" {
		if p == phaseInitial {
			budget, c = checkedAdd(v.rss, v.available)
			if c == "" {
				budget, c = checkedSub(budget, headroomBytes)
			}
		} else {
			budget, c = checkedAdd(v.rss, clampedDifference(v.available, headroomBytes))
			budget = min(s.budget, budget)
		}
	}
	if c == "" {
		switch {
		case v.pressure != pressureNormal:
			c = codePressure
		case p != phaseInitial && (v.swapUsed > s.swapBase || v.swapouts > s.swapoutsBase):
			c = codeSwapGrowth
		case p != phaseRunning && v.total < minimumTotalBytes:
			c = codeMemory
		case p != phaseRunning && v.available < requiredBytes:
			c = codeMemory
		case p != phaseRunning && clampedDifference(budget, v.rss) < minimumRemainingBytes:
			c = codeMemory
		case p == phaseRunning && v.available < headroomBytes:
			c = codeHeadroom
		case p == phaseRunning && v.rss > budget:
			c = codeBudget
		}
	}
	if c != "" {
		s.trip = c
		return s, c
	}
	if p == phaseInitial {
		s.total, s.swapBase, s.swapoutsBase = v.total, v.swapUsed, v.swapouts
	}
	s.budget = budget
	return s, ""
}
