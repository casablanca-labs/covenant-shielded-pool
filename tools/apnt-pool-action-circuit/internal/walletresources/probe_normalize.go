package walletresources

type probeNormalizeReason uint8

const (
	probeNormalizeMissing probeNormalizeReason = iota + 1
	probeNormalizeReadError
	probeNormalizeLayout
	probeNormalizeUnit
	probeNormalizeShape
	probeNormalizeShort
	probeNormalizeOversized
	probeNormalizeOverflow
	probeNormalizeZero
	probeNormalizeInconsistent
	probeNormalizePressureUnclassified
)

// Facts are not a resourceSample: no pressure level, freshness or owned RSS.
type probeMemoryFacts struct {
	raw      probeRawMemory
	eligible uint64
}

// sdk is B1's in-process compiled layout, never a serialized acceptance input.
// This pure arithmetic boundary does not authenticate either input's origin.
func probeNormalize(v probeRaw, sdk probeRaw) (probeMemoryFacts, probeNormalizeReason) {
	var empty probeMemoryFacts
	// Process observations belong to a later authenticated scope, not this step.
	for _, i := range []int{0, 1, 2, 3, 4, 8} {
		c, w := v.Calls[i], sdk.Calls[i]
		kind := uint64(0)
		if i == 3 || i == 8 {
			kind = 2
		}
		if w.Unit == 0 || w.Required > w.Capacity || w.Kind != kind ||
			w.Attempted != 0 || w.Result != 0 || w.Errno != 0 || w.Count != 0 ||
			(i != 8 && w.Required == 0) || (i == 8 && (w.Required != 0 || w.Capacity != 0)) {
			return empty, probeNormalizeLayout
		}
		if c.Attempted == 0 {
			return empty, probeNormalizeMissing
		}
		if c.Unit != w.Unit {
			return empty, probeNormalizeUnit
		}
		if c.Kind != w.Kind || c.Required != w.Required || c.Capacity != w.Capacity {
			return empty, probeNormalizeShape
		}
		switch c.availability() {
		case probeAvailable:
		case probeReadError:
			return empty, probeNormalizeReadError
		case probeShort:
			return empty, probeNormalizeShort
		case probeOversized:
			return empty, probeNormalizeOversized
		case probeOverflow:
			return empty, probeNormalizeOverflow
		default:
			return empty, probeNormalizeShape
		}
	}
	m := v.Memory
	if m.Total == 0 || m.Page == 0 || m.SwapPage == 0 {
		return empty, probeNormalizeZero
	}
	if m.Page > 1<<20 || m.Page&(m.Page-1) != 0 ||
		m.SwapPage > 1<<20 || m.SwapPage&(m.SwapPage-1) != 0 {
		return empty, probeNormalizeUnit
	}
	pages, c := checkedAdd(m.Free, m.Inactive)
	if c != "" {
		return empty, probeNormalizeOverflow
	}
	eligible, c := checkedMul(pages, m.Page)
	if c != "" {
		return empty, probeNormalizeOverflow
	}
	swap, c := checkedAdd(m.SwapUsed, m.SwapAvailable)
	if c != "" {
		return empty, probeNormalizeOverflow
	}
	// Checked nonnegative exact sum also implies used <= total.
	if eligible > m.Total || m.Speculative > m.Free || swap != m.SwapTotal {
		return empty, probeNormalizeInconsistent
	}
	// Speculative is already in free; purgeable earns no additional credit.
	// No raw pressure integer has an established native normal mapping here.
	return probeMemoryFacts{raw: m, eligible: eligible}, probeNormalizePressureUnclassified
}
