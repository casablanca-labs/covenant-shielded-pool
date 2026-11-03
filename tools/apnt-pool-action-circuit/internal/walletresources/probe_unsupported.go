package walletresources

// No portable estimate, native read, or development fallback exists here.
type probeAbsentBackend struct{}

func (probeAbsentBackend) acquire(int32) (probeRaw, code)       { return probeRaw{}, codePlatform }
func (probeAbsentBackend) layout() (probeRaw, [4][2]uint64)     { return probeRaw{}, [4][2]uint64{} }
func (probeAbsentBackend) transfer(c probeRawCall) probeRawCall { return c }
