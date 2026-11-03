//go:build !darwin || !arm64 || !cgo

package walletresources

const probeNativeBuild = false

type probeBackend = probeAbsentBackend
