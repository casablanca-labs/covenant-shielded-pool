package walletresources

type code string

const (
	codePlatform         code = "pool-wallet-prover-platform"
	codeHostRole         code = "pool-wallet-prover-host-role"
	codeInstallation     code = "pool-wallet-prover-installation"
	codeMeasurement      code = "pool-wallet-prover-measurement"
	codeContext          code = "pool-wallet-prover-context"
	codeFamilyBlocked    code = "pool-wallet-prover-family-blocked"
	codeBusy             code = "pool-wallet-prover-busy"
	codeProbeUnavailable code = "pool-wallet-prover-probe-unavailable"
	codeSampleInvalid    code = "pool-wallet-prover-sample-invalid"
	codeSampleStale      code = "pool-wallet-prover-sample-stale"
	codeMemory           code = "pool-wallet-prover-memory"
	codePressure         code = "pool-wallet-prover-pressure"
	codeSwapGrowth       code = "pool-wallet-prover-swap-growth"
	codeHeadroom         code = "pool-wallet-prover-headroom"
	codeBudget           code = "pool-wallet-prover-budget"
	codeDisconnected     code = "pool-wallet-prover-disconnected"
	codeCancelled        code = "pool-wallet-prover-cancelled"
	codeLaunch           code = "pool-wallet-prover-launch"
	codeProtocol         code = "pool-wallet-prover-protocol"
	codeWorkFailed       code = "pool-wallet-prover-work-failed"
	codeCleanup          code = "pool-wallet-prover-cleanup"
)

// Each call returns a copy, so callers cannot change recognition authority.
func consumerCodes() [21]code {
	return [21]code{
		codePlatform, codeHostRole, codeInstallation, codeMeasurement,
		codeContext, codeFamilyBlocked, codeBusy, codeProbeUnavailable,
		codeSampleInvalid, codeSampleStale, codeMemory, codePressure,
		codeSwapGrowth, codeHeadroom, codeBudget, codeDisconnected,
		codeCancelled, codeLaunch, codeProtocol, codeWorkFailed, codeCleanup,
	}
}

func recognizeCode(value string) (code, code) {
	for _, candidate := range consumerCodes() {
		if string(candidate) == value {
			return candidate, ""
		}
	}
	return "", codeProtocol
}
