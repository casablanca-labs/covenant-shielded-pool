//go:build ignore

// TEST DRIVER ONLY. Built by filename in a disposable clean-main fixture;
// never installed as a production runner or linked into the ordinary library.
package main

import (
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"os"
)

func main() {
	if len(os.Args) < 5 || os.Args[1] != "admit-request" || os.Args[2] != "--request" {
		os.Exit(2)
	}
	a, source, err := devprove.InactiveLiveActionTargetV2(os.Args[3]).Assignment()
	if err == nil || (err.Error() != "live-request-harness-required" && err.Error() != "live-request-prover-lock-required") || a != nil || source != nil {
		os.Exit(1)
	}
}
