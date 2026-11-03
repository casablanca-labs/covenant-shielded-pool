//go:build !private_runner_admission_test

package runneradmission

// Production has no setter, function variable or runtime bypass.
func Require(sourceCheckout string) error { return requireLiveHarness(sourceCheckout) }
