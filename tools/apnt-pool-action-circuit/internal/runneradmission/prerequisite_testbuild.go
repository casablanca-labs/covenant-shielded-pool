//go:build private_runner_admission_test

package runneradmission

import "sync"

var testScope sync.Mutex
var prerequisiteMu sync.RWMutex
var testPrerequisite func() error

// This symbol does not exist in the ordinary build. Overrides serialize, have
// test-scoped cleanup and substitute only the existing harness prerequisite.
func SetTestPrerequisite(cleanup func(func()), prerequisite func() error) {
	testScope.Lock()
	prerequisiteMu.Lock()
	testPrerequisite = prerequisite
	prerequisiteMu.Unlock()
	cleanup(func() {
		prerequisiteMu.Lock()
		testPrerequisite = nil
		prerequisiteMu.Unlock()
		testScope.Unlock()
	})
}

func Require(sourceCheckout string) error {
	prerequisiteMu.RLock()
	prerequisite := testPrerequisite
	prerequisiteMu.RUnlock()
	if prerequisite != nil {
		return prerequisite()
	}
	return requireLiveHarness(sourceCheckout)
}
