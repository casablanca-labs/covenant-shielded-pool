package runneradmission

// A closed in-memory refusal. It is never a receipt or terminal diagnostic.
type Refusal struct {
	Code  string `json:"code"`
	Retry string `json:"retry"`
	Cause string `json:"cause"`
}

func (r *Refusal) Error() string { return "private-runner-refused" }
func OwnershipRefusal() *Refusal {
	return &Refusal{"wallet-command-component-refused", "none", "pool-wallet-payment-host-authority-required"}
}
