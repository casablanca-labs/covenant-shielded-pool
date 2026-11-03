//go:build !darwin

package main

import "errors"

type Residency struct {
	Pages         int     `json:"pages"`
	ResidentPages int     `json:"residentPages"`
	Fraction      float64 `json:"fraction"`
	Method        string  `json:"method"`
	Error         string  `json:"error,omitempty"`
}

func residency(string) Residency {
	return Residency{Error: "page-cache residency is measured on darwin only"}
}

func evict(string) error { return errors.New("page-cache eviction is implemented on darwin only") }
