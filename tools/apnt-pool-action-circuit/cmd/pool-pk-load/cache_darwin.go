package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Residency is how much of a file the page cache holds, from mincore(2) on a
// read-only shared mapping (mapping a file faults nothing in).
type Residency struct {
	Pages         int     `json:"pages"`
	ResidentPages int     `json:"residentPages"`
	Fraction      float64 `json:"fraction"`
	Method        string  `json:"method"`
	Error         string  `json:"error,omitempty"`
}

func withMapping(path string, f func([]byte) error) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	st, err := fd.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	b, err := syscall.Mmap(int(fd.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return err
	}
	defer syscall.Munmap(b)
	return f(b)
}

func residency(path string) Residency {
	r := Residency{Method: "mincore(2) on a PROT_READ MAP_SHARED mapping"}
	err := withMapping(path, func(b []byte) error {
		ps := os.Getpagesize()
		vec := make([]byte, (len(b)+ps-1)/ps)
		if _, _, e := syscall.Syscall(syscall.SYS_MINCORE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&vec[0]))); e != 0 {
			return e
		}
		r.Pages = len(vec)
		for _, v := range vec {
			if v&1 != 0 {
				r.ResidentPages++
			}
		}
		r.Fraction = float64(r.ResidentPages) / float64(r.Pages)
		return nil
	})
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

// evict drops the file's clean pages from the page cache: msync(2) with
// MS_INVALIDATE on a read-only shared mapping, as vmtouch -e does on macOS.
// It writes nothing to the file.
func evict(path string) error {
	return withMapping(path, func(b []byte) error {
		const msInvalidate = 0x2
		if _, _, e := syscall.Syscall(syscall.SYS_MSYNC, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), msInvalidate); e != 0 {
			return e
		}
		return nil
	})
}
