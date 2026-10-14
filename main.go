//go:build wasip1

package main

import (
	"unsafe"

	_ "github.com/TedaTech/fluent-bit-gitleaks/internal/argv"
)

var (
	scrubber *Scrubber
	allocs   = map[uint32][]byte{}
	result   []byte
)

func main() {}

func init() {
	var err error
	if scrubber, err = NewScrubber(); err != nil {
		panic(err)
	}
}

//go:wasmexport malloc
func malloc(size uint32) uint32 {
	b := make([]byte, size)
	p := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(b))))
	allocs[p] = b
	return p
}

//go:wasmexport free
func free(p uint32) {
	delete(allocs, p)
}

//go:wasmexport scrub
func scrub(tag uint32, tagLen uint32, sec uint32, nsec uint32, record uint32, recordLen uint32) uint32 {
	tg := string(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(tag))), tagLen))
	in := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(record))), recordLen)
	result = append(scrubber.Scrub(tg, in), 0)
	return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(result))))
}
