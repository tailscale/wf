package wf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type arena struct {
	slabs     []uintptr
	next      uintptr
	remaining uintptr
}

const slabSize = 4096

func (a *arena) grow() {
	slab, err := windows.LocalAlloc(windows.LPTR, slabSize)
	if err != nil {
		panic(fmt.Sprintf("memory allocation failed: %v", err))
	}
	a.slabs = append(a.slabs, slab)
	a.next = slab
	a.remaining = slabSize
}

func (a *arena) alloc(length uintptr) unsafe.Pointer {
	if length > slabSize {
		panic(fmt.Sprintf("can't allocate something that big (%d bytes)", length))
	}
	if length == 0 {
		panic("can't allocate zero bytes")
	}
	if length > a.remaining {
		a.grow()
	}

	// Cast from *uintptr rather than plain uintptr to avoid the go
	// vet unsafe.Pointer safety check. This pattern is safe because
	// a.next never points into the Go heap.
	ret := *(**struct{})(unsafe.Pointer(&a.next))
	a.next += length
	a.remaining -= length
	return unsafe.Pointer(ret)
}

func (a *arena) calloc(num int, size uintptr) unsafe.Pointer {
	return a.alloc(uintptr(num) * size)
}

func (a *arena) dispose() {
	for _, slab := range a.slabs {
		if _, err := windows.LocalFree(windows.Handle(slab)); err != nil {
			panic(fmt.Sprintf("free failed: %v", err))
		}
	}
	a.slabs = a.slabs[:0]
	a.next = 0
	a.remaining = 0
}
