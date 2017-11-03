package cbmgr

import (
	"sync/atomic"
)

type atomicBool struct {
	value uint32
}

func newAtomicBool(initValue bool) *atomicBool {
	if initValue {
		return &atomicBool{1}
	}

	return &atomicBool{0}
}

func (a *atomicBool) Load() bool {
	if atomic.LoadUint32(&a.value) == 1 {
		return true
	}

	return false
}

func (a *atomicBool) CompareAndSwap(oldValue, newValue bool) bool {
	old := uint32(0)
	if oldValue {
		old = 1
	}

	new := uint32(0)
	if newValue {
		new = 1
	}
	return atomic.CompareAndSwapUint32(&a.value, old, new)
}

func (a *atomicBool) Store(value bool) {
	if value {
		atomic.StoreUint32(&a.value, 1)
	} else {
		atomic.StoreUint32(&a.value, 0)
	}
}

func (a *atomicBool) Swap(value bool) bool {
	new := uint32(0)
	if value {
		new = 1
	}

	old := atomic.SwapUint32(&a.value, new)
	if old != 0 {
		return true
	}

	return false
}
