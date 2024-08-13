package ebpf

import (
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type MapMemory struct {
	// Pointer to the mmaped region.
	b []byte
}

func (m *Map) Memory() (*MapMemory, error) {
	if m.flags&unix.BPF_F_MMAPABLE == 0 {
		return nil, fmt.Errorf("Map was not created with the BPF_F_MMAPABLE flag")
	}

	//TODO: Size calc is different for arena maps, add helper to *Map.
	b, err := unix.Mmap(m.FD(), 0, int(m.ValueSize()*m.MaxEntries()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("setting up memory-mapped region: %w", err)
	}

	mm := &MapMemory{b: b}
	runtime.SetFinalizer(mm, (*MapMemory).close)

	return mm, nil
}

func (mm *MapMemory) close() error {
	if err := unix.Munmap(mm.b); err != nil {
		return fmt.Errorf("unmapping memory-mapped region: %w", err)
	}

	mm.b = nil

	return nil
}

func (mm *MapMemory) ReadAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}

	if p == nil {
		return 0, fmt.Errorf("input buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("read offset out of range")
	}

	n := copy(p, mm.b[off:])
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

func (mm *MapMemory) WriteAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}

	if p == nil {
		return 0, fmt.Errorf("output buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("write offset out of range")
	}

	n := copy(mm.b[off:], p)
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

func bounds[T any](mm *MapMemory, off uint64, val T) error {
	if mm.b == nil {
		return fmt.Errorf("memory-mapped region closed")
	}
	vs, bs := uint64(unsafe.Sizeof(val)), uint64(len(mm.b))
	if off+vs > bs {
		return fmt.Errorf("%d-byte write at offset %d exceeds mmap size of %d bytes", vs, off, bs)
	}
	return nil
}

func reinterp[Out, In any](in In) Out {
	return *(*Out)(unsafe.Pointer(&in))
}

type Uint32 struct {
	*atomic.Uint32
	mm *MapMemory
}

type Uint64 struct {
	*atomic.Uint64
	mm *MapMemory
}

type Int32 struct {
	*atomic.Int32
	mm *MapMemory
}

type Int64 struct {
	*atomic.Int64
	mm *MapMemory
}

// Uint32 returns a pointer to an atomic uint32 in the memory-mapped region at
// offset off.
func (mm *MapMemory) Uint32(off uint64) (r *Uint32, err error) {
	if err := bounds(mm, off, atomic.Uint32{}); err != nil {
		return nil, fmt.Errorf("offset out of range: %w", err)
	}
	return &Uint32{reinterp[*atomic.Uint32](&mm.b[off]), mm}, nil
}

// Uint64 returns a pointer to an atomic uint64 in the memory-mapped region at
// offset off.
func (mm *MapMemory) Uint64(off uint64) (r *Uint64, err error) {
	if err := bounds(mm, off, atomic.Uint64{}); err != nil {
		return nil, fmt.Errorf("offset out of range: %w", err)
	}
	return &Uint64{reinterp[*atomic.Uint64](&mm.b[off]), mm}, nil
}

// Int32 returns a pointer to an atomic int32 in the memory-mapped region at
// offset off.
func (mm *MapMemory) Int32(off uint64) (r *Int32, err error) {
	if err := bounds(mm, off, atomic.Int32{}); err != nil {
		return nil, fmt.Errorf("offset out of range: %w", err)
	}
	return &Int32{reinterp[*atomic.Int32](&mm.b[off]), mm}, nil
}

// Int64 returns a pointer to an atomic int64 in the memory-mapped region at
// offset off.
func (mm *MapMemory) Int64(off uint64) (r *Int64, err error) {
	if err := bounds(mm, off, atomic.Int64{}); err != nil {
		return nil, fmt.Errorf("offset out of range: %w", err)
	}
	return &Int64{reinterp[*atomic.Int64](&mm.b[off]), mm}, nil
}

// StoreUint32 atomically stores val into the memory-mapped region at offset
// off.
func (mm *MapMemory) StoreUint32(off uint64, val uint32) error {
	if err := bounds(mm, off, val); err != nil {
		return fmt.Errorf("write offset out of range: %w", err)
	}
	atomic.StoreUint32(reinterp[*uint32](&mm.b[off]), val)
	return nil
}

// StoreUint64 atomically stores val into the memory-mapped region at offset
// off.
func (mm *MapMemory) StoreUint64(off uint64, val uint64) error {
	if err := bounds(mm, off, val); err != nil {
		return fmt.Errorf("write offset out of range: %w", err)
	}
	atomic.StoreUint64(reinterp[*uint64](&mm.b[off]), val)
	return nil
}

// StoreInt32 atomically stores val into the memory-mapped region at offset off.
func (mm *MapMemory) StoreInt32(off uint64, val int32) error {
	if err := bounds(mm, off, val); err != nil {
		return fmt.Errorf("write offset out of range: %w", err)
	}
	atomic.StoreInt32(reinterp[*int32](&mm.b[off]), val)
	return nil
}

// StoreInt64 atomically stores val into the memory-mapped region at offset off.
func (mm *MapMemory) StoreInt64(off uint64, val int64) error {
	if err := bounds(mm, off, val); err != nil {
		return fmt.Errorf("write offset out of range: %w", err)
	}
	atomic.StoreInt64(reinterp[*int64](&mm.b[off]), val)
	return nil
}

// LoadUint32 atomically loads a uint32 from the memory-mapped region at offset
// off.
func (mm *MapMemory) LoadUint32(off uint64) (r uint32, err error) {
	if err := bounds(mm, off, r); err != nil {
		return 0, fmt.Errorf("read offset out of range: %w", err)
	}
	return atomic.LoadUint32(reinterp[*uint32](&mm.b[off])), nil
}

// LoadUint64 atomically loads a uint64 from the memory-mapped region at offset
// off.
func (mm *MapMemory) LoadUint64(off uint64) (r uint64, err error) {
	if err := bounds(mm, off, r); err != nil {
		return 0, fmt.Errorf("read offset out of range: %w", err)
	}
	return atomic.LoadUint64(reinterp[*uint64](&mm.b[off])), nil
}

// LoadInt32 atomically loads an int32 from the memory-mapped region at offset
// off.
func (mm *MapMemory) LoadInt32(off uint64) (r int32, err error) {
	if err := bounds(mm, off, r); err != nil {
		return 0, fmt.Errorf("read offset out of range: %w", err)
	}
	return atomic.LoadInt32(reinterp[*int32](&mm.b[off])), nil
}

// LoadInt64 atomically loads an int64 from the memory-mapped region at offset
// off.
func (mm *MapMemory) LoadInt64(off uint64) (r int64, err error) {
	if err := bounds(mm, off, r); err != nil {
		return 0, fmt.Errorf("read offset out of range: %w", err)
	}
	return atomic.LoadInt64(reinterp[*int64](&mm.b[off])), nil
}

// AddUint32 atomically adds delta to the memory-mapped region at offset off and
// returns the new value.
func (mm *MapMemory) AddUint32(off uint64, delta uint32) (new uint32, err error) {
	if err := bounds(mm, off, delta); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.AddUint32(reinterp[*uint32](&mm.b[off]), delta), nil
}

// AddUint64 atomically adds delta to the memory-mapped region at offset off and
// returns the new value.
func (mm *MapMemory) AddUint64(off uint64, delta uint64) (new uint64, err error) {
	if err := bounds(mm, off, delta); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.AddUint64(reinterp[*uint64](&mm.b[off]), delta), nil
}

// AddInt32 atomically adds delta to the memory-mapped region at offset off and
// returns the new value.
func (mm *MapMemory) AddInt32(off uint64, delta int32) (new int32, err error) {
	if err := bounds(mm, off, delta); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.AddInt32(reinterp[*int32](&mm.b[off]), delta), nil
}

// AddInt64 atomically adds delta to the memory-mapped region at offset off and
// returns the new value.
func (mm *MapMemory) AddInt64(off uint64, delta int64) (new int64, err error) {
	if err := bounds(mm, off, delta); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.AddInt64(reinterp[*int64](&mm.b[off]), delta), nil
}

// SwapUint32 atomically stores new into the memory-mapped region at offset off
// and returns the previous value.
func (mm *MapMemory) SwapUint32(off uint64, new uint32) (old uint32, err error) {
	if err := bounds(mm, off, new); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.SwapUint32(reinterp[*uint32](&mm.b[off]), new), nil
}

// SwapUint64 atomically stores new into the memory-mapped region at offset off
// and returns the previous value.
func (mm *MapMemory) SwapUint64(off uint64, new uint64) (old uint64, err error) {
	if err := bounds(mm, off, new); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.SwapUint64(reinterp[*uint64](&mm.b[off]), new), nil
}

// SwapInt32 atomically stores new into the memory-mapped region at offset off
// and returns the previous value.
func (mm *MapMemory) SwapInt32(off uint64, new int32) (old int32, err error) {
	if err := bounds(mm, off, new); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.SwapInt32(reinterp[*int32](&mm.b[off]), new), nil
}

// SwapInt64 atomically stores new into the memory-mapped region at offset off
// and returns the previous value.
func (mm *MapMemory) SwapInt64(off uint64, new int64) (old int64, err error) {
	if err := bounds(mm, off, new); err != nil {
		return 0, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.SwapInt64(reinterp[*int64](&mm.b[off]), new), nil
}

// CompareAndSwapUint32 atomically stores new into the memory-mapped region at
// offset off if the current value is equal to old. It returns the previous
// value.
func (mm *MapMemory) CompareAndSwapUint32(off uint64, old, new uint32) (swapped bool, err error) {
	if err := bounds(mm, off, new); err != nil {
		return false, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.CompareAndSwapUint32(reinterp[*uint32](&mm.b[off]), old, new), nil
}

// CompareAndSwapUint64 atomically stores new into the memory-mapped region at
// offset off if the current value is equal to old. It returns the previous
// value.
func (mm *MapMemory) CompareAndSwapUint64(off uint64, old, new uint64) (swapped bool, err error) {
	if err := bounds(mm, off, new); err != nil {
		return false, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.CompareAndSwapUint64(reinterp[*uint64](&mm.b[off]), old, new), nil
}

// CompareAndSwapInt32 atomically stores new into the memory-mapped region at
// offset off if the current value is equal to old. It returns the previous
// value.
func (mm *MapMemory) CompareAndSwapInt32(off uint64, old, new int32) (swapped bool, err error) {
	if err := bounds(mm, off, new); err != nil {
		return false, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.CompareAndSwapInt32(reinterp[*int32](&mm.b[off]), old, new), nil
}

// CompareAndSwapInt64 atomically stores new into the memory-mapped region at
// offset off if the current value is equal to old. It returns the previous
// value.
func (mm *MapMemory) CompareAndSwapInt64(off uint64, old, new int64) (swapped bool, err error) {
	if err := bounds(mm, off, new); err != nil {
		return false, fmt.Errorf("offset out of range: %w", err)
	}
	return atomic.CompareAndSwapInt64(reinterp[*int64](&mm.b[off]), old, new), nil
}
