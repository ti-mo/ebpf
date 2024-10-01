package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

// Memory is the building block for accessing the memory of specific bpf map
// types (Array and Arena at the time of writing) without going through the bpf
// syscall interface.
//
// Given the fd of a bpf map created with the BPF_F_MMAPABLE flag, a shared
// 'file'-based memory-mapped region can be allocated in the process' address
// space, exposing the bpf map's memory by simply accessing a memory location.
//
// Since Go is a gargabe-collected language, this complicates things a bit. We
// don't want to place the burden of managing these memory regions on the
// caller, since the end goal is to carve out many small objects from this
// memory corresponding to global variables declared in the BPF C program. In
// practice, this means leaning on the runtime and GC as much as possible.
//
// We settled on a solution that requests regular Go heap memory by allocating a
// slice, allowing the runtime to track any pointers to the slice's backing
// memory. Re-slicing is a core feature of the language, but any kind of pointer
// into a the backing array is sufficient to keep it alive.
//
// Then, before returning the Memory to the caller, a finalizer is set on the
// backing array, making sure the bpf map's memory is unmapped from the heap
// before releasing the backing array to the runtime for reallocation.
//
// Putting the finalizer on the backing array was a conscious decision to avoid
// having to maintaining a reference to the Memory at all times, which is hard
// to guarantee if the actual access is done through another object, e.g. a
// sync.Atomic aliased to a piece of the backing array.
//
// This way, memory safety is guaranteed as long as there are any pointers
// whatsoever into the backing array. When all pointers are gone, the finalizer
// will run and unmap the bpf map's memory.

//go:linkname heapObjectsCanMove runtime.heapObjectsCanMove
func heapObjectsCanMove() bool

var ErrReadOnly = errors.New("resource is read-only")
var ErrInvalidType = errors.New("invalid type")

// Memory implements accessing a Map's memory without making any syscalls.
type Memory struct {
	b  []byte
	ro bool
}

func newMemory(fd, s int, ro bool) (*Memory, error) {
	// Allocate a page-aligned span of memory on the Go heap.
	alloc, size, err := allocate(s)
	if err != nil {
		return nil, fmt.Errorf("allocating memory: %w", err)
	}

	flags := unix.PROT_READ | unix.PROT_WRITE
	if ro {
		flags = unix.PROT_READ
	}

	// Map the bpf map memory over the Go heap. This will result in the following
	// mmap layout in the process' address space (0xc000000000 is a span of Go
	// heap), visualized using pmap:
	//
	// Address           Kbytes     RSS   Dirty Mode  Mapping
	// 000000c000000000    1824     864     864 rw--- [ anon ]
	// 000000c0001c8000       4       4       4 rw-s- [ anon ]
	// 000000c0001c9000    2268      16      16 rw--- [ anon ]
	//
	// This will break up the Go heap, but as long as the runtime doesn't try to
	// move our allocation around, this is safe for as long as we hold a reference
	// to our allocated object.
	//
	// Use MAP_SHARED to make sure the kernel sees any writes we do, and MAP_FIXED
	// to ensure the mapping starts exactly at the address we requested. If alloc
	// isn't page-aligned, the mapping operation will fail.
	if _, err = unix.MmapPtr(fd, 0, alloc, uintptr(size),
		flags, unix.MAP_SHARED|unix.MAP_FIXED); err != nil {
		return nil, fmt.Errorf("setting up memory-mapped region: %w", err)
	}

	// Set a finalizer on the heap allocation to undo the mapping before the span
	// is collected and reused by the runtime. This has a few reasons:
	//
	//  - Avoid leaking memory/mappings.
	//  - Future writes to this memory should never clobber a bpf map's contents.
	//  - Some bpf maps are mapped read-only, causing a segfault if the runtime
	//    reallocates and zeroes the span later.
	runtime.SetFinalizer((*byte)(alloc), unmap(size))

	mm := &Memory{
		unsafe.Slice((*byte)(alloc), size),
		ro,
	}

	return mm, nil
}

// allocate returns an unsafe.Pointer to a page-aligned section of memory on the
// Go heap, managed by the runtime. The given size is rounded up to the nearest
// multiple of the system's page size to ensure we're given an allocation that
// starts on a page boundary. The size of the resulting allocation is returned.
func allocate(size int) (unsafe.Pointer, int, error) {
	// Memory-mapping over a piece of the Go heap is unsafe when the GC can
	// randomly decide to move objects around, in which case the mapped region
	// will not move along with it.
	if heapObjectsCanMove() {
		return nil, 0, errors.New("this Go runtime has a moving garbage collector")
	}

	// Request at least a full page from the runtime, otherwise the allocated span
	// is likely not page-aligned, risking mapping over objects on another page.
	// Since we use MAP_FIXED, the starting address of the mapping must be
	// page-aligned on most architectures anyway.
	size = internal.Align(size, os.Getpagesize())

	// Get the address of the backing array of the slice and check if it's
	// page-aligned to make sure it works with MAP_FIXED.
	ptr := unsafe.Pointer(unsafe.SliceData(make([]byte, size)))
	addr := int(uintptr(ptr))
	if internal.Align(addr, os.Getpagesize()) != addr {
		return nil, 0, fmt.Errorf("allocated memory is not page-aligned: %d", addr)
	}

	return ptr, size, nil
}

// unmap returns a function that takes a pointer to a memory-mapped region on
// the Go heap. The function undoes any mappings and discards the span's
// contents.
//
// Used as a finalizer in [newMemory], split off into a separate function for
// testing and to avoid accidentally closing over the unsafe.Pointer to the
// memory region, which would cause a cyclical reference.
//
// The resulting function panics if the mmap operation returns an error, since
// it would mean the integrity of the Go heap is compromised.
func unmap(size int) func(*byte) {
	return func(a *byte) {
		// Create another mapping at the same address to undo the original mapping.
		// This will cause the kernel to repair the slab since we're using the same
		// protection mode and flags as the original mapping for the Go heap.
		//
		// Address           Kbytes     RSS   Dirty Mode  Mapping
		// 000000c000000000    4096     884     884 rw--- [ anon ]
		//
		// Using munmap here would leave an unmapped hole in the heap, compromising
		// its integrity.
		//
		// MmapPtr allocates another unsafe.Pointer at the same address. Even though
		// we discard it here, it may temporarily resurrect the backing array and
		// delay its collection to the next GC cycle.
		_, err := unix.MmapPtr(-1, 0, unsafe.Pointer(a), uintptr(size),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANONYMOUS)
		if err != nil {
			panic(fmt.Errorf("undoing bpf map memory mapping: %w", err))
		}
	}
}

// Size returns the size of the memory-mapped region in bytes.
func (mm *Memory) Size() int {
	return len(mm.b)
}

// Readonly returns true if the memory-mapped region is read-only.
func (mm *Memory) Readonly() bool {
	return mm.ro
}

// ReadAt implements [io.ReaderAt]. Useful for creating a new [io.OffsetWriter].
func (mm *Memory) ReadAt(p []byte, off int64) (int, error) {
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

// WriteAt implements [io.WriterAt]. Useful for creating a new
// [io.SectionReader].
func (mm *Memory) WriteAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}
	if mm.ro {
		return 0, fmt.Errorf("memory-mapped region not writable: %w", ErrReadOnly)
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

// checkMemory ensures value T can be accessed in mm at offset off.
func checkMemory[T any](mm *Memory, off uint64) error {
	if mm.b == nil {
		return fmt.Errorf("memory-mapped region closed")
	}
	if mm.ro {
		return ErrReadOnly
	}

	var t T
	size := binary.Size(t)
	if size < 0 {
		return fmt.Errorf("can't determine size of type %T: %w", t, ErrInvalidType)
	}

	align := internal.Align(off, uint64(size))
	if off != align {
		return fmt.Errorf("unaligned access of memory-mapped region: size %d at offset %d aligns to %d", size, off, align)
	}

	vs, bs := uint64(size), uint64(len(mm.b))
	if off+vs > bs {
		return fmt.Errorf("%d-byte value at offset %d exceeds mmap size of %d bytes", vs, off, bs)
	}

	return nil
}

// reinterp reinterprets a pointer of type In to a pointer of type Out.
func reinterp[Out any, In any](in *In) *Out {
	return (*Out)(unsafe.Pointer(in))
}

// MemoryPointer returns a pointer to a value of type T at offset off in mm.
//
// T must be a fixed-size type according to [binary.Size]. Types containing Go
// pointers are not valid. Memory must be writable, off must be aligned to
// the size of T, and the value must be in bounds of the Memory.
//
// To access read-only memory, use [Memory.ReadAt].
func MemoryPointer[T any](mm *Memory, off uint64) (*T, error) {
	if err := checkMemory[T](mm, off); err != nil {
		return nil, fmt.Errorf("memory pointer: %w", err)
	}
	return reinterp[T](&mm.b[off]), nil
}
