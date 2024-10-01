package ebpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sysenc"
)

// VariableSpec is a convenience wrapper for modifying global variables of a
// CollectionSpec before loading it into the kernel.
//
// All operations on a VariableSpec's underlying MapSpec are performed in the
// host's native endianness.
type VariableSpec struct {
	name   string
	offset uint64
	size   uint64

	m *MapSpec
	t btf.Type
}

// Set sets the value of the VariableSpec to the provided input using the host's
// native endianness.
func (s *VariableSpec) Set(in any) error {
	buf, err := sysenc.Marshal(in, int(s.size))
	if err != nil {
		return fmt.Errorf("marshaling value %s: %w", s.name, err)
	}

	b, _, err := s.m.dataSection()
	if err != nil {
		return fmt.Errorf("getting data section of map %s: %w", s.m.Name, err)
	}

	if int(s.offset+s.size) > len(b) {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", s.offset, s.size, s.name)
	}

	// MapSpec.Copy() performs a shallow copy. Fully copy the byte slice
	// to avoid any changes affecting other copies of the MapSpec.
	cpy := make([]byte, len(b))
	copy(cpy, b)

	buf.CopyTo(cpy[s.offset : s.offset+s.size])

	s.m.Contents[0] = MapKV{Key: uint32(0), Value: cpy}

	return nil
}

// Get writes the value of the VariableSpec to the provided output using the
// host's native endianness.
func (s *VariableSpec) Get(out any) error {
	b, _, err := s.m.dataSection()
	if err != nil {
		return fmt.Errorf("getting data section of map %s: %w", s.m.Name, err)
	}

	if int(s.offset+s.size) > len(b) {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", s.offset, s.size, s.name)
	}

	if err := sysenc.Unmarshal(out, b[s.offset:s.offset+s.size]); err != nil {
		return fmt.Errorf("unmarshaling value: %w", err)
	}

	return nil
}

// Size returns the size of the variable in bytes.
func (s *VariableSpec) Size() uint64 {
	return s.size
}

// Constant returns true if the VariableSpec represents a variable that is
// read-only from the perspective of the BPF program.
func (s *VariableSpec) Constant() bool {
	return s.m.readOnly()
}

// Type returns the BTF type of the variable. It contains the [btf.Var] wrapping
// the underlying variable's type.
func (s *VariableSpec) Type() btf.Type {
	return s.t
}

func (s *VariableSpec) String() string {
	return fmt.Sprintf("%s (type=%v, map=%s, offset=%d, size=%d)", s.name, s.t, s.m.Name, s.offset, s.size)
}

// copy returns a new VariableSpec with the same values as the original,
// but with a different underlying MapSpec. This is useful when copying a
// CollectionSpec. Returns nil if a MapSpec with the same name is not found.
func (s *VariableSpec) copy(cpy *CollectionSpec) *VariableSpec {
	out := &VariableSpec{
		name:   s.name,
		offset: s.offset,
		size:   s.size,
		t:      s.t,
	}

	// Attempt to find a MapSpec with the same name in the copied CollectionSpec.
	for _, m := range cpy.Maps {
		if m.Name == s.m.Name {
			out.m = m
			return out
		}
	}

	return nil
}

// Variable is a convenience wrapper for modifying global variables of a
// Collection after loading it into the kernel. Operations on a Variable are
// performed using direct memory access, bypassing the BPF map syscall API.
//
// Requires Linux 5.5 and later, or a kernel supporting BPF_F_MMAPABLE.
type Variable struct {
	name   string
	offset uint64
	size   uint64
	t      btf.Type

	mm *Memory
}

// Size returns the size of the variable.
func (v *Variable) Size() uint64 {
	return v.size
}

// Constant returns true if the Variable represents a variable that is read-only
// after loading the Collection into the kernel.
func (v *Variable) Constant() bool {
	return v.mm.Readonly()
}

// Type returns the BTF type of the variable. It contains the [btf.Var] wrapping
// the underlying variable's type.
func (v *Variable) Type() btf.Type {
	return v.t
}

func (v *Variable) String() string {
	return fmt.Sprintf("%s (type=%v)", v.name, v.t)
}

// Set the value of the Variable to the provided input. The input must marshal
// to the same length as the size of the Variable.
func (v *Variable) Set(in any) error {
	if v.Constant() {
		return fmt.Errorf("variable %s: %w", v.name, ErrReadOnly)
	}

	buf, err := sysenc.Marshal(in, int(v.size))
	if err != nil {
		return fmt.Errorf("marshaling value %s: %w", v.name, err)
	}

	if int(v.offset+v.size) > v.mm.Size() {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", v.offset, v.size, v.name)
	}

	if _, err := v.mm.WriteAt(buf.Bytes(), int64(v.offset)); err != nil {
		return fmt.Errorf("writing value to %s: %w", v.name, err)
	}

	return nil
}

// Get writes the value of the Variable to the provided output. The output must
// be a pointer to a value whose size matches the Variable.
func (v *Variable) Get(out any) error {
	if int(v.offset+v.size) > v.mm.Size() {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", v.offset, v.size, v.name)
	}

	b := make([]byte, v.size)
	if _, err := v.mm.ReadAt(b, int64(v.offset)); err != nil {
		return fmt.Errorf("reading value from %s: %w", v.name, err)
	}

	if err := sysenc.Unmarshal(out, b); err != nil {
		return fmt.Errorf("unmarshaling value: %w", err)
	}

	return nil
}

func checkVariable[T any](v *Variable) error {
	if v.Constant() {
		return ErrReadOnly
	}

	var t T
	size := binary.Size(t)
	if size < 0 {
		return fmt.Errorf("can't determine size of type %T: %w", t, ErrInvalidType)
	}

	if v.size != uint64(size) {
		return fmt.Errorf("can't create %d-byte accessor to %d-byte variable", size, v.size)
	}
	return nil
}

// VariablePointer returns a pointer to a value of type T that has its
// underlying memory mapped to the memory representing the Variable. Accessing a
// constant Variable is not supported.
//
// T must be a fixed-size type according to [binary.Size]. Types containing Go
// pointers are not valid.
//
// When accessing structs, embedding [structs.HostLayout] may help ensure the
// layout of the Go struct matches the one in the BPF C program.
func VariablePointer[T any](v *Variable) (*T, error) {
	if err := checkVariable[T](v); err != nil {
		return nil, fmt.Errorf("variable pointer %s: %w", v.name, err)
	}
	return MemoryPointer[T](v.mm, v.offset)
}
