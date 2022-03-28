//go:generate stringer -linecomment -output=btf_types_string.go -type=FuncLinkage,VarLinkage
package types

import (
	"fmt"
	"math"
	"strings"
)

const maxTypeDepth = 32

// TypeID identifies a type in a BTF section.
type TypeID uint32

// ID implements part of the Type interface.
func (tid TypeID) ID() TypeID {
	return tid
}

// Type represents a type described by BTF.
type Type interface {
	// The type ID of the Type within this BTF spec.
	ID() TypeID

	// Name of the type, empty for anonymous types and types that cannot
	// carry a name, like Void and Pointer.
	TypeName() string

	// Make a copy of the type, without copying Type members.
	copy() Type

	// Enumerate all nested Types. Repeated calls must visit nested
	// types in the same order.
	Walk(*TypeDeque)

	String() string
}

type Types []Type

// Copy copies Types recursively.
//
// Types may form a cycle.
//
// Returns any errors from transform verbatim.
func (types Types) Copy(transform func(Type) (Type, error)) ([]Type, error) {
	result := make([]Type, len(types))
	copy(result, types)

	copies := make(copier)
	for i := range result {
		if err := copies.copy(&result[i], transform); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// FuncLinkage describes BTF function linkage metadata.
type FuncLinkage int

// Equivalent of enum btf_func_linkage.
const (
	StaticFunc FuncLinkage = iota // static
	GlobalFunc                    // global
	ExternFunc                    // extern
)

// VarLinkage describes BTF variable linkage metadata.
type VarLinkage int

const (
	StaticVar VarLinkage = iota // static
	GlobalVar                   // global
	ExternVar                   // extern
)

var (
	_ Type = (*Int)(nil)
	_ Type = (*Struct)(nil)
	_ Type = (*Union)(nil)
	_ Type = (*Enum)(nil)
	_ Type = (*Fwd)(nil)
	_ Type = (*Func)(nil)
	_ Type = (*Typedef)(nil)
	_ Type = (*Var)(nil)
	_ Type = (*Datasec)(nil)
	_ Type = (*Float)(nil)
)

// Void is the unit type of BTF.
type Void struct{}

func (v *Void) ID() TypeID       { return 0 }
func (v *Void) String() string   { return "void#0" }
func (v *Void) TypeName() string { return "" }
func (v *Void) size() uint32     { return 0 }
func (v *Void) copy() Type       { return (*Void)(nil) }
func (v *Void) Walk(*TypeDeque)  {}

type IntEncoding byte

const (
	Signed IntEncoding = 1 << iota
	Char
	Bool
)

func (ie IntEncoding) IsSigned() bool {
	return ie&Signed != 0
}

func (ie IntEncoding) IsChar() bool {
	return ie&Char != 0
}

func (ie IntEncoding) IsBool() bool {
	return ie&Bool != 0
}

// Int is an integer of a given length.
type Int struct {
	TypeID

	Name string

	// The size of the integer in bytes.
	Size     uint32
	Encoding IntEncoding
	// OffsetBits is the starting bit offset. Currently always 0.
	// See https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-int
	OffsetBits uint32
	Bits       byte
}

func (i *Int) String() string {
	var s strings.Builder

	switch {
	case i.Encoding.IsChar():
		s.WriteString("char")
	case i.Encoding.IsBool():
		s.WriteString("bool")
	default:
		if !i.Encoding.IsSigned() {
			s.WriteRune('u')
		}
		s.WriteString("int")
		fmt.Fprintf(&s, "%d", i.Size*8)
	}

	fmt.Fprintf(&s, "#%d", i.TypeID)

	if i.Bits > 0 {
		fmt.Fprintf(&s, "[bits=%d]", i.Bits)
	}

	return s.String()
}

func (i *Int) TypeName() string { return i.Name }
func (i *Int) size() uint32     { return i.Size }
func (i *Int) Walk(*TypeDeque)  {}
func (i *Int) copy() Type {
	cpy := *i
	return &cpy
}

func (i *Int) IsBitfield() bool {
	return i.OffsetBits > 0
}

// Pointer is a pointer to another type.
type Pointer struct {
	TypeID
	Target Type
}

func (p *Pointer) String() string {
	return fmt.Sprintf("pointer#%d[target=#%d]", p.TypeID, p.Target.ID())
}

func (p *Pointer) TypeName() string    { return "" }
func (p *Pointer) size() uint32        { return 8 }
func (p *Pointer) Walk(tdq *TypeDeque) { tdq.push(&p.Target) }
func (p *Pointer) copy() Type {
	cpy := *p
	return &cpy
}

// Array is an array with a fixed number of elements.
type Array struct {
	TypeID
	Type   Type
	Nelems uint32
}

func (arr *Array) String() string {
	return fmt.Sprintf("array#%d[type=#%d n=%d]", arr.TypeID, arr.Type.ID(), arr.Nelems)
}

func (arr *Array) TypeName() string { return "" }

func (arr *Array) Walk(tdq *TypeDeque) { tdq.push(&arr.Type) }
func (arr *Array) copy() Type {
	cpy := *arr
	return &cpy
}

// Struct is a compound type of consecutive members.
type Struct struct {
	TypeID
	Name string
	// The size of the struct including padding, in bytes
	Size    uint32
	Members []Member
}

func (s *Struct) String() string {
	return fmt.Sprintf("struct#%d[%q]", s.TypeID, s.Name)
}

func (s *Struct) TypeName() string { return s.Name }

func (s *Struct) size() uint32 { return s.Size }

func (s *Struct) Walk(tdq *TypeDeque) {
	for i := range s.Members {
		tdq.push(&s.Members[i].Type)
	}
}

func (s *Struct) copy() Type {
	cpy := *s
	cpy.Members = copyMembers(s.Members)
	return &cpy
}

func (s *Struct) GetMembers() []Member {
	return s.Members
}

// Union is a compound type where members occupy the same memory.
type Union struct {
	TypeID
	Name string
	// The size of the union including padding, in bytes.
	Size    uint32
	Members []Member
}

func (u *Union) String() string {
	return fmt.Sprintf("union#%d[%q]", u.TypeID, u.Name)
}

func (u *Union) TypeName() string { return u.Name }

func (u *Union) size() uint32 { return u.Size }

func (u *Union) Walk(tdq *TypeDeque) {
	for i := range u.Members {
		tdq.push(&u.Members[i].Type)
	}
}

func (u *Union) copy() Type {
	cpy := *u
	cpy.Members = copyMembers(u.Members)
	return &cpy
}

func (u *Union) GetMembers() []Member {
	return u.Members
}

func copyMembers(orig []Member) []Member {
	cpy := make([]Member, len(orig))
	copy(cpy, orig)
	return cpy
}

// Member is part of a Struct or Union.
//
// It is not a valid Type.
type Member struct {
	Name string
	Type Type
	// OffsetBits is the bit offset of this member.
	OffsetBits   uint32
	BitfieldSize uint32
}

// Enum lists possible values.
type Enum struct {
	TypeID
	Name   string
	Values []EnumValue
}

func (e *Enum) String() string {
	return fmt.Sprintf("enum#%d[%q]", e.TypeID, e.Name)
}

func (e *Enum) TypeName() string { return e.Name }

// EnumValue is part of an Enum
//
// Is is not a valid Type
type EnumValue struct {
	Name  string
	Value int32
}

func (e *Enum) size() uint32    { return 4 }
func (e *Enum) Walk(*TypeDeque) {}
func (e *Enum) copy() Type {
	cpy := *e
	cpy.Values = make([]EnumValue, len(e.Values))
	copy(cpy.Values, e.Values)
	return &cpy
}

// FwdKind is the type of forward declaration.
type FwdKind int

// Valid types of forward declaration.
const (
	FwdStruct FwdKind = iota
	FwdUnion
)

func (fk FwdKind) String() string {
	switch fk {
	case FwdStruct:
		return "struct"
	case FwdUnion:
		return "union"
	default:
		return fmt.Sprintf("%T(%d)", fk, int(fk))
	}
}

// Fwd is a forward declaration of a Type.
type Fwd struct {
	TypeID
	Name string
	Kind FwdKind
}

func (f *Fwd) String() string {
	return fmt.Sprintf("fwd#%d[%s %q]", f.TypeID, f.Kind, f.Name)
}

func (f *Fwd) TypeName() string { return f.Name }

func (f *Fwd) Walk(*TypeDeque) {}
func (f *Fwd) copy() Type {
	cpy := *f
	return &cpy
}

// Typedef is an alias of a Type.
type Typedef struct {
	TypeID
	Name string
	Type Type
}

func (td *Typedef) String() string {
	return fmt.Sprintf("typedef#%d[%q #%d]", td.TypeID, td.Name, td.Type.ID())
}

func (td *Typedef) TypeName() string { return td.Name }

func (td *Typedef) Walk(tdq *TypeDeque) { tdq.push(&td.Type) }
func (td *Typedef) copy() Type {
	cpy := *td
	return &cpy
}

// Volatile is a qualifier.
type Volatile struct {
	TypeID
	Type Type
}

func (v *Volatile) String() string {
	return fmt.Sprintf("volatile#%d[#%d]", v.TypeID, v.Type.ID())
}

func (v *Volatile) TypeName() string { return "" }

func (v *Volatile) qualify() Type       { return v.Type }
func (v *Volatile) Walk(tdq *TypeDeque) { tdq.push(&v.Type) }
func (v *Volatile) copy() Type {
	cpy := *v
	return &cpy
}

// Const is a qualifier.
type Const struct {
	TypeID
	Type Type
}

func (c *Const) String() string {
	return fmt.Sprintf("const#%d[#%d]", c.TypeID, c.Type.ID())
}

func (c *Const) TypeName() string { return "" }

func (c *Const) qualify() Type       { return c.Type }
func (c *Const) Walk(tdq *TypeDeque) { tdq.push(&c.Type) }
func (c *Const) copy() Type {
	cpy := *c
	return &cpy
}

// Restrict is a qualifier.
type Restrict struct {
	TypeID
	Type Type
}

func (r *Restrict) String() string {
	return fmt.Sprintf("restrict#%d[#%d]", r.TypeID, r.Type.ID())
}

func (r *Restrict) TypeName() string { return "" }

func (r *Restrict) qualify() Type       { return r.Type }
func (r *Restrict) Walk(tdq *TypeDeque) { tdq.push(&r.Type) }
func (r *Restrict) copy() Type {
	cpy := *r
	return &cpy
}

// Func is a function definition.
type Func struct {
	TypeID
	Name    string
	Type    Type
	Linkage FuncLinkage
}

func (f *Func) String() string {
	return fmt.Sprintf("func#%d[%s %q proto=#%d]", f.TypeID, f.Linkage, f.Name, f.Type.ID())
}

func (f *Func) TypeName() string { return f.Name }

func (f *Func) Walk(tdq *TypeDeque) { tdq.push(&f.Type) }
func (f *Func) copy() Type {
	cpy := *f
	return &cpy
}

// FuncProto is a function declaration.
type FuncProto struct {
	TypeID
	Return Type
	Params []FuncParam
}

func (fp *FuncProto) String() string {
	var s strings.Builder
	fmt.Fprintf(&s, "proto#%d[", fp.TypeID)
	for _, param := range fp.Params {
		fmt.Fprintf(&s, "%q=#%d, ", param.Name, param.Type.ID())
	}
	fmt.Fprintf(&s, "return=#%d]", fp.Return.ID())
	return s.String()
}

func (fp *FuncProto) TypeName() string { return "" }

func (fp *FuncProto) Walk(tdq *TypeDeque) {
	tdq.push(&fp.Return)
	for i := range fp.Params {
		tdq.push(&fp.Params[i].Type)
	}
}

func (fp *FuncProto) copy() Type {
	cpy := *fp
	cpy.Params = make([]FuncParam, len(fp.Params))
	copy(cpy.Params, fp.Params)
	return &cpy
}

type FuncParam struct {
	Name string
	Type Type
}

// Var is a global variable.
type Var struct {
	TypeID
	Name    string
	Type    Type
	Linkage VarLinkage
}

func (v *Var) String() string {
	return fmt.Sprintf("var#%d[%s %q]", v.TypeID, v.Linkage, v.Name)
}

func (v *Var) TypeName() string { return v.Name }

func (v *Var) Walk(tdq *TypeDeque) { tdq.push(&v.Type) }
func (v *Var) copy() Type {
	cpy := *v
	return &cpy
}

// Datasec is a global program section containing data.
type Datasec struct {
	TypeID
	Name string
	Size uint32
	Vars []VarSecinfo
}

func (ds *Datasec) String() string {
	return fmt.Sprintf("section#%d[%q]", ds.TypeID, ds.Name)
}

func (ds *Datasec) TypeName() string { return ds.Name }

func (ds *Datasec) size() uint32 { return ds.Size }

func (ds *Datasec) Walk(tdq *TypeDeque) {
	for i := range ds.Vars {
		tdq.push(&ds.Vars[i].Type)
	}
}

func (ds *Datasec) copy() Type {
	cpy := *ds
	cpy.Vars = make([]VarSecinfo, len(ds.Vars))
	copy(cpy.Vars, ds.Vars)
	return &cpy
}

// VarSecinfo describes variable in a Datasec.
//
// It is not a valid Type.
type VarSecinfo struct {
	Type   Type
	Offset uint32
	Size   uint32
}

// Float is a float of a given length.
type Float struct {
	TypeID
	Name string

	// The size of the float in bytes.
	Size uint32
}

func (f *Float) String() string {
	return fmt.Sprintf("float%d#%d[%q]", f.Size*8, f.TypeID, f.Name)
}

func (f *Float) TypeName() string { return f.Name }
func (f *Float) size() uint32     { return f.Size }
func (f *Float) Walk(*TypeDeque)  {}
func (f *Float) copy() Type {
	cpy := *f
	return &cpy
}

type sizer interface {
	size() uint32
}

var (
	_ sizer = (*Int)(nil)
	_ sizer = (*Pointer)(nil)
	_ sizer = (*Struct)(nil)
	_ sizer = (*Union)(nil)
	_ sizer = (*Enum)(nil)
	_ sizer = (*Datasec)(nil)
)

type qualifier interface {
	qualify() Type
}

var (
	_ qualifier = (*Const)(nil)
	_ qualifier = (*Restrict)(nil)
	_ qualifier = (*Volatile)(nil)
)

// Sizeof returns the size of a type in bytes.
//
// Returns an error if the size can't be computed.
func Sizeof(typ Type) (int, error) {
	var (
		n    = int64(1)
		elem int64
	)

	for i := 0; i < maxTypeDepth; i++ {
		switch v := typ.(type) {
		case *Array:
			if n > 0 && int64(v.Nelems) > math.MaxInt64/n {
				return 0, fmt.Errorf("type %s: overflow", typ)
			}

			// Arrays may be of zero length, which allows
			// n to be zero as well.
			n *= int64(v.Nelems)
			typ = v.Type
			continue

		case sizer:
			elem = int64(v.size())

		case *Typedef:
			typ = v.Type
			continue

		case qualifier:
			typ = v.qualify()
			continue

		default:
			return 0, fmt.Errorf("unsized type %T", typ)
		}

		if n > 0 && elem > math.MaxInt64/n {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		size := n * elem
		if int64(int(size)) != size {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		return int(size), nil
	}

	return 0, fmt.Errorf("type %s: exceeded type depth", typ)
}

// alignof returns the alignment of a type.
//
// Currently only supports the subset of types necessary for bitfield relocations.
func Alignof(typ Type) (int, error) {
	typ, err := SkipQualifiersAndTypedefs(typ)
	if err != nil {
		return 0, err
	}

	switch t := typ.(type) {
	case *Enum:
		return int(t.size()), nil
	case *Int:
		return int(t.Size), nil
	default:
		return 0, fmt.Errorf("can't calculate alignment of %T", t)
	}
}

// Copy a Type recursively.
func Copy(typ Type) Type {
	typ, _ = CopyType(typ, nil)
	return typ
}

// copy a Type recursively.
//
// typ may form a cycle.
//
// Returns any errors from transform verbatim.
func CopyType(typ Type, transform func(Type) (Type, error)) (Type, error) {
	copies := make(copier)
	return typ, copies.copy(&typ, transform)
}

type copier map[Type]Type

func (c copier) copy(typ *Type, transform func(Type) (Type, error)) error {
	var work TypeDeque
	for t := typ; t != nil; t = work.pop() {
		// *t is the identity of the type.
		if cpy := c[*t]; cpy != nil {
			*t = cpy
			continue
		}

		var cpy Type
		if transform != nil {
			tf, err := transform(*t)
			if err != nil {
				return fmt.Errorf("copy %s: %w", *t, err)
			}
			cpy = tf.copy()
		} else {
			cpy = (*t).copy()
		}

		c[*t] = cpy
		*t = cpy

		// Mark any nested types for copying.
		cpy.Walk(&work)
	}

	return nil
}

// TypeDeque keeps track of pointers to types which still
// need to be visited.
type TypeDeque struct {
	types       []*Type
	read, write uint64
	mask        uint64
}

func (dq *TypeDeque) empty() bool {
	return dq.read == dq.write
}

// push adds a type to the stack.
func (dq *TypeDeque) push(t *Type) {
	if dq.write-dq.read < uint64(len(dq.types)) {
		dq.types[dq.write&dq.mask] = t
		dq.write++
		return
	}

	new := len(dq.types) * 2
	if new == 0 {
		new = 8
	}

	types := make([]*Type, new)
	pivot := dq.read & dq.mask
	n := copy(types, dq.types[pivot:])
	n += copy(types[n:], dq.types[:pivot])
	types[n] = t

	dq.types = types
	dq.mask = uint64(new) - 1
	dq.read, dq.write = 0, uint64(n+1)
}

// Shift returns the first element or null.
func (dq *TypeDeque) Shift() *Type {
	if dq.empty() {
		return nil
	}

	index := dq.read & dq.mask
	t := dq.types[index]
	dq.types[index] = nil
	dq.read++
	return t
}

// pop returns the last element or null.
func (dq *TypeDeque) pop() *Type {
	if dq.empty() {
		return nil
	}

	dq.write--
	index := dq.write & dq.mask
	t := dq.types[index]
	dq.types[index] = nil
	return t
}

// all returns all elements.
//
// The deque is empty after calling this method.
func (dq *TypeDeque) all() []*Type {
	length := dq.write - dq.read
	types := make([]*Type, 0, length)
	for t := dq.Shift(); t != nil; t = dq.Shift() {
		types = append(types, t)
	}
	return types
}

// UnderlyingType skips qualifiers and Typedefs.
//
// May return typ verbatim if too many types have to be skipped to protect against
// circular Types.
func UnderlyingType(typ Type) Type {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result
		}
	}
	// Return the original argument, since we can't find an underlying type.
	return typ
}
