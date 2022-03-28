package btf

import (
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf/types"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/google/go-cmp/cmp"

	qt "github.com/frankban/quicktest"
)

func TestCOREAreTypesCompatible(t *testing.T) {
	tests := []struct {
		a, b       types.Type
		compatible bool
	}{
		{&types.Void{}, &types.Void{}, true},
		{&types.Struct{Name: "a"}, &types.Struct{Name: "b"}, true},
		{&types.Union{Name: "a"}, &types.Union{Name: "b"}, true},
		{&types.Union{Name: "a"}, &types.Struct{Name: "b"}, false},
		{&types.Enum{Name: "a"}, &types.Enum{Name: "b"}, true},
		{&types.Fwd{Name: "a"}, &types.Fwd{Name: "b"}, true},
		{&types.Int{Name: "a", Size: 2}, &types.Int{Name: "b", Size: 4}, true},
		{&types.Int{OffsetBits: 1}, &types.Int{}, false},
		{&types.Pointer{Target: &types.Void{}}, &types.Pointer{Target: &types.Void{}}, true},
		{&types.Pointer{Target: &types.Void{}}, &types.Void{}, false},
		{&types.Array{Type: &types.Void{}}, &types.Array{Type: &types.Void{}}, true},
		{&types.Array{Type: &types.Int{}}, &types.Array{Type: &types.Void{}}, false},
		{&types.FuncProto{Return: &types.Int{}}, &types.FuncProto{Return: &types.Void{}}, false},
		{
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Name: "a", Type: &types.Void{}}}},
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Name: "b", Type: &types.Void{}}}},
			true,
		},
		{
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Type: &types.Void{}}}},
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Type: &types.Int{}}}},
			false,
		},
		{
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Type: &types.Void{}}, {Type: &types.Void{}}}},
			&types.FuncProto{Return: &types.Void{}, Params: []types.FuncParam{{Type: &types.Void{}}}},
			false,
		},
	}

	for _, test := range tests {
		err := coreAreTypesCompatible(test.a, test.b)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		}

		err = coreAreTypesCompatible(test.b, test.a)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected reversed types to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected reversed types to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		}
	}

	for _, invalid := range []types.Type{&types.Var{}, &types.Datasec{}} {
		err := coreAreTypesCompatible(invalid, invalid)
		if errors.Is(err, errImpossibleRelocation) {
			t.Errorf("Expected an error for %T, not errImpossibleRelocation", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCOREAreMembersCompatible(t *testing.T) {
	tests := []struct {
		a, b       types.Type
		compatible bool
	}{
		{&types.Struct{Name: "a"}, &types.Struct{Name: "b"}, true},
		{&types.Union{Name: "a"}, &types.Union{Name: "b"}, true},
		{&types.Union{Name: "a"}, &types.Struct{Name: "b"}, true},
		{&types.Enum{Name: "a"}, &types.Enum{Name: "b"}, false},
		{&types.Enum{Name: "a"}, &types.Enum{Name: "a___foo"}, true},
		{&types.Enum{Name: "a"}, &types.Enum{Name: ""}, true},
		{&types.Fwd{Name: "a"}, &types.Fwd{Name: "b"}, false},
		{&types.Fwd{Name: "a"}, &types.Fwd{Name: "a___foo"}, true},
		{&types.Fwd{Name: "a"}, &types.Fwd{Name: ""}, true},
		{&types.Int{Name: "a", Size: 2}, &types.Int{Name: "b", Size: 4}, true},
		{&types.Int{OffsetBits: 1}, &types.Int{}, false},
		{&types.Pointer{Target: &types.Void{}}, &types.Pointer{Target: &types.Void{}}, true},
		{&types.Pointer{Target: &types.Void{}}, &types.Void{}, false},
		{&types.Array{Type: &types.Int{Size: 1}}, &types.Array{Type: &types.Int{Encoding: types.Signed}}, true},
		{&types.Float{Size: 2}, &types.Float{Size: 4}, true},
	}

	for _, test := range tests {
		err := coreAreMembersCompatible(test.a, test.b)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected members to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected members to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
				continue
			}
		}

		err = coreAreMembersCompatible(test.b, test.a)
		if test.compatible {
			if err != nil {
				t.Errorf("Expected reversed members to be compatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		} else {
			if !errors.Is(err, errImpossibleRelocation) {
				t.Errorf("Expected reversed members to be incompatible: %s\na = %#v\nb = %#v", err, test.a, test.b)
			}
		}
	}

	for _, invalid := range []types.Type{&types.Void{}, &types.FuncProto{}, &types.Var{}, &types.Datasec{}} {
		err := coreAreMembersCompatible(invalid, invalid)
		if errors.Is(err, errImpossibleRelocation) {
			t.Errorf("Expected an error for %T, not errImpossibleRelocation", invalid)
		} else if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCOREAccessor(t *testing.T) {
	for _, valid := range []string{
		"0",
		"1:0",
		"1:0:3:34:10:1",
	} {
		_, err := parseCOREAccessor(valid)
		if err != nil {
			t.Errorf("Parse %q: %s", valid, err)
		}
	}

	for _, invalid := range []string{
		"",
		"-1",
		":",
		"0:",
		":12",
		"4294967296",
	} {
		_, err := parseCOREAccessor(invalid)
		if err == nil {
			t.Errorf("Accepted invalid accessor %q", invalid)
		}
	}
}

func TestCOREFindEnumValue(t *testing.T) {
	a := &types.Enum{Values: []types.EnumValue{{"foo", 23}, {"bar", 42}}}
	b := &types.Enum{Values: []types.EnumValue{
		{"foo___flavour", 0},
		{"bar", 123},
		{"garbage", 3},
	}}

	invalid := []struct {
		name   string
		local  types.Type
		target types.Type
		acc    coreAccessor
		err    error
	}{
		{"o-o-b accessor", a, b, coreAccessor{len(a.Values)}, nil},
		{"long accessor", a, b, coreAccessor{0, 1}, nil},
		{"wrong target", a, &types.Void{}, coreAccessor{0, 1}, nil},
		{
			"no matching value",
			b, a,
			coreAccessor{2},
			errImpossibleRelocation,
		},
	}

	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindEnumValue(test.local, test.acc, test.target)
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("Expected %s, got %s", test.err, err)
			}
			if err == nil {
				t.Fatal("Accepted invalid case")
			}
		})
	}

	valid := []struct {
		name                    string
		local, target           types.Type
		acc                     coreAccessor
		localValue, targetValue int32
	}{
		{"a to b", a, b, coreAccessor{0}, 23, 0},
		{"b to a", b, a, coreAccessor{1}, 123, 42},
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			local, target, err := coreFindEnumValue(test.local, test.acc, test.target)
			qt.Assert(t, err, qt.IsNil)
			qt.Check(t, local.Value, qt.Equals, test.localValue)
			qt.Check(t, target.Value, qt.Equals, test.targetValue)
		})
	}
}

func TestCOREFindField(t *testing.T) {
	ptr := &types.Pointer{}
	u16 := &types.Int{Size: 2}
	u32 := &types.Int{Size: 4}
	aFields := []types.Member{
		{Name: "foo", Type: ptr, OffsetBits: 8},
		{Name: "bar", Type: u16, OffsetBits: 16},
		{Name: "baz", Type: u32, OffsetBits: 32, BitfieldSize: 3},
		{Name: "quux", Type: u32, OffsetBits: 35, BitfieldSize: 10},
		{Name: "quuz", Type: u32, OffsetBits: 45, BitfieldSize: 8},
	}
	bFields := []types.Member{
		{Name: "foo", Type: ptr, OffsetBits: 16},
		{Name: "bar", Type: u32, OffsetBits: 8},
		{Name: "other", OffsetBits: 4},
		// baz is separated out from the other bitfields
		{Name: "baz", Type: u32, OffsetBits: 64, BitfieldSize: 3},
		// quux's type changes u32->u16
		{Name: "quux", Type: u16, OffsetBits: 96, BitfieldSize: 10},
		// quuz becomes a normal field
		{Name: "quuz", Type: u16, OffsetBits: 112},
	}

	aStruct := &types.Struct{Members: aFields, Size: 48}
	bStruct := &types.Struct{Members: bFields, Size: 80}
	aArray := &types.Array{Nelems: 4, Type: u16}
	bArray := &types.Array{Nelems: 3, Type: u32}

	invalid := []struct {
		name          string
		local, target types.Type
		acc           coreAccessor
		err           error
	}{
		{
			"unsupported type",
			&types.Void{}, &types.Void{},
			coreAccessor{0, 0},
			ErrNotSupported,
		},
		{
			"different types",
			&types.Union{}, &types.Array{Type: u16},
			coreAccessor{0},
			errImpossibleRelocation,
		},
		{
			"invalid composite accessor",
			aStruct, aStruct,
			coreAccessor{0, len(aStruct.Members)},
			nil,
		},
		{
			"invalid array accessor",
			aArray, aArray,
			coreAccessor{0, int(aArray.Nelems)},
			nil,
		},
		{
			"o-o-b array accessor",
			aArray, bArray,
			coreAccessor{0, int(bArray.Nelems)},
			errImpossibleRelocation,
		},
		{
			"no match",
			bStruct, aStruct,
			coreAccessor{0, 2},
			errImpossibleRelocation,
		},
		{
			"incompatible match",
			&types.Union{Members: []types.Member{{Name: "foo", Type: &types.Pointer{}}}},
			&types.Union{Members: []types.Member{{Name: "foo", Type: &types.Int{}}}},
			coreAccessor{0, 0},
			errImpossibleRelocation,
		},
	}

	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindField(test.local, test.acc, test.target)
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("Expected %s, got %s", test.err, err)
			}
			if err == nil {
				t.Fatal("Accepted invalid case")
			}
			t.Log(err)
		})
	}

	bytes := func(typ types.Type) uint32 {
		sz, err := types.Sizeof(typ)
		if err != nil {
			t.Fatal(err)
		}
		return uint32(sz)
	}

	anon := func(t types.Type, offset uint32) []types.Member {
		return []types.Member{{Type: t, OffsetBits: offset}}
	}

	anonStruct := func(m ...types.Member) types.Member {
		return types.Member{Type: &types.Struct{Members: m}}
	}

	anonUnion := func(m ...types.Member) types.Member {
		return types.Member{Type: &types.Union{Members: m}}
	}

	valid := []struct {
		name                    string
		local                   types.Type
		target                  types.Type
		acc                     coreAccessor
		localField, targetField coreField
	}{
		{
			"array[0]",
			aArray,
			bArray,
			coreAccessor{0, 0},
			coreField{u16, 0, 0, 0},
			coreField{u32, 0, 0, 0},
		},
		{
			"array[1]",
			aArray,
			bArray,
			coreAccessor{0, 1},
			coreField{u16, bytes(aArray.Type), 0, 0},
			coreField{u32, bytes(bArray.Type), 0, 0},
		},
		{
			"array[0] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 0},
			coreField{u16, bytes(aArray), 0, 0},
			coreField{u32, bytes(bArray), 0, 0},
		},
		{
			"array[2] with base offset",
			aArray,
			bArray,
			coreAccessor{1, 2},
			coreField{u16, bytes(aArray) + 2*bytes(aArray.Type), 0, 0},
			coreField{u32, bytes(bArray) + 2*bytes(bArray.Type), 0, 0},
		},
		{
			"flex array",
			&types.Struct{Members: []types.Member{{Name: "foo", Type: &types.Array{Nelems: 0, Type: u16}}}},
			&types.Struct{Members: []types.Member{{Name: "foo", Type: &types.Array{Nelems: 0, Type: u32}}}},
			coreAccessor{0, 0, 9000},
			coreField{u16, bytes(u16) * 9000, 0, 0},
			coreField{u32, bytes(u32) * 9000, 0, 0},
		},
		{
			"struct.0",
			aStruct, bStruct,
			coreAccessor{0, 0},
			coreField{ptr, 1, 0, 0},
			coreField{ptr, 2, 0, 0},
		},
		{
			"struct.0 anon",
			aStruct, &types.Struct{Members: anon(bStruct, 24)},
			coreAccessor{0, 0},
			coreField{ptr, 1, 0, 0},
			coreField{ptr, 3 + 2, 0, 0},
		},
		{
			"struct.0 with base offset",
			aStruct, bStruct,
			coreAccessor{3, 0},
			coreField{ptr, 3*bytes(aStruct) + 1, 0, 0},
			coreField{ptr, 3*bytes(bStruct) + 2, 0, 0},
		},
		{
			"struct.1",
			aStruct, bStruct,
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 1, 0, 0},
		},
		{
			"struct.1 anon",
			aStruct, &types.Struct{Members: anon(bStruct, 24)},
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 3 + 1, 0, 0},
		},
		{
			"union.1",
			&types.Union{Members: aFields, Size: 32},
			&types.Union{Members: bFields, Size: 32},
			coreAccessor{0, 1},
			coreField{u16, 2, 0, 0},
			coreField{u32, 1, 0, 0},
		},
		{
			"interchangeable composites",
			&types.Struct{
				Members: []types.Member{
					anonStruct(anonUnion(types.Member{Name: "_1", Type: u16})),
				},
			},
			&types.Struct{
				Members: []types.Member{
					anonUnion(anonStruct(types.Member{Name: "_1", Type: u16})),
				},
			},
			coreAccessor{0, 0, 0, 0},
			coreField{u16, 0, 0, 0},
			coreField{u16, 0, 0, 0},
		},
		{
			"struct.2 (bitfield baz)",
			aStruct, bStruct,
			coreAccessor{0, 2},
			coreField{u32, 4, 0, 3},
			coreField{u32, 8, 0, 3},
		},
		{
			"struct.3 (bitfield quux)",
			aStruct, bStruct,
			coreAccessor{0, 3},
			coreField{u32, 4, 3, 10},
			coreField{u16, 12, 0, 10},
		},
		{
			"struct.4 (bitfield quuz)",
			aStruct, bStruct,
			coreAccessor{0, 4},
			coreField{u32, 4, 13, 8},
			coreField{u16, 14, 0, 0},
		},
	}

	allowCoreField := cmp.AllowUnexported(coreField{})

	checkCOREField := func(t *testing.T, which string, got, want coreField) {
		t.Helper()
		if diff := cmp.Diff(want, got, allowCoreField); diff != "" {
			t.Errorf("%s mismatch (-want +got):\n%s", which, diff)
		}
	}

	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			localField, targetField, err := coreFindField(test.local, test.acc, test.target)
			qt.Assert(t, err, qt.IsNil)
			checkCOREField(t, "local", localField, test.localField)
			checkCOREField(t, "target", targetField, test.targetField)
		})
	}
}

func TestCOREFindFieldCyclical(t *testing.T) {
	members := []types.Member{{Name: "foo", Type: &types.Pointer{}}}

	cyclicStruct := &types.Struct{}
	cyclicStruct.Members = []types.Member{{Type: cyclicStruct}}

	cyclicUnion := &types.Union{}
	cyclicUnion.Members = []types.Member{{Type: cyclicUnion}}

	cyclicArray := &types.Array{Nelems: 1}
	cyclicArray.Type = &types.Pointer{Target: cyclicArray}

	tests := []struct {
		name          string
		local, cyclic types.Type
	}{
		{"struct", &types.Struct{Members: members}, cyclicStruct},
		{"union", &types.Union{Members: members}, cyclicUnion},
		{"array", &types.Array{Nelems: 2, Type: &types.Int{}}, cyclicArray},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := coreFindField(test.local, coreAccessor{0, 0}, test.cyclic)
			if !errors.Is(err, errImpossibleRelocation) {
				t.Fatal("Should return errImpossibleRelocation, got", err)
			}
		})
	}
}

func TestCORERelocation(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/*.elf"), func(t *testing.T, file string) {
		rd, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()

		spec, err := LoadSpecFromReader(rd)
		if err != nil {
			t.Fatal(err)
		}

		errs := map[string]error{
			"err_ambiguous":         errAmbiguousRelocation,
			"err_ambiguous_flavour": errAmbiguousRelocation,
		}

		for section := range spec.funcInfos {
			name := strings.TrimPrefix(section, "socket_filter/")
			t.Run(name, func(t *testing.T) {
				prog, err := spec.Program(section)
				if err != nil {
					t.Fatal("Retrieve program:", err)
				}

				relos, err := CORERelocate(prog.Spec(), spec, prog.CORERelos)
				if want := errs[name]; want != nil {
					if !errors.Is(err, want) {
						t.Fatal("Expected", want, "got", err)
					}
					return
				}

				if err != nil {
					t.Fatal("Can't relocate against itself:", err)
				}

				for offset, relo := range relos {
					if want := relo.Local; relo.Kind.validateLocal && want != relo.Target {
						// Since we're relocating against ourselves both values
						// should match.
						t.Errorf("offset %d: local %v doesn't match target %d (kind %s)", offset, relo.Local, relo.Target, relo.Kind)
					}
				}
			})
		}
	})
}

func TestCORECopyWithoutQualifiers(t *testing.T) {
	qualifiers := []struct {
		name string
		fn   func(types.Type) types.Type
	}{
		{"const", func(t types.Type) types.Type { return &types.Const{Type: t} }},
		{"volatile", func(t types.Type) types.Type { return &types.Volatile{Type: t} }},
		{"restrict", func(t types.Type) types.Type { return &types.Restrict{Type: t} }},
		{"typedef", func(t types.Type) types.Type { return &types.Typedef{Type: t} }},
	}

	for _, test := range qualifiers {
		t.Run(test.name+" cycle", func(t *testing.T) {
			root := &types.Volatile{}
			root.Type = test.fn(root)

			_, err := types.CopyType(root, types.SkipQualifiersAndTypedefs)
			qt.Assert(t, err, qt.Not(qt.IsNil))
		})
	}

	for _, a := range qualifiers {
		for _, b := range qualifiers {
			t.Run(a.name+" "+b.name, func(t *testing.T) {
				v := a.fn(&types.Pointer{Target: b.fn(&types.Int{Name: "z"})})
				want := &types.Pointer{Target: &types.Int{Name: "z"}}

				got, err := types.CopyType(v, types.SkipQualifiersAndTypedefs)
				qt.Assert(t, err, qt.IsNil)
				qt.Assert(t, got, qt.DeepEquals, want)
			})
		}
	}

	t.Run("long chain", func(t *testing.T) {
		root := &types.Int{Name: "abc"}
		v := types.Type(root)
		for i := 0; i < maxTypeDepth; i++ {
			q := qualifiers[rand.Intn(len(qualifiers))]
			v = q.fn(v)
			t.Log(q.name)
		}

		got, err := types.CopyType(v, types.SkipQualifiersAndTypedefs)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, got, qt.DeepEquals, root)
	})
}
