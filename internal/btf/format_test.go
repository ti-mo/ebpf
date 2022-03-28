package btf

import (
	"errors"
	"fmt"
	"go/format"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf/types"
)

func TestGoTypeDeclaration(t *testing.T) {
	tests := []struct {
		typ    types.Type
		output string
	}{
		{&types.Int{Size: 1}, "type t uint8"},
		{&types.Int{Size: 1, Encoding: types.Bool}, "type t bool"},
		{&types.Int{Size: 2, Encoding: types.Bool}, "type t uint16"},
		{&types.Int{Size: 1, Encoding: types.Char}, "type t uint8"},
		{&types.Int{Size: 1, Encoding: types.Char | types.Signed}, "type t int8"},
		{&types.Int{Size: 2, Encoding: types.Char}, "type t uint16"},
		{&types.Int{Size: 2, Encoding: types.Signed}, "type t int16"},
		{&types.Int{Size: 4, Encoding: types.Signed}, "type t int32"},
		{&types.Int{Size: 8}, "type t uint64"},
		{&types.Typedef{Name: "frob", Type: &types.Int{Size: 8}}, "type t uint64"},
		{&types.Int{Size: 16}, "type t uint128"},
		{&types.Enum{Values: []types.EnumValue{{"FOO", 32}}}, "type t int32; const ( tFOO t = 32; )"},
		{&types.Array{Nelems: 2, Type: &types.Int{Size: 1}}, "type t [2]uint8"},
		{
			&types.Union{
				Size: 8,
				Members: []types.Member{
					{Name: "a", Type: &types.Int{Size: 4}},
					{Name: "b", Type: &types.Int{Size: 8}},
				},
			},
			"type t struct { a uint32; _ [4]byte; }",
		},
		{
			&types.Struct{
				Name: "field padding",
				Size: 16,
				Members: []types.Member{
					{Name: "frob", Type: &types.Int{Size: 4}, OffsetBits: 0},
					{Name: "foo", Type: &types.Int{Size: 8}, OffsetBits: 8 * 8},
				},
			},
			"type t struct { frob uint32; _ [4]byte; foo uint64; }",
		},
		{
			&types.Struct{
				Name: "end padding",
				Size: 16,
				Members: []types.Member{
					{Name: "foo", Type: &types.Int{Size: 8}, OffsetBits: 0},
					{Name: "frob", Type: &types.Int{Size: 4}, OffsetBits: 8 * 8},
				},
			},
			"type t struct { foo uint64; frob uint32; _ [4]byte; }",
		},
		{
			&types.Struct{
				Name: "bitfield",
				Size: 8,
				Members: []types.Member{
					{Name: "foo", Type: &types.Int{Size: 4}, OffsetBits: 0, BitfieldSize: 1},
					{Name: "frob", Type: &types.Int{Size: 4}, OffsetBits: 4 * 8},
				},
			},
			"type t struct { _ [4]byte /* unsupported bitfield */; frob uint32; }",
		},
		{
			&types.Struct{
				Name: "nested",
				Size: 8,
				Members: []types.Member{
					{
						Name: "foo",
						Type: &types.Struct{
							Size: 4,
							Members: []types.Member{
								{Name: "bar", Type: &types.Int{Size: 4}, OffsetBits: 0},
							},
						},
					},
					{Name: "frob", Type: &types.Int{Size: 4}, OffsetBits: 4 * 8},
				},
			},
			"type t struct { foo struct { bar uint32; }; frob uint32; }",
		},
		{
			&types.Struct{
				Name: "nested anon union",
				Size: 8,
				Members: []types.Member{
					{
						Name: "",
						Type: &types.Union{
							Size: 4,
							Members: []types.Member{
								{Name: "foo", Type: &types.Int{Size: 4}, OffsetBits: 0},
								{Name: "bar", Type: &types.Int{Size: 4}, OffsetBits: 0},
							},
						},
					},
				},
			},
			"type t struct { foo uint32; _ [4]byte; }",
		},
		{
			&types.Datasec{
				Size: 16,
				Vars: []types.VarSecinfo{
					{&types.Var{Name: "s", Type: &types.Int{Size: 2}, Linkage: types.StaticVar}, 0, 2},
					{&types.Var{Name: "g", Type: &types.Int{Size: 4}, Linkage: types.GlobalVar}, 4, 4},
					{&types.Var{Name: "e", Type: &types.Int{Size: 8}, Linkage: types.ExternVar}, 8, 8},
				},
			},
			"type t struct { _ [4]byte; g uint32; _ [8]byte; }",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			have := mustGoTypeDeclaration(t, test.typ, nil, nil)
			if have != test.output {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", test.output, have)
			}
		})
	}
}

func TestGoTypeDeclarationNamed(t *testing.T) {
	e1 := &types.Enum{Name: "e1"}
	s1 := &types.Struct{
		Name: "s1",
		Size: 4,
		Members: []types.Member{
			{Name: "frob", Type: e1},
		},
	}
	s2 := &types.Struct{
		Name: "s2",
		Size: 4,
		Members: []types.Member{
			{Name: "frood", Type: s1},
		},
	}
	td := &types.Typedef{Name: "td", Type: e1}
	arr := &types.Array{Nelems: 1, Type: td}

	tests := []struct {
		typ    types.Type
		named  []types.Type
		output string
	}{
		{e1, []types.Type{e1}, "type t int32"},
		{s1, []types.Type{e1, s1}, "type t struct { frob E1; }"},
		{s2, []types.Type{e1}, "type t struct { frood struct { frob E1; }; }"},
		{s2, []types.Type{e1, s1}, "type t struct { frood S1; }"},
		{td, nil, "type t int32"},
		{td, []types.Type{td}, "type t int32"},
		{arr, []types.Type{td}, "type t [1]TD"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			names := make(map[types.Type]string)
			for _, t := range test.named {
				names[t] = strings.ToUpper(t.TypeName())
			}

			have := mustGoTypeDeclaration(t, test.typ, names, nil)
			if have != test.output {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", test.output, have)
			}
		})
	}
}

func TestGoTypeDeclarationQualifiers(t *testing.T) {
	i := &types.Int{Size: 4}
	want := mustGoTypeDeclaration(t, i, nil, nil)

	tests := []struct {
		typ types.Type
	}{
		{&types.Volatile{Type: i}},
		{&types.Const{Type: i}},
		{&types.Restrict{Type: i}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			have := mustGoTypeDeclaration(t, test.typ, nil, nil)
			if have != want {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", want, have)
			}
		})
	}
}

func TestGoTypeDeclarationCycle(t *testing.T) {
	s := &types.Struct{Name: "cycle"}
	s.Members = []types.Member{{Name: "f", Type: s}}

	var gf GoFormatter
	_, err := gf.TypeDeclaration("t", s)
	if !errors.Is(err, errNestedTooDeep) {
		t.Fatal("Expected errNestedTooDeep, got", err)
	}
}

func mustGoTypeDeclaration(tb testing.TB, typ types.Type, names map[types.Type]string, id func(string) string) string {
	tb.Helper()

	gf := GoFormatter{
		Names:      names,
		Identifier: id,
	}

	have, err := gf.TypeDeclaration("t", typ)
	if err != nil {
		tb.Fatal(err)
	}

	_, err = format.Source([]byte(have))
	if err != nil {
		tb.Fatalf("Output can't be formatted: %s\n%s", err, have)
	}

	return have
}
