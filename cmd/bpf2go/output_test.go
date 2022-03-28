package main

import (
	"testing"

	"github.com/cilium/ebpf/btf/types"
	qt "github.com/frankban/quicktest"
)

func TestOrderTypes(t *testing.T) {
	a := &types.Int{}
	b := &types.Int{}
	c := &types.Int{}

	for _, test := range []struct {
		name string
		in   map[types.Type]string
		out  []types.Type
	}{
		{
			"order",
			map[types.Type]string{
				a: "foo",
				b: "bar",
				c: "baz",
			},
			[]types.Type{b, c, a},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := sortTypes(test.in)
			qt.Assert(t, err, qt.IsNil)
			qt.Assert(t, len(result), qt.Equals, len(test.out))
			for i, o := range test.out {
				if result[i] != o {
					t.Fatalf("Index %d: expected %p got %p", i, o, result[i])
				}
			}
		})
	}

	for _, test := range []struct {
		name string
		in   map[types.Type]string
	}{
		{
			"duplicate names",
			map[types.Type]string{
				a: "foo",
				b: "foo",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := sortTypes(test.in)
			qt.Assert(t, err, qt.IsNotNil)
			qt.Assert(t, result, qt.IsNil)
		})
	}
}
