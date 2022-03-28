package btf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf/types"
)

const maxTypeDepth = 32

// inflateRawTypes takes a list of raw btf types linked via type IDs, and turns
// it into a graph of Types connected via pointers.
//
// Returns a map of named types (so, where NameOff is non-zero) and a slice of types
// indexed by TypeID. Since BTF ignores compilation units, multiple types may share
// the same name. A Type may form a cyclic graph by pointing at itself.
func inflateRawTypes(rawTypes []rawType, rawStrings stringTable) (typs []types.Type, namedTypes map[essentialName]types.Types, err error) {
	type fixupDef struct {
		id           types.TypeID
		expectedKind btfKind
		typ          *types.Type
	}

	var fixups []fixupDef
	fixup := func(id types.TypeID, expectedKind btfKind, typ *types.Type) {
		fixups = append(fixups, fixupDef{id, expectedKind, typ})
	}

	convertMembers := func(raw []btfMember, kindFlag bool) ([]types.Member, error) {
		// NB: The fixup below relies on pre-allocating this array to
		// work, since otherwise append might re-allocate members.
		members := make([]types.Member, 0, len(raw))
		for i, btfMember := range raw {
			name, err := rawStrings.Lookup(btfMember.NameOff)
			if err != nil {
				return nil, fmt.Errorf("can't get name for member %d: %w", i, err)
			}
			m := types.Member{
				Name:       name,
				OffsetBits: btfMember.Offset,
			}
			if kindFlag {
				m.BitfieldSize = btfMember.Offset >> 24
				m.OffsetBits &= 0xffffff
			}
			members = append(members, m)
		}
		for i := range members {
			fixup(raw[i].Type, kindUnknown, &members[i].Type)
		}
		return members, nil
	}

	typs = make([]types.Type, 0, len(rawTypes))
	typs = append(typs, (*types.Void)(nil))
	namedTypes = make(map[essentialName]types.Types)

	for i, raw := range rawTypes {
		var (
			// Void is defined to always be type ID 0, and is thus
			// omitted from BTF.
			id  = types.TypeID(i + 1)
			typ types.Type
		)

		name, err := rawStrings.Lookup(raw.NameOff)
		if err != nil {
			return nil, nil, fmt.Errorf("get name for type id %d: %w", id, err)
		}

		switch raw.Kind() {
		case kindInt:
			encoding, offset, bits := intEncoding(*raw.data.(*uint32))
			typ = &types.Int{id, name, raw.Size(), encoding, offset, bits}

		case kindPointer:
			ptr := &types.Pointer{id, nil}
			fixup(raw.Type(), kindUnknown, &ptr.Target)
			typ = ptr

		case kindArray:
			btfArr := raw.data.(*btfArray)

			// IndexType is unused according to btf.rst.
			// Don't make it available right now.
			arr := &types.Array{id, nil, btfArr.Nelems}
			fixup(btfArr.Type, kindUnknown, &arr.Type)
			typ = arr

		case kindStruct:
			members, err := convertMembers(raw.data.([]btfMember), raw.KindFlag())
			if err != nil {
				return nil, nil, fmt.Errorf("struct %s (id %d): %w", name, id, err)
			}
			typ = &types.Struct{id, name, raw.Size(), members}

		case kindUnion:
			members, err := convertMembers(raw.data.([]btfMember), raw.KindFlag())
			if err != nil {
				return nil, nil, fmt.Errorf("union %s (id %d): %w", name, id, err)
			}
			typ = &types.Union{id, name, raw.Size(), members}

		case kindEnum:
			rawvals := raw.data.([]btfEnum)
			vals := make([]types.EnumValue, 0, len(rawvals))
			for i, btfVal := range rawvals {
				name, err := rawStrings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, nil, fmt.Errorf("get name for enum value %d: %s", i, err)
				}
				vals = append(vals, types.EnumValue{
					Name:  name,
					Value: btfVal.Val,
				})
			}
			typ = &types.Enum{id, name, vals}

		case kindForward:
			if raw.KindFlag() {
				typ = &types.Fwd{id, name, types.FwdUnion}
			} else {
				typ = &types.Fwd{id, name, types.FwdStruct}
			}

		case kindTypedef:
			typedef := &types.Typedef{id, name, nil}
			fixup(raw.Type(), kindUnknown, &typedef.Type)
			typ = typedef

		case kindVolatile:
			volatile := &types.Volatile{id, nil}
			fixup(raw.Type(), kindUnknown, &volatile.Type)
			typ = volatile

		case kindConst:
			cnst := &types.Const{id, nil}
			fixup(raw.Type(), kindUnknown, &cnst.Type)
			typ = cnst

		case kindRestrict:
			restrict := &types.Restrict{id, nil}
			fixup(raw.Type(), kindUnknown, &restrict.Type)
			typ = restrict

		case kindFunc:
			fn := &types.Func{id, name, nil, raw.Linkage()}
			fixup(raw.Type(), kindFuncProto, &fn.Type)
			typ = fn

		case kindFuncProto:
			rawparams := raw.data.([]btfParam)
			params := make([]types.FuncParam, 0, len(rawparams))
			for i, param := range rawparams {
				name, err := rawStrings.Lookup(param.NameOff)
				if err != nil {
					return nil, nil, fmt.Errorf("get name for func proto parameter %d: %s", i, err)
				}
				params = append(params, types.FuncParam{
					Name: name,
				})
			}
			for i := range params {
				fixup(rawparams[i].Type, kindUnknown, &params[i].Type)
			}

			fp := &types.FuncProto{id, nil, params}
			fixup(raw.Type(), kindUnknown, &fp.Return)
			typ = fp

		case kindVar:
			variable := raw.data.(*btfVariable)
			v := &types.Var{id, name, nil, types.VarLinkage(variable.Linkage)}
			fixup(raw.Type(), kindUnknown, &v.Type)
			typ = v

		case kindDatasec:
			btfVars := raw.data.([]btfVarSecinfo)
			vars := make([]types.VarSecinfo, 0, len(btfVars))
			for _, btfVar := range btfVars {
				vars = append(vars, types.VarSecinfo{
					Offset: btfVar.Offset,
					Size:   btfVar.Size,
				})
			}
			for i := range vars {
				fixup(btfVars[i].Type, kindVar, &vars[i].Type)
			}
			typ = &types.Datasec{id, name, raw.SizeType, vars}

		case kindFloat:
			typ = &types.Float{id, name, raw.Size()}

		default:
			return nil, nil, fmt.Errorf("type id %d: unknown kind: %v", id, raw.Kind())
		}

		typs = append(typs, typ)

		if name := newEssentialName(typ.TypeName()); name != "" {
			namedTypes[name] = append(namedTypes[name], typ)
		}
	}

	for _, fixup := range fixups {
		i := int(fixup.id)
		if i >= len(typs) {
			return nil, nil, fmt.Errorf("reference to invalid type id: %d", fixup.id)
		}

		// Default void (id 0) to unknown
		rawKind := kindUnknown
		if i > 0 {
			rawKind = rawTypes[i-1].Kind()
		}

		if expected := fixup.expectedKind; expected != kindUnknown && rawKind != expected {
			return nil, nil, fmt.Errorf("expected type id %d to have kind %s, found %s", fixup.id, expected, rawKind)
		}

		*fixup.typ = typs[i]
	}

	return typs, namedTypes, nil
}

// essentialName represents the name of a BTF type stripped of any flavor
// suffixes after a ___ delimiter.
type essentialName string

// newEssentialName returns name without a ___ suffix.
//
// CO-RE has the concept of 'struct flavors', which are used to deal with
// changes in kernel data structures. Anything after three underscores
// in a type name is ignored for the purpose of finding a candidate type
// in the kernel's BTF.
func newEssentialName(name string) essentialName {
	lastIdx := strings.LastIndex(name, "___")
	if lastIdx > 0 {
		return essentialName(name[:lastIdx])
	}
	return essentialName(name)
}
