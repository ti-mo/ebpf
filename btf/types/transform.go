package types

import (
	"errors"
)

func SkipQualifiersAndTypedefs(typ Type) (Type, error) {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result, nil
		}
	}
	return nil, errors.New("exceeded type depth")
}

func SkipQualifiers(typ Type) (Type, error) {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		default:
			return result, nil
		}
	}
	return nil, errors.New("exceeded type depth")
}
