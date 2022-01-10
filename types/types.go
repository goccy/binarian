package types

import (
	"fmt"
	"go/token"
	"go/types"

	"github.com/goccy/binarian/reflect"
)

type wrappedType struct {
	typ    types.Type
	cached *string
	rtype  reflect.Type
}

func (t *wrappedType) Underlying() types.Type {
	return t.typ
}

func (t *wrappedType) String() string {
	return t.rtype.String()
}

func TypeFromReflectType(typ reflect.Type) types.Type {
	cachedMap := map[string]types.Type{}
	return typeFromReflectType(typ, cachedMap)
}

func typeFromReflectType(typ reflect.Type, cachedMap map[string]types.Type) types.Type {
	if t, found := cachedMap[typ.String()]; found {
		return t
	}
	switch typ.Kind() {
	case reflect.Bool:
		return types.Typ[types.Bool]
	case reflect.Int:
		return types.Typ[types.Int]
	case reflect.Int8:
		return types.Typ[types.Int8]
	case reflect.Int16:
		return types.Typ[types.Int16]
	case reflect.Int32:
		return types.Typ[types.Int32]
	case reflect.Int64:
		return types.Typ[types.Int64]
	case reflect.Uint:
		return types.Typ[types.Uint]
	case reflect.Uint8:
		return types.Typ[types.Uint8]
	case reflect.Uint16:
		return types.Typ[types.Uint16]
	case reflect.Uint32:
		return types.Typ[types.Uint32]
	case reflect.Uint64:
		return types.Typ[types.Uint64]
	case reflect.Uintptr:
		return types.Typ[types.Uintptr]
	case reflect.Float32:
		return types.Typ[types.Float32]
	case reflect.Float64:
		return types.Typ[types.Float64]
	case reflect.Complex64:
		return types.Typ[types.Complex64]
	case reflect.Complex128:
		return types.Typ[types.Complex128]
	case reflect.Array:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = types.NewArray(typeFromReflectType(typ.Elem(), cachedMap), int64(typ.Len()))
		return w.typ
	case reflect.Chan:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = types.NewChan(types.ChanDir(typ.ChanDir()), typeFromReflectType(typ.Elem(), cachedMap))
		return w.typ
	case reflect.Func:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = signatureFromReflectType(nil, typ, cachedMap)
		return w.typ
	case reflect.Interface:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		methods := make([]*types.Func, typ.NumMethod())
		for i := 0; i < typ.NumMethod(); i++ {
			mtd := typ.Method(i)
			sig := signatureFromReflectType(nil, mtd.Type, cachedMap)
			methods[i] = types.NewFunc(token.NoPos, nil, mtd.Name, sig)
		}
		w.typ = types.NewInterfaceType(methods, nil)
		return w.typ
	case reflect.Map:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = types.NewMap(typeFromReflectType(typ.Key(), cachedMap), typeFromReflectType(typ.Elem(), cachedMap))
		return w.typ
	case reflect.Ptr:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = types.NewPointer(typeFromReflectType(typ.Elem(), cachedMap))
		return w.typ
	case reflect.Slice:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		w.typ = types.NewSlice(typeFromReflectType(typ.Elem(), cachedMap))
		return w.typ
	case reflect.String:
		return types.Typ[types.String]
	case reflect.Struct:
		w := &wrappedType{rtype: typ}
		cachedMap[typ.String()] = w
		t, _ := structTypeFromReflectType(typ, cachedMap)
		w.typ = t
		return t
	case reflect.UnsafePointer:
		return types.Typ[types.UnsafePointer]
	}
	return types.Typ[types.UntypedNil]
}

func MethodSignatureFromReflectType(recv reflect.Type, mtd reflect.Method) *types.Signature {
	cachedMap := map[string]types.Type{}
	return signatureFromReflectType(
		types.NewVar(token.NoPos, nil, "", typeFromReflectType(recv, cachedMap)),
		mtd.Type,
		cachedMap,
	)
}

func SignatureFromReflectType(typ reflect.Type) (*types.Signature, error) {
	if typ.Kind() != reflect.Func {
		return nil, fmt.Errorf("failed to convert from reflect.Type to *types.Func. from type is %s", typ.Kind())
	}
	return signatureFromReflectType(nil, typ, map[string]types.Type{}), nil
}

func signatureFromReflectType(recv *types.Var, typ reflect.Type, cachedMap map[string]types.Type) *types.Signature {
	params := make([]*types.Var, 0, typ.NumIn())
	for i := 0; i < typ.NumIn(); i++ {
		params = append(params, types.NewParam(token.NoPos, nil, "", typeFromReflectType(typ.In(i), cachedMap)))
	}
	paramTuple := types.NewTuple(params...)
	results := make([]*types.Var, 0, typ.NumOut())
	for i := 0; i < typ.NumOut(); i++ {
		results = append(results, types.NewVar(token.NoPos, nil, "", typeFromReflectType(typ.Out(i), cachedMap)))
	}
	resultTuple := types.NewTuple(results...)
	return types.NewSignature(recv, paramTuple, resultTuple, typ.IsVariadic())
}

func StructTypeFromReflectType(typ reflect.Type) (types.Type, error) {
	return structTypeFromReflectType(typ, map[string]types.Type{})
}

func structTypeFromReflectType(typ reflect.Type, cachedMap map[string]types.Type) (types.Type, error) {
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("failed to convert from reflect.Type to *types.Struct. from type is %s", typ.Kind())
	}
	fields := make([]*types.Var, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		structField := typ.Field(i)
		if structField.Type == nil {
			// unexported field
			continue
		}
		fields = append(fields, types.NewVar(token.NoPos, nil, structField.Name, typeFromReflectType(structField.Type, cachedMap)))
	}
	name := typ.Name()
	if name != "" {
		s := types.NewStruct(fields, nil)
		return types.NewNamed(
			types.NewTypeName(token.NoPos, nil, name, s),
			s,
			nil,
		), nil
	}
	return types.NewStruct(fields, nil), nil
}
