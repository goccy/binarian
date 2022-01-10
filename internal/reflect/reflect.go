package reflect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/goccy/binarian/reflect"
)

type Type struct {
	*rtype
	offset     int32
	rodataAddr uint64
	rodata     []byte
	bo         binary.ByteOrder
}

type rtype struct {
	size       uintptr
	ptrdata    uintptr
	hash       uint32
	tflag      tflag
	align      uint8
	fieldAlign uint8
	kind       uint8
	equal      unsafe.Pointer
	gcdata     *byte
	str        nameOff
	ptrToThis  typeOff
}

type sliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}

const uintptrSize = 4 << (^uintptr(0) >> 63)

type tflag uint8
type nameOff int32
type typeOff int32
type textOff int32

type name struct {
	bytes *byte
}

const (
	kindMask = (1 << 5) - 1
)

const (
	tflagUncommon      tflag = 1 << 0
	tflagExtraStar     tflag = 1 << 1
	tflagNamed         tflag = 1 << 2
	tflagRegularMemory tflag = 1 << 3
)

// size 16 ( 4 + 2 + 2 + 4 + 4 )
type uncommonType struct {
	pkgPath nameOff
	mcount  uint16
	xcount  uint16
	moff    uint32
	_       uint32
}

// size 70 ( 48 + 8 + 8 + 8 )
type arrayType struct {
	rtype
	elem  *Type
	slice *Type
	len   uintptr
}

// size 62 ( 48 + 8 + 8 )
type chanType struct {
	rtype
	elem *Type
	dir  uintptr
}

// size 52 ( 48 + 2 + 2 )
type funcType struct {
	rtype
	inCount  uint16
	outCount uint16
}

type imethod struct {
	name nameOff
	typ  typeOff
}

// size 80 ( 48 + 8 + 24 )
type interfaceType struct {
	rtype
	pkgPath name
	methods []imethod
}

// size 88 ( 48 + 8 + 8 + 8 + 8 + 1 + 1 + 2 + 4)
type mapType struct {
	rtype
	key        *Type
	elem       *Type
	bucket     *Type
	hasher     func(unsafe.Pointer, uintptr) uintptr
	keysize    uint8
	valuesize  uint8
	bucketsize uint16
	flags      uint32
}

// size 56 ( 48 + 8 )
type ptrType struct {
	rtype
	elem *Type
}

// size 54 ( 48 + 8 )
type sliceType struct {
	rtype
	elem *Type
}

// size 24 ( 8 + 8 + 8 )
type structField struct {
	name        name
	typ         *Type
	offsetEmbed uintptr
}

func (f *structField) offset() uintptr {
	return f.offsetEmbed >> 1
}

func (f *structField) embedded() bool {
	return f.offsetEmbed&1 != 0
}

// size 80 ( 48 + 8 + 24 )
type structType struct {
	rtype
	pkgPath name
	fields  []structField
}

// size 96 ( 80 + 16 )
type structTypeUncommon struct {
	structType
	u uncommonType
}

// size 72 ( 56 + 16 )
type ptrTypeUncommon struct {
	ptrType
	u uncommonType
}

// size 68 ( 52 + 16 )
type funcTypeUncommon struct {
	funcType
	u uncommonType
}

// size 70 ( 54 + 16 )
type sliceTypeUncommon struct {
	sliceType
	u uncommonType
}

// size 86 ( 70 + 16 )
type arrayTypeUncommon struct {
	arrayType
	u uncommonType
}

// size 78 ( 62 + 16 )
type chanTypeUncommon struct {
	chanType
	u uncommonType
}

// size 104 ( 88 + 16 )
type mapTypeUncommon struct {
	mapType
	u uncommonType
}

// size 96 ( 80 + 16 )
type interfaceTypeUncommon struct {
	interfaceType
	u uncommonType
}

// size 64 ( 48 + 16 )
type defaultTypeUncommon struct {
	rtype
	uncommonType
}

// size 16 ( 4 + 4 + 4 + 4 )
type method struct {
	name nameOff
	mtyp typeOff
	ifn  textOff
	tfn  textOff
}

var (
	typeSize          = uint64(unsafe.Sizeof(rtype{}))
	methodSize        = uint64(unsafe.Sizeof(method{}))
	imethodSize       = uint64(unsafe.Sizeof(imethod{}))
	structFieldSize   = uint64(unsafe.Sizeof(structField{}))
	structTypeSize    = uint64(unsafe.Sizeof(structType{}))
	ptrTypeSize       = uint64(unsafe.Sizeof(ptrType{}))
	arrayTypeSize     = uint64(unsafe.Sizeof(arrayType{}))
	sliceTypeSize     = uint64(unsafe.Sizeof(sliceType{}))
	mapTypeSize       = uint64(unsafe.Sizeof(mapType{}))
	chanTypeSize      = uint64(unsafe.Sizeof(chanType{}))
	funcTypeSize      = uint64(unsafe.Sizeof(funcType{}))
	interfaceTypeSize = uint64(unsafe.Sizeof(interfaceType{}))
)

func NewType(rodataAddr uint64, rodata []byte, bo binary.ByteOrder, offset int32) (*Type, error) {
	var v [48]byte
	if err := binary.Read(bytes.NewReader(rodata[offset:offset+int32(typeSize)]), bo, &v); err != nil {
		return nil, err
	}
	typ := (*rtype)(unsafe.Pointer(&v))
	return &Type{
		rtype:      typ,
		offset:     offset,
		rodataAddr: rodataAddr,
		rodata:     rodata,
		bo:         bo,
	}, nil
}

func (t *Type) Addr() uintptr {
	return uintptr(unsafe.Pointer(t.rtype))
}

func (t *Type) pointers() bool { return t.ptrdata != 0 }

func (t *Type) common() *Type { return t }

func (t *Type) toStructTypeUncommon() *structTypeUncommon {
	var v [96]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+96]), t.bo, &v)
	return (*structTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toPtrTypeUncommon() *ptrTypeUncommon {
	var v [72]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+72]), t.bo, &v)
	return (*ptrTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toFuncTypeUncommon() *funcTypeUncommon {
	var v [68]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+68]), t.bo, &v)
	return (*funcTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toSliceTypeUncommon() *sliceTypeUncommon {
	var v [70]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+70]), t.bo, &v)
	return (*sliceTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toArrayTypeUncommon() *arrayTypeUncommon {
	var v [86]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+86]), t.bo, &v)
	return (*arrayTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toChanTypeUncommon() *chanTypeUncommon {
	var v [78]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+78]), t.bo, &v)
	return (*chanTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toMapTypeUncommon() *mapTypeUncommon {
	var v [104]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+104]), t.bo, &v)
	return (*mapTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toInterfaceTypeUncommon() *interfaceTypeUncommon {
	var v [96]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+96]), t.bo, &v)
	return (*interfaceTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) toDefaultTypeUncommon() *defaultTypeUncommon {
	var v [64]byte
	_ = binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+64]), t.bo, &v)
	return (*defaultTypeUncommon)(unsafe.Pointer(&v))
}

func (t *Type) uncommon() (*uncommonType, uint64) {
	if t.tflag&tflagUncommon == 0 {
		return nil, 0
	}
	switch t.Kind() {
	case reflect.Struct:
		return &t.toStructTypeUncommon().u, structTypeSize
	case reflect.Ptr:
		return &t.toPtrTypeUncommon().u, ptrTypeSize
	case reflect.Func:
		return &t.toFuncTypeUncommon().u, funcTypeSize
	case reflect.Slice:
		return &t.toSliceTypeUncommon().u, sliceTypeSize
	case reflect.Array:
		return &t.toArrayTypeUncommon().u, arrayTypeSize
	case reflect.Chan:
		return &t.toChanTypeUncommon().u, chanTypeSize
	case reflect.Map:
		return &t.toMapTypeUncommon().u, mapTypeSize
	case reflect.Interface:
		return &t.toInterfaceTypeUncommon().u, interfaceTypeSize
	default:
		return &t.toDefaultTypeUncommon().uncommonType, typeSize
	}
}

func (t *Type) exportedMethods() []method {
	ut, uncommonOffset := t.uncommon()
	if ut == nil {
		return nil
	}
	if ut.xcount == 0 {
		return nil
	}
	methods := make([]method, ut.xcount)
	start := t.offset + int32(uncommonOffset) + int32(ut.moff)
	end := start + 16
	for i := 0; i < int(ut.xcount); i++ {
		var v [16]byte
		if err := binary.Read(bytes.NewReader(t.rodata[start:end]), t.bo, &v); err != nil {
			panic(err)
		}
		methods[i] = *(*method)(unsafe.Pointer(&v))
		start += 16
		end += 16
	}
	return methods
}

func (t *Type) Size() uintptr { return t.size }

func (t *Type) Bits() int {
	if t == nil {
		panic("reflect: Bits of nil Type")
	}
	k := t.Kind()
	if k < reflect.Int || k > reflect.Complex128 {
		panic("reflect: Bits of non-arithmetic Type " + t.String())
	}
	return int(t.size) * 8
}

func (t *Type) Align() int { return int(t.align) }

func (t *Type) FieldAlign() int { return int(t.fieldAlign) }

func (t *Type) Kind() reflect.Kind { return reflect.Kind(t.kind & kindMask) }

func (t *Type) Method(i int) (m reflect.Method) {
	if t.Kind() == reflect.Interface {
		tt, err := t.toInterfaceType()
		if err != nil {
			panic(err)
		}
		return tt.Method(i, t)
	}
	methods := t.exportedMethods()
	if i < 0 || i >= len(methods) {
		panic("reflect: Method index out of range")
	}
	p := methods[i]
	m.Index = i
	name, err := nameOffToText(p.name, t.rodata, t.bo)
	if err != nil {
		panic(err)
	}
	m.Name = name
	nameHeader, err := nameOffToHeader(p.name, t.rodata, t.bo)
	if err != nil {
		panic(err)
	}
	if !isExported(nameHeader) || p.mtyp < 0 {
		return m
	}
	mtyp, err := t.loadType(int32(p.mtyp))
	if err != nil {
		panic(err)
	}
	m.Type = mtyp
	return m
}

func (t *Type) MethodByName(name string) (reflect.Method, bool) {
	if t.Kind() == reflect.Interface {
		tt, err := t.toInterfaceType()
		if err != nil {
			panic(err)
		}
		return tt.MethodByName(name, t)
	}
	for i, p := range t.exportedMethods() {
		text, err := nameOffToText(p.name, t.rodata, t.bo)
		if err != nil {
			panic(err)
		}
		if text == name {
			return t.Method(i), true
		}
	}
	return reflect.Method{}, false
}

func (t *Type) NumMethod() int {
	if t.Kind() == reflect.Interface {
		tt, err := t.toInterfaceType()
		if err != nil {
			panic(err)
		}
		return tt.NumMethod()
	}
	return len(t.exportedMethods())
}

func (t *Type) Implements(u reflect.Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.Implements")
	}
	if u.Kind() != reflect.Interface {
		panic("reflect: non-interface type passed to Type.Implements")
	}
	return implements(u.(*Type))
}

func implements(typ *Type) bool {
	return false
}

func (t *Type) hasName() bool {
	return t.tflag&tflagNamed != 0
}

func (t *Type) Name() string {
	if !t.hasName() {
		return ""
	}
	s := t.String()
	i := len(s) - 1
	for i >= 0 && s[i] != '.' {
		i--
	}
	return s[i+1:]
}

func (t *Type) PkgPath() string {
	if t.tflag&tflagNamed == 0 {
		return ""
	}
	ut, _ := t.uncommon()
	if ut == nil {
		return ""
	}
	text, err := nameOffToText(ut.pkgPath, t.rodata, t.bo)
	if err != nil {
		return ""
	}
	return text
}

func (t *Type) String() string {
	text, err := nameOffToText(t.str, t.rodata, t.bo)
	if err != nil {
		return ""
	}
	if text[0] == '*' {
		return text[1:]
	}
	return text
}

func (t *Type) AssignableTo(u reflect.Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.AssignableTo")
	}
	//uu := u.(*Type)
	return false
	//return directlyAssignable(uu, t) || implements(uu, t)
}

func (t *Type) ConvertibleTo(u reflect.Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.ConvertibleTo")
	}
	//uu := u.(*Type)
	return false
	//return convertOp(uu, t) != nil
}

func (t *Type) Comparable() bool {
	return t.equal != nil
}

func (t *Type) ChanDir() reflect.ChanDir {
	if t.Kind() != reflect.Chan {
		panic("reflect: ChanDir of non-chan type " + t.String())
	}
	tt, err := t.toChanType()
	if err != nil {
		panic(err)
	}
	return reflect.ChanDir(tt.dir)
}

func (t *Type) IsVariadic() bool {
	if t.Kind() != reflect.Func {
		panic("reflect: IsVariadic of non-func type " + t.String())
	}
	tt, err := t.toFuncType()
	if err != nil {
		panic(err)
	}
	return tt.outCount&(1<<15) != 0
}

func (t *Type) toChanType() (*chanType, error) {
	var v [64]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+64]), t.bo, &v); err != nil {
		return nil, err
	}
	type chanAddrType struct {
		rtype
		elemAddr uint64
		dir      uintptr
	}
	typ := (*chanAddrType)(unsafe.Pointer(&v))
	elem, err := t.loadType(int32(typ.elemAddr - t.rodataAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to decode chan elem type")
	}
	return &chanType{
		rtype: typ.rtype,
		elem:  elem,
		dir:   typ.dir,
	}, nil
}

func (t *Type) toInterfaceType() (*interfaceType, error) {
	var v [80]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+80]), t.bo, &v); err != nil {
		return nil, err
	}
	type interfaceTypeAddr struct {
		rtype
		pkgpath name
		mhdr    sliceHeader
	}
	typ := (*interfaceTypeAddr)(unsafe.Pointer(&v))
	methods, err := t.toIMethods(typ.mhdr)
	if err != nil {
		return nil, err
	}
	return &interfaceType{
		rtype:   typ.rtype,
		pkgPath: typ.pkgpath,
		methods: methods,
	}, nil
}

func (t *Type) toIMethods(mhdr sliceHeader) ([]imethod, error) {
	start := uint64(uintptr(mhdr.data) - uintptr(t.rodataAddr))
	end := start + imethodSize
	var methods []imethod
	for i := uint64(0); i < uint64(mhdr.len); i++ {
		var hdr uint64
		if err := binary.Read(bytes.NewReader(t.rodata[start:end]), t.bo, &hdr); err != nil {
			return nil, err
		}
		methods = append(methods, *(*imethod)(unsafe.Pointer(&hdr)))
		start += imethodSize
		end += imethodSize
	}
	return methods, nil
}

func (t *Type) toFuncType() (*funcType, error) {
	var v [52]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+52]), t.bo, &v); err != nil {
		return nil, err
	}
	return (*funcType)(unsafe.Pointer(&v)), nil
}

func (t *Type) toStructType() (*structType, error) {
	var v [80]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+80]), t.bo, &v); err != nil {
		return nil, err
	}
	type structTypeAddr struct {
		rtype
		pkgpath   name
		fieldsHdr sliceHeader
	}
	typ := (*structTypeAddr)(unsafe.Pointer(&v))
	fields, err := t.toStructFields(typ.fieldsHdr)
	if err != nil {
		return nil, err
	}
	return &structType{
		rtype:   typ.rtype,
		pkgPath: typ.pkgpath,
		fields:  fields,
	}, nil
}

func (t *Type) toStructFields(hdr sliceHeader) ([]structField, error) {
	start := uint64(uintptr(hdr.data) - uintptr(t.rodataAddr))
	end := start + structFieldSize
	var fields []structField
	for i := 0; i < hdr.len; i++ {
		var v [24]byte
		if err := binary.Read(bytes.NewReader(t.rodata[start:end]), t.bo, &v); err != nil {
			return nil, err
		}
		type structFieldAddr struct {
			name        name
			typ         uint64
			offsetEmbed uintptr
		}
		addr := *(*structFieldAddr)(unsafe.Pointer(&v))
		typ, err := t.loadType(int32(addr.typ - t.rodataAddr))
		if err != nil {
			return nil, err
		}
		fields = append(fields, structField{
			name:        addr.name,
			typ:         typ,
			offsetEmbed: addr.offsetEmbed,
		})
		start += structFieldSize
		end += structFieldSize
	}
	return fields, nil
}

func (t *Type) loadType(offset int32) (*Type, error) {
	var v [48]byte
	if err := binary.Read(bytes.NewReader(t.rodata[offset:offset+48]), t.bo, &v); err != nil {
		return nil, err
	}
	return t.toType((*rtype)(unsafe.Pointer(&v)), offset), nil
}

func (t *Type) Elem() reflect.Type {
	typ, err := t.elem()
	if err != nil {
		panic(err)
	}
	return typ
}

func (t *Type) elem() (reflect.Type, error) {
	switch t.Kind() {
	case reflect.Array:
		arrayType, err := t.toArrayType()
		if err != nil {
			return nil, err
		}
		return arrayType.elem, nil
	case reflect.Chan:
		chanType, err := t.toChanType()
		if err != nil {
			return nil, err
		}
		return chanType.elem, nil
	case reflect.Map:
		mapType, err := t.toMapType()
		if err != nil {
			return nil, err
		}
		return mapType.elem, nil
	case reflect.Ptr:
		ptrType, err := t.toPtrType()
		if err != nil {
			return nil, err
		}
		return ptrType.elem, nil
	case reflect.Slice:
		sliceType, err := t.toPtrType()
		if err != nil {
			return nil, err
		}
		return sliceType.elem, nil
	}
	return nil, fmt.Errorf("reflect: Elem of invalid type %s", t.String())
}

func (t *Type) toArrayType() (*arrayType, error) {
	var v [70]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+70]), t.bo, &v); err != nil {
		return nil, err
	}
	type arrayAddrType struct {
		rtype
		elemAddr  uint64
		sliceAddr uint64
		len       uintptr
	}
	addr := (*arrayAddrType)(unsafe.Pointer(&v))
	elem, err := t.loadType(int32(addr.elemAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	slice, err := t.loadType(int32(addr.sliceAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	return &arrayType{
		rtype: addr.rtype,
		elem:  elem,
		slice: slice,
		len:   addr.len,
	}, nil
}

func (t *Type) toPtrType() (*ptrType, error) {
	var v [54]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+54]), t.bo, &v); err != nil {
		return nil, err
	}
	type ptrAddrType struct {
		rtype
		elemAddr uint64
	}
	addr := (*ptrAddrType)(unsafe.Pointer(&v))
	elem, err := t.loadType(int32(addr.elemAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	return &ptrType{
		rtype: addr.rtype,
		elem:  elem,
	}, nil
}

func (t *Type) toMapType() (*mapType, error) {
	var v [88]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+88]), t.bo, &v); err != nil {
		return nil, err
	}
	type mapAddrType struct {
		rtype
		keyAddr    uint64
		elemAddr   uint64
		bucketAddr uint64
		hasher     func(unsafe.Pointer, uintptr) uintptr
		keysize    uint8
		valuesize  uint8
		bucketsize uint16
		flags      uint32
	}
	addr := (*mapAddrType)(unsafe.Pointer(&v))
	key, err := t.loadType(int32(addr.keyAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	elem, err := t.loadType(int32(addr.elemAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	bucket, err := t.loadType(int32(addr.bucketAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	return &mapType{
		rtype:      addr.rtype,
		key:        key,
		elem:       elem,
		bucket:     bucket,
		hasher:     addr.hasher,
		keysize:    addr.keysize,
		valuesize:  addr.valuesize,
		bucketsize: addr.bucketsize,
		flags:      addr.flags,
	}, nil
}

func (t *Type) toSliceType() (*sliceType, error) {
	var v [54]byte
	if err := binary.Read(bytes.NewReader(t.rodata[t.offset:t.offset+54]), t.bo, &v); err != nil {
		return nil, err
	}
	type sliceAddrType struct {
		rtype
		elemAddr uint64
	}
	addr := (*sliceAddrType)(unsafe.Pointer(&v))
	elem, err := t.loadType(int32(addr.elemAddr - t.rodataAddr))
	if err != nil {
		return nil, err
	}
	return &sliceType{
		rtype: addr.rtype,
		elem:  elem,
	}, nil
}

func (t *Type) Field(i int) reflect.StructField {
	if t.Kind() != reflect.Struct {
		panic("reflect: Field of non-struct type " + t.String())
	}
	tt, err := t.toStructType()
	if err != nil {
		panic(err)
	}
	return tt.Field(i)
}

func (t *Type) FieldByIndex(index []int) reflect.StructField {
	if t.Kind() != reflect.Struct {
		panic("reflect: FieldByIndex of non-struct type " + t.String())
	}
	tt, err := t.toStructType()
	if err != nil {
		panic(err)
	}
	return tt.FieldByIndex(index, t)
}

func (t *Type) FieldByName(name string) (reflect.StructField, bool) {
	if t.Kind() != reflect.Struct {
		panic("reflect: FieldByName of non-struct type " + t.String())
	}
	tt, err := t.toStructType()
	if err != nil {
		panic(err)
	}
	return tt.FieldByName(name)
}

func (t *Type) FieldByNameFunc(match func(string) bool) (reflect.StructField, bool) {
	if t.Kind() != reflect.Struct {
		panic("reflect: FieldByNameFunc of non-struct type " + t.String())
	}
	tt, err := t.toStructType()
	if err != nil {
		panic(err)
	}
	return tt.FieldByNameFunc(match)
}

func (t *Type) In(i int) reflect.Type {
	if t.Kind() != reflect.Func {
		panic("reflect: In of non-func type " + t.String())
	}
	tt, err := t.toFuncType()
	if err != nil {
		panic(err)
	}
	inTypes, err := tt.in(t)
	if err != nil {
		panic(err)
	}
	return inTypes[i]
}

func (t *Type) Key() reflect.Type {
	if t.Kind() != reflect.Map {
		panic("reflect: Key of non-map type " + t.String())
	}
	tt, err := t.toMapType()
	if err != nil {
		panic(err)
	}
	return tt.key
}

func (t *Type) Len() int {
	if t.Kind() != reflect.Array {
		panic("reflect: Len of non-array type " + t.String())
	}
	tt, err := t.toArrayType()
	if err != nil {
		panic(err)
	}
	return int(tt.len)
}

func (t *Type) NumField() int {
	if t.Kind() != reflect.Struct {
		panic("reflect: NumField of non-struct type " + t.String())
	}
	tt, err := t.toStructType()
	if err != nil {
		panic(err)
	}
	return len(tt.fields)
}

func (t *Type) NumIn() int {
	if t.Kind() != reflect.Func {
		panic("reflect: NumIn of non-func type " + t.String())
	}
	tt, err := t.toFuncType()
	if err != nil {
		panic(err)
	}
	return int(tt.inCount)
}

func (t *Type) NumOut() int {
	if t.Kind() != reflect.Func {
		panic("reflect: NumOut of non-func type " + t.String())
	}
	tt, err := t.toFuncType()
	if err != nil {
		panic(err)
	}
	outTypes, err := tt.out(t)
	if err != nil {
		panic(err)
	}
	return len(outTypes)
}

func (t *Type) Out(i int) reflect.Type {
	if t.Kind() != reflect.Func {
		panic("reflect: Out of non-func type " + t.String())
	}
	tt, err := t.toFuncType()
	if err != nil {
		panic(err)
	}
	outTypes, err := tt.out(t)
	if err != nil {
		panic(err)
	}
	return outTypes[i]
}

func (t *Type) toType(typ *rtype, offset int32) *Type {
	if typ == nil {
		return nil
	}
	return &Type{
		rtype:      typ,
		offset:     offset,
		rodataAddr: t.rodataAddr,
		rodata:     t.rodata,
		bo:         t.bo,
	}
}

func (t *Type) ptrTo() (*Type, error) {
	if t.ptrToThis != 0 {
		return t.loadType(int32(t.ptrToThis))
	}
	return nil, nil
}

func nameOffToHeader(name nameOff, data []byte, bo binary.ByteOrder) (byte, error) {
	var hdr byte
	if err := binary.Read(bytes.NewReader(data[name:name+1]), bo, &hdr); err != nil {
		return 0, err
	}
	return hdr, nil
}

func nameOffToText(name nameOff, data []byte, bo binary.ByteOrder) (string, error) {
	var hdr [4]byte
	if err := binary.Read(bytes.NewReader(data[name:name+4]), bo, &hdr); err != nil {
		return "", err
	}
	var text string
	textHeader := (*sliceHeader)(unsafe.Pointer(&text))
	textHeader.data = unsafe.Pointer(&data[name+2])
	textHeader.len = int(hdr[1])
	return text, nil
}

func (t *interfaceType) NumMethod() int { return len(t.methods) }

func (t *interfaceType) Method(i int, typ *Type) (m reflect.Method) {
	if i < 0 || i >= len(t.methods) {
		return
	}
	p := &t.methods[i]
	pname, err := nameOffToText(p.name, typ.rodata, typ.bo)
	if err != nil {
		panic(err)
	}
	m.Name = pname
	nameHeader, err := nameOffToHeader(p.name, typ.rodata, typ.bo)
	if err != nil {
		panic(err)
	}
	if !isExported(nameHeader) {
		m.PkgPath = "" //pname.pkgPath()
		if m.PkgPath == "" {
			m.PkgPath = "" //t.pkgPath.name()
		}
	}
	tt, err := typ.loadType(int32(p.typ))
	if err != nil {
		panic(err)
	}
	m.Type = reflect.Type(tt)
	m.Index = i
	return
}

func isExported(hdr byte) bool {
	return hdr&(1<<0) != 0
}

func hasTag(hdr byte) bool {
	return hdr&(1<<1) != 0
}

func (t *interfaceType) MethodByName(name string, typ *Type) (m reflect.Method, ok bool) {
	if t == nil {
		return
	}
	var p *imethod
	for i := range t.methods {
		p = &t.methods[i]
		text, err := nameOffToText(p.name, typ.rodata, typ.bo)
		if err != nil {
			panic(err)
		}
		if text == name {
			return t.Method(i, typ), true
		}
	}
	return
}

func (t *funcType) in(typ *Type) ([]*Type, error) {
	var uadd uintptr
	if t.tflag&tflagUncommon != 0 {
		uadd += unsafe.Sizeof(uncommonType{})
	}
	if t.inCount == 0 {
		return nil, nil
	}
	intypes := make([]*Type, t.inCount)
	start := uintptr(typ.offset) + uintptr(funcTypeSize) + uadd
	end := start + 8
	for i := 0; i < int(t.inCount); i++ {
		var addr uint64
		if err := binary.Read(bytes.NewReader(typ.rodata[start:end]), typ.bo, &addr); err != nil {
			return nil, err
		}
		offset := int32(addr - typ.rodataAddr)
		intype, err := typ.loadType(offset)
		if err != nil {
			return nil, err
		}
		intypes[i] = intype
		start += 8
		end += 8
	}
	return intypes, nil
}

func (t *funcType) out(typ *Type) ([]*Type, error) {
	var uadd uintptr
	if t.tflag&tflagUncommon != 0 {
		uadd += unsafe.Sizeof(uncommonType{})
	}
	outCount := t.outCount & (1<<15 - 1)
	if outCount == 0 {
		return nil, nil
	}
	outtypes := make([]*Type, outCount)
	start := uintptr(typ.offset) + uintptr(funcTypeSize) + uadd + 8*uintptr(t.inCount)
	end := start + 8
	for i := 0; i < int(outCount); i++ {
		var addr uint64
		if err := binary.Read(bytes.NewReader(typ.rodata[start:end]), typ.bo, &addr); err != nil {
			return nil, err
		}
		offset := int32(addr - typ.rodataAddr)
		outtype, err := typ.loadType(offset)
		if err != nil {
			return nil, err
		}
		outtypes[i] = outtype
		start += 8
		end += 8
	}
	return outtypes, nil
}

func (t *structType) Field(i int) (f reflect.StructField) {
	if i < 0 || i >= len(t.fields) {
		panic("reflect: Field index out of bounds")
	}
	return
}

func (t *structType) FieldByIndex(index []int, typ *Type) (f reflect.StructField) {
	offset := uintptr(unsafe.Pointer(&t.rtype)) - uintptr(typ.rodataAddr)
	f.Type = reflect.Type(typ.toType(&t.rtype, int32(offset)))
	for i, x := range index {
		if i > 0 {
			ft := f.Type
			if ft.Kind() == reflect.Ptr && ft.Elem().Kind() == reflect.Struct {
				ft = ft.Elem()
			}
			f.Type = ft
		}
		f = f.Type.Field(x)
	}
	return
}

func (t *structType) FieldByName(name string) (f reflect.StructField, present bool) {
	return
}

func (t *structType) FieldByNameFunc(match func(string) bool) (result reflect.StructField, ok bool) {
	return
}

func PtrTo(t reflect.Type) reflect.Type {
	tt, err := t.(*Type).ptrTo()
	if err != nil {
		panic(err)
	}
	return tt
}
