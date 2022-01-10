package file

import (
	"bytes"
	"debug/gosym"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"go/types"
	"os"
	"sort"
	"sync"

	internalreflect "github.com/goccy/binarian/internal/reflect"
	"github.com/goccy/binarian/reflect"
	binarytypes "github.com/goccy/binarian/types"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/tools/go/ssa"
)

type MachOFile struct {
	File     *macho.File
	rawFile  *os.File
	allSyms  []Sym
	typeMap  map[string]reflect.Type
	funcMap  map[uintptr]*gosym.Func
	loadOnce sync.Once
}

func NewMachOFile(f *os.File) (*MachOFile, error) {
	bin, err := macho.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &MachOFile{
		File:    bin,
		rawFile: f,
	}, nil
}

type Function struct {
	SymFunc *gosym.Func
	SSAFunc *ssa.Function
	Inst    []x86asm.Inst
	Source  []string
	Callee  []*ssa.Function
}

type Sym struct {
	Name string
	Addr uint64
	Size int64
	Code rune
	Type string
}

const stabTypeMask = 0xe0

type uint64s []uint64

func (x uint64s) Len() int           { return len(x) }
func (x uint64s) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
func (x uint64s) Less(i, j int) bool { return x[i] < x[j] }

type byAddr []Sym

func (x byAddr) Less(i, j int) bool { return x[i].Addr < x[j].Addr }
func (x byAddr) Len() int           { return len(x) }
func (x byAddr) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

func (f *MachOFile) symbols() ([]Sym, error) {
	if f.File.Symtab == nil {
		return nil, nil
	}

	var addrs []uint64
	for _, s := range f.File.Symtab.Syms {
		if s.Type&stabTypeMask == 0 {
			addrs = append(addrs, s.Value)
		}
	}
	sort.Sort(uint64s(addrs))

	var syms []Sym
	for _, s := range f.File.Symtab.Syms {
		if s.Type&stabTypeMask != 0 {
			continue
		}
		sym := Sym{Name: s.Name, Addr: s.Value, Code: '?'}
		i := sort.Search(len(addrs), func(x int) bool { return addrs[x] > s.Value })
		if i < len(addrs) {
			sym.Size = int64(addrs[i] - s.Value)
		}
		if s.Sect == 0 {
			sym.Code = 'U'
		} else if int(s.Sect) <= len(f.File.Sections) {
			sect := f.File.Sections[s.Sect-1]
			switch sect.Seg {
			case "__TEXT", "__DATA_CONST":
				sym.Code = 'R'
			case "__DATA":
				sym.Code = 'D'
			}
			switch sect.Seg + " " + sect.Name {
			case "__TEXT __text":
				sym.Code = 'T'
			case "__DATA __bss", "__DATA __noptrbss":
				sym.Code = 'B'
			}
		}
		syms = append(syms, sym)
	}
	sort.Sort(byAddr(syms))
	return syms, nil
}

func (f *MachOFile) load() error {
	syms, err := f.symbols()
	if err != nil {
		return err
	}
	f.allSyms = syms
	typeMap := map[string]reflect.Type{}
	allTypes, err := f.Types()
	if err != nil {
		return err
	}
	for _, typ := range allTypes {
		typeMap[fmt.Sprintf("%s.%s", typ.PkgPath(), typ.Name())] = typ
	}
	f.typeMap = typeMap
	funcMap := map[uintptr]*gosym.Func{}
	symtab, err := f.gosymTable()
	if err != nil {
		return err
	}
	for _, fn := range symtab.Funcs {
		fn := fn
		funcMap[uintptr(fn.Value)] = &fn
	}
	f.funcMap = funcMap
	return err
}

func (f *MachOFile) Funcs() ([]*Function, error) {
	symtab, err := f.gosymTable()
	if err != nil {
		return nil, err
	}
	var loadErr error
	f.loadOnce.Do(func() {
		loadErr = f.load()
	})
	if loadErr != nil {
		return nil, loadErr
	}
	addr := f.File.Section("__text").Addr
	textdat, _ := f.File.Section("__text").Data()
	syms := f.allSyms
	lookup := func(addr uint64) (string, uint64) {
		i := sort.Search(len(syms), func(i int) bool { return addr < syms[i].Addr })
		if i > 0 {
			s := syms[i-1]
			if s.Addr != 0 && s.Addr <= addr && addr < s.Addr+uint64(s.Size) {
				return s.Name, s.Addr
			}
		}
		return "", 0
	}
	funcs := make([]*Function, 0, len(symtab.Funcs))
	for _, fn := range symtab.Funcs {
		fn := fn
		start := fn.Entry - addr
		end := fn.End - addr
		mem := textdat[start:end]
		pc := fn.Entry
		funcV := &Function{SymFunc: &fn}
		var pos int
		for pos < len(mem) {
			inst, err := x86asm.Decode(mem[pos:], 64)
			if err != nil {
				break
			}
			switch inst.Op {
			case x86asm.CALL, x86asm.LCALL:
				if len(inst.Args) > 0 {
					rel, ok := inst.Args[0].(x86asm.Rel)
					if ok {
						addr := int64(pc) + int64(rel) + int64(inst.Len)
						fun, found := f.funcMap[uintptr(addr)]
						if found {
							funcV.Callee = append(funcV.Callee, f.funcToSSAFunction(*fun))
						}
					}
				}
			}
			text := x86asm.GoSyntax(inst, pc, lookup)
			funcV.Source = append(funcV.Source, text)
			funcV.Inst = append(funcV.Inst, inst)
			pos += inst.Len
			pc += uint64(inst.Len)
		}
		funcV.SSAFunc = f.funcToSSAFunction(fn)
		funcs = append(funcs, funcV)
	}
	return funcs, nil
}

func (f *MachOFile) funcToSSAFunction(fn gosym.Func) (retfunc *ssa.Function) {
	prog := &ssa.Program{}
	base := fn.Sym.BaseName()
	pkgName := fn.Sym.PackageName()
	recvName := fn.Sym.ReceiverName()
	pkg := prog.Package(types.NewPackage("", pkgName))
	defer func() {
		retfunc.Pkg = pkg
	}()
	if recvName != "" {
		recvType, isPtr := recvType(recvName)
		foundType, exists := f.typeMap[fmt.Sprintf("%s.%s", pkgName, recvType)]
		if exists {
			if isPtr {
				foundType = internalreflect.PtrTo(foundType)
			}
			mtd, found := foundType.MethodByName(base)
			if found && mtd.Type != nil {
				sig := binarytypes.MethodSignatureFromReflectType(foundType, mtd)
				return prog.NewFunction(base, sig, "")
			}
		}
		return prog.NewFunction(base, types.NewSignature(nil, nil, nil, false), "")
	}
	return prog.NewFunction(base, types.NewSignature(nil, nil, nil, false), "")
}

func recvType(recvName string) (string, bool) {
	if recvName == "" {
		return "", false
	}
	if recvName[0] == '(' {
		recvName = recvName[1 : len(recvName)-1]
	}
	isPtr := false
	if recvName[0] == '*' {
		recvName = recvName[1:]
		isPtr = true
	}
	return recvName, isPtr
}

func (f *MachOFile) Types() ([]reflect.Type, error) {
	sect := f.File.Section("__typelink")
	typedat, err := sect.Data()
	if err != nil {
		return nil, err
	}
	typeNum := len(typedat) / 4
	rosect := f.File.Section("__rodata")
	rodata, err := rosect.Data()
	if err != nil {
		return nil, err
	}
	bo := f.File.ByteOrder
	typeOffsets := []int32{}
	for i := 0; i < typeNum; i++ {
		start := 4 * i
		end := 4 * (i + 1)
		var v uint32
		if err := binary.Read(bytes.NewReader(typedat[start:end]), bo, &v); err != nil {
			return nil, err
		}
		typeOffsets = append(typeOffsets, int32(v))
	}
	types := make([]reflect.Type, 0, len(typeOffsets))
	for _, offset := range typeOffsets {
		typ, err := internalreflect.NewType(rosect.Addr, rodata, bo, offset)
		if err != nil {
			return nil, err
		}
		t := reflect.Type(typ)
		if typ.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		types = append(types, t)
	}
	return types, nil
}

func (f *MachOFile) gosymTable() (*gosym.Table, error) {
	symdat, err := f.File.Section("__gosymtab").Data()
	if err != nil {
		return nil, err
	}
	pclndat, err := f.File.Section("__gopclntab").Data()
	if err != nil {
		return nil, err
	}

	pcln := gosym.NewLineTable(pclndat, f.File.Section("__text").Addr)
	tab, err := gosym.NewTable(symdat, pcln)
	if err != nil {
		return nil, err
	}
	return tab, nil
}
