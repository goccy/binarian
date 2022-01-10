package ssa

import (
	"debug/gosym"
	"fmt"
	"go/ast"
	"go/types"

	internalreflect "github.com/goccy/binarian/internal/reflect"
	"github.com/goccy/binarian/reflect"
	binarytypes "github.com/goccy/binarian/types"
	"golang.org/x/tools/go/ssa"
)

type Builder struct {
	typeMap map[string]reflect.Type
	prog    *ssa.Program
}

func NewBuilder(types []reflect.Type) *Builder {
	typeMap := map[string]reflect.Type{}
	for _, typ := range types {
		typeMap[fmt.Sprintf("%s.%s", typ.PkgPath(), typ.Name())] = typ
	}
	return &Builder{
		typeMap: typeMap,
		prog:    ssa.NewProgram(nil, 0),
	}
}

func (b *Builder) BuildFunction(fn gosym.Func) *ssa.Function {
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	pkg := b.prog.CreatePackage(types.NewPackage("", fn.Sym.PackageName()), nil, info, false)
	f := b.functionFromGoSymFunc(fn)
	f.Pkg = pkg
	return f
}

func (b *Builder) functionFromGoSymFunc(fn gosym.Func) *ssa.Function {
	base := fn.Sym.BaseName()
	pkgName := fn.Sym.PackageName()
	recvName := fn.Sym.ReceiverName()
	if recvName != "" {
		recvType, isPtr := recvType(recvName)
		foundType, exists := b.typeMap[fmt.Sprintf("%s.%s", pkgName, recvType)]
		if exists {
			if isPtr {
				foundType = internalreflect.PtrTo(foundType)
			}
			mtd, found := foundType.MethodByName(base)
			if found && mtd.Type != nil {
				sig := binarytypes.MethodSignatureFromReflectType(foundType, mtd)
				return b.prog.NewFunction(base, sig, "")
			}
		}
		return b.prog.NewFunction(base, types.NewSignature(nil, nil, nil, false), "")
	}
	return b.prog.NewFunction(base, types.NewSignature(nil, nil, nil, false), "")
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
