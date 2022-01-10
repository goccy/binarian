package file_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/binarian/file"
	"github.com/goccy/binarian/reflect"
)

func TestMachOFile(t *testing.T) {
	path := filepath.Join("testdata", "macho")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	machoFile, err := file.NewMachOFile(f)
	if err != nil {
		t.Fatal(err)
	}
	types, err := machoFile.Types()
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range types {
		if typ.Kind() != reflect.Interface {
			continue
		}
		for i := 0; i < typ.NumMethod(); i++ {
			mtd := typ.Method(i)
			foundMtd, found := typ.MethodByName(mtd.Name)
			if !found || foundMtd.Name != mtd.Name {
				t.Fatalf("failed to get method by name %s", mtd.Name)
			}
		}
	}
	funcs, err := machoFile.Funcs()
	if err != nil {
		t.Fatal(err)
	}
	for _, fun := range funcs {
		t.Log(fun.SSAFunc)
	}
}
