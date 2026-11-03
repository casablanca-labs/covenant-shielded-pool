package pkload

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestNoExportedDecoderTakesBytes reads this package's source: no exported
// function or method that returns a proving key may take a byte slice. Bytes
// reach a decoder only inside a Verified, which only ReadVerified makes (F5).
func TestNoExportedDecoderTakesBytes(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
					continue
				}
				returnsKey := false
				for _, r := range fn.Type.Results.List {
					if strings.Contains(types(r.Type), "ProvingKey") {
						returnsKey = true
					}
				}
				if !returnsKey {
					continue
				}
				checked++
				for _, p := range fn.Type.Params.List {
					if types(p.Type) == "[]byte" {
						t.Errorf("%s: exported %s returns a proving key and takes a []byte parameter; it would decode unpinned bytes",
							fset.Position(fn.Pos()), fn.Name.Name)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no exported function returning a proving key; the check is vacuous")
	}
}

func types(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + types(x.X)
	case *ast.SelectorExpr:
		return types(x.X) + "." + x.Sel.Name
	case *ast.ArrayType:
		if x.Len == nil {
			return "[]" + types(x.Elt)
		}
		return "[N]" + types(x.Elt)
	}
	return "?"
}
