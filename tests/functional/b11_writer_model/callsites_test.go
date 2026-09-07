// FP-M6-31: the Go half of B11's call-site proof (design.md §11.1.3,
// B11's writer model, consequence 4(c)).
//
// A .go call site must be proved to be a *parsed call expression* in the
// declaring process's own source, inside the pinned enclosing declaration, and
// only a Go parser can do that. This guard deliberately duplicates the two
// manifest-side invariants that must not depend on the Python guard having run:
// the file is under the declaring process's source root, and the file is not
// one of the three writer-definition files.
package b11_writer_model_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type callSite struct {
	File   string    `yaml:"file"`
	Line   int       `yaml:"line"`
	In     string    `yaml:"in"`
	Symbol string    `yaml:"symbol"`
	Expr   string    `yaml:"expr"`
	Via    *callSite `yaml:"via"`
}

type writerProcess struct {
	Process   string     `yaml:"process"`
	Tables    []string   `yaml:"tables"`
	CallSites []callSite `yaml:"call_sites"`
}

type concurrencyModel struct {
	Writers         int             `yaml:"writers"`
	WriterProcesses []writerProcess `yaml:"writer_processes"`
}

type benchmarkEntry struct {
	ID               string            `yaml:"id"`
	ConcurrencyModel *concurrencyModel `yaml:"concurrency_model"`
}

type thresholdsFile struct {
	Benchmarks []benchmarkEntry `yaml:"benchmarks"`
}

// processSourceRoots mirrors the Python guard's PROCESS_SOURCE_ROOTS literal.
var processSourceRoots = map[string]string{
	"ingest-gateway":  "services/gateway/",
	"dashboard-api":   "services/dashboard-api/",
	"probe-gateway":   "services/probe-gateway/",
	"temporal-worker": "services/worker/",
}

// writerDefinitionFiles mirrors the Python guard's WRITER_DEFINITION_FILES.
var writerDefinitionFiles = map[string]bool{
	"libs/py/rca_common/rca_common/audit.py":                true,
	"libs/py/rca_common/rca_common/llmclient/tracestore.py": true,
	"services/probe-gateway/internal/audit/audit.go":        true,
}

const sharedLibRoot = "libs/py/rca_common/"

// goSite carries a .go call site together with the process that declared it.
type goSite struct {
	process string
	site    callSite
	isVia   bool
	parent  *callSite
}

func exprHits(lines []string, expr string) []int {
	var hits []int
	for i, l := range lines {
		if strings.Contains(l, expr) {
			hits = append(hits, i+1)
		}
	}
	return hits
}

// enclosingFuncDecl returns the *ast.FuncDecl whose span contains line.
func enclosingFuncDecl(fset *token.FileSet, f *ast.File, line int) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		if start <= line && line <= end {
			return fn
		}
	}
	return nil
}

// matchesIn reports whether fn has the shape `in` describes.  Go spells the
// receiver `func (s *Server) emitCredentialAudits(`, which no literal search
// for `(*Server).emitCredentialAudits` would ever match, so the match is made
// by shape rather than by text.
func matchesIn(fn *ast.FuncDecl, in string) bool {
	if strings.HasPrefix(in, "(*") {
		close := strings.Index(in, ")")
		if close < 0 || !strings.HasPrefix(in[close:], ").") {
			return false
		}
		typeName := in[2:close]
		method := in[close+2:]
		if fn.Name == nil || fn.Name.Name != method {
			return false
		}
		if fn.Recv == nil || len(fn.Recv.List) != 1 {
			return false
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			return false
		}
		ident, ok := star.X.(*ast.Ident)
		return ok && ident.Name == typeName
	}
	return fn.Recv == nil && fn.Name != nil && fn.Name.Name == in
}

func TestB11GoCallSitesAreRealCalls(t *testing.T) {
	// Resolved relative to this package's own directory (design.md 4(c)).
	manifestPath := filepath.Join("..", "..", "benchmark", "thresholds.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read thresholds: %v (path=%s)", err, manifestPath)
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(manifestPath), "..", ".."))

	var tf thresholdsFile
	if err := yaml.Unmarshal(raw, &tf); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	var model *concurrencyModel
	for _, b := range tf.Benchmarks {
		if b.ID == "B11" {
			model = b.ConcurrencyModel
			break
		}
	}
	if model == nil {
		t.Fatal("B11 concurrency_model missing")
	}

	// Every call_sites entry AND every via block whose file ends in .go.
	var sites []goSite
	for _, wp := range model.WriterProcesses {
		for i := range wp.CallSites {
			cs := wp.CallSites[i]
			if strings.HasSuffix(cs.File, ".go") {
				sites = append(sites, goSite{process: wp.Process, site: cs, parent: &cs})
			}
			if cs.Via != nil && strings.HasSuffix(cs.Via.File, ".go") {
				sites = append(sites, goSite{process: wp.Process, site: *cs.Via, isVia: true})
			}
		}
	}
	if len(sites) == 0 {
		t.Fatal("no .go call_sites in B11 concurrency_model — this guard would be vacuous")
	}

	for _, gs := range sites {
		site := gs.site

		// Manifest-side invariant 1: not a writer definition.
		if writerDefinitionFiles[site.File] {
			t.Fatalf("%s is a writer definition, not a caller (process %s)", site.File, gs.process)
		}
		// Manifest-side invariant 2: the declaring process's own source root.
		root, ok := processSourceRoots[gs.process]
		if !ok {
			t.Fatalf("unknown process %q in concurrency_model", gs.process)
		}
		inRoot := strings.HasPrefix(site.File, root)
		if !inRoot && !gs.isVia && gs.parent != nil && gs.parent.Via != nil {
			inRoot = strings.HasPrefix(site.File, sharedLibRoot) &&
				strings.HasPrefix(gs.parent.Via.File, root)
		}
		if !inRoot {
			t.Fatalf("%s is outside %s's source root %q", site.File, gs.process, root)
		}
		// symbol must occur inside expr.
		if !strings.Contains(site.Expr, site.Symbol) {
			t.Fatalf("symbol %q does not occur inside expr %q", site.Symbol, site.Expr)
		}

		path := filepath.Join(repoRoot, site.File)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		lines := strings.Split(string(src), "\n")
		if site.Line < 1 || site.Line > len(lines) {
			t.Fatalf("%s:%d out of range (expr occurs at %v)", site.File, site.Line,
				exprHits(lines, site.Expr))
		}
		lineText := lines[site.Line-1]
		if !strings.Contains(lineText, site.Expr) {
			t.Fatalf("%s:%d missing expr %q (expr occurs at %v)\n  line: %s",
				site.File, site.Line, site.Expr, exprHits(lines, site.Expr), lineText)
		}
		s := strings.Index(lineText, site.Expr)
		sCol, eCol := s+1, s+len(site.Expr)+1

		// The parsed-call proof: comments land in File.Comments and never become
		// CallExprs, and a string literal is a *ast.BasicLit.
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fset.Position(call.Pos()).Line != site.Line {
				return true
			}
			sym := ""
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				sym = fun.Sel.Name
			case *ast.Ident:
				sym = fun.Name
			}
			if sym != site.Symbol {
				return true
			}
			endCol := fset.Position(call.Fun.End()).Column
			if sCol <= endCol && endCol <= eCol {
				found = true
			}
			return true
		})
		if !found {
			t.Fatalf("no *ast.CallExpr for %s at %s:%d covered by %q — a comment or "+
				"string literal is not a call (expr occurs at %v)",
				site.Symbol, site.File, site.Line, site.Expr, exprHits(lines, site.Expr))
		}

		// The enclosing declaration, matched to `in` by shape.
		fn := enclosingFuncDecl(fset, f, site.Line)
		if fn == nil {
			t.Fatalf("%s:%d is not inside any func declaration (expected %q)",
				site.File, site.Line, site.In)
		}
		if !matchesIn(fn, site.In) {
			recv := "nil"
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				recv = "receiver"
			}
			t.Fatalf("%s:%d is inside func %s (recv=%s), not the pinned enclosing "+
				"declaration %q", site.File, site.Line, fn.Name.Name, recv, site.In)
		}
	}
}
