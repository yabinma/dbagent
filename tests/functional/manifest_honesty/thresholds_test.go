// FP-M6-26: Go half of the threshold-assertion honesty rule
// (design.md §11.1.3 errata passes 11–16).
//
// A .go link at status:covered must contain a reachable, executable
// threshold check — proved by go/parser AST inspection with full lexical
// resolution (goResolve), not regex over source text. Comments are
// excluded by parsing without ParseComments.
package manifest_honesty_test

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Closed threshold-reason vocabulary (design.md clause (W)(1) — 22 tokens).
// ---------------------------------------------------------------------------

var thresholdReasons = map[string]bool{
	"missing_file":               true,
	"ambiguous_test_name":        true,
	"nonexistent_linked_test":    true,
	"unknown_suffix":             true,
	"missing_go_guard":           true,
	"build_context":              true,
	"not_collected":              true,
	"skipped":                    true,
	"dead_candidate":             true,
	"swallowed_candidate":        true,
	"no_candidate":               true,
	"not_a_threshold_comparison": true,
	"both_operands_numeric":      true,
	"no_numeric_term":            true,
	"unresolved_identifier":      true,
	"not_testify":                true,
	"bad_testing_t":              true,
	"spread_operand":             true,
	"no_fail_in_branch":          true,
	"star_import":                true,
	"dot_import":                 true,
	"bad_tolerance":              true,
}

// ---------------------------------------------------------------------------
// Closed sets
// ---------------------------------------------------------------------------

var failSelectors = map[string]bool{
	"Fatal": true, "Fatalf": true,
	"Error": true, "Errorf": true,
	"FailNow": true, "Fail": true,
}

var skipSelectors = map[string]bool{
	"Skip": true, "SkipNow": true, "Skipf": true,
}

var requireAssertSelectors = map[string]bool{
	"Less": true, "Lessf": true,
	"LessOrEqual": true, "LessOrEqualf": true,
	"Greater": true, "Greaterf": true,
	"GreaterOrEqual": true, "GreaterOrEqualf": true,
	"InDelta": true, "InDeltaf": true,
	"InEpsilon": true, "InEpsilonf": true,
}

var inDeltaEpsilon = map[string]bool{
	"InDelta": true, "InDeltaf": true,
	"InEpsilon": true, "InEpsilonf": true,
}

var durationUnits = map[string]bool{
	"Nanosecond": true, "Microsecond": true, "Millisecond": true,
	"Second": true, "Minute": true, "Hour": true,
}

var testifyPaths = map[string]bool{
	"github.com/stretchr/testify/require": true,
	"github.com/stretchr/testify/assert":  true,
}

var testingPaths = map[string]bool{"testing": true}
var timePaths = map[string]bool{"time": true}

const numericDepthCap = 3

// ---------------------------------------------------------------------------
// YAML manifest types
// ---------------------------------------------------------------------------

type benchmarkEntry struct {
	ID     string   `yaml:"id"`
	Status string   `yaml:"status"`
	Tests  []string `yaml:"tests"`
}

type thresholdsFile struct {
	Benchmarks []benchmarkEntry `yaml:"benchmarks"`
}

// ---------------------------------------------------------------------------
// Binding / resolution model
// ---------------------------------------------------------------------------

type bindKind int

const (
	bindConst bindKind = iota
	bindVar
	bindType
	bindDefine
	bindAssign
	bindRange
	bindParam
	bindTypeParam
	bindImport
	bindFunc
)

type binding struct {
	kind       bindKind
	name       string
	pos        token.Pos // identifier position
	scopeStart token.Pos // per (P)(1) table; NoPos = position-independent
	value      ast.Expr  // const/var value expression when available
	spec       *ast.ValueSpec
	importSpec *ast.ImportSpec
	paramField *ast.Field // for param bindings
	node       ast.Node   // declaring node
	file       *ast.File  // declaring file (package-scope bindings span files)
}

type resolution struct {
	found       bool
	predeclared bool
	scope       ast.Node // binding scope node
	bindings    []binding
	declFile    *ast.File
	mutations   []binding
}

type pkgContext struct {
	fset       *token.FileSet
	dir        string
	pkgName    string
	files      map[string]*ast.File // basename → file
	linked     *ast.File
	linkedBase string
	fn         *ast.FuncDecl // linked function under check
	parents    map[ast.Node]ast.Node
	// implicit scope markers: nodes that act as scopes without being BlockStmt
}

// ciGoBuildContext is the build context the CI jobs that run the Go links use.
func ciGoBuildContext() build.Context {
	c := build.Default
	c.GOOS = "linux"
	c.GOARCH = "amd64"
	c.CgoEnabled = true
	c.BuildTags = nil
	c.UseAllFiles = false
	return c
}

// ---------------------------------------------------------------------------
// Constant-folding (boolean-literal fragment only). Undecided ⇒ not dead.
// ---------------------------------------------------------------------------

func isConstantTrue(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "true"
	case *ast.ParenExpr:
		return isConstantTrue(v.X)
	case *ast.UnaryExpr:
		if v.Op == token.NOT {
			return isConstantFalse(v.X)
		}
	case *ast.BinaryExpr:
		switch v.Op {
		case token.LAND:
			return isConstantTrue(v.X) && isConstantTrue(v.Y)
		case token.LOR:
			return isConstantTrue(v.X) || isConstantTrue(v.Y)
		}
	}
	return false
}

func isConstantFalse(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "false"
	case *ast.ParenExpr:
		return isConstantFalse(v.X)
	case *ast.UnaryExpr:
		if v.Op == token.NOT {
			return isConstantTrue(v.X)
		}
	case *ast.BinaryExpr:
		switch v.Op {
		case token.LAND:
			return isConstantFalse(v.X) || isConstantFalse(v.Y)
		case token.LOR:
			return isConstantFalse(v.X) && isConstantFalse(v.Y)
		}
	}
	return false
}

func unwrapParen(e ast.Expr) ast.Expr {
	for {
		if p, ok := e.(*ast.ParenExpr); ok {
			e = p.X
			continue
		}
		return e
	}
}

// ---------------------------------------------------------------------------
// Parent map
// ---------------------------------------------------------------------------

func buildParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	stack := []ast.Node{}
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

// ---------------------------------------------------------------------------
// Package loading
// ---------------------------------------------------------------------------

func loadPackage(linkedPath string) (*pkgContext, string) {
	abs, err := filepath.Abs(linkedPath)
	if err != nil {
		return nil, "missing_file"
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, "missing_file"
	}
	// Build context (N) before anything else.
	ctx := ciGoBuildContext()
	match, err := ctx.MatchFile(filepath.Dir(abs), filepath.Base(abs))
	if err != nil || !match {
		return nil, "build_context"
	}

	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	fset := token.NewFileSet()
	linkedFile, err := parser.ParseFile(fset, abs, nil, 0)
	if err != nil {
		return nil, "missing_file"
	}
	pkgName := linkedFile.Name.Name
	files := map[string]*ast.File{base: linkedFile}

	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			if !strings.HasSuffix(name, ".go") || name == base {
				continue
			}
			p := filepath.Join(dir, name)
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				continue
			}
			if f.Name.Name != pkgName {
				continue
			}
			files[name] = f
		}
	}

	// Parent map over the linked file (scope chains are file-local for blocks;
	// package scope is handled separately).
	parents := buildParentMap(linkedFile)

	return &pkgContext{
		fset:       fset,
		dir:        dir,
		pkgName:    pkgName,
		files:      files,
		linked:     linkedFile,
		linkedBase: base,
		parents:    parents,
	}, ""
}

func fileHasDotImport(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Name != nil && imp.Name.Name == "." {
			return true
		}
	}
	return false
}

// importBoundName returns the bound name of an ImportSpec.
func importBoundName(imp *ast.ImportSpec) string {
	if imp.Name != nil {
		return imp.Name.Name
	}
	path := strings.Trim(imp.Path.Value, `"`)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ---------------------------------------------------------------------------
// goPackageBindings — package scope across matching-package files.
// ---------------------------------------------------------------------------

func (pkg *pkgContext) goPackageBindings(name string) []binding {
	var out []binding
	for _, f := range pkg.files {
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.GenDecl:
				switch decl.Tok {
				case token.CONST, token.VAR:
					for _, spec := range decl.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, n := range vs.Names {
							if n.Name != name {
								continue
							}
							kind := bindVar
							if decl.Tok == token.CONST {
								kind = bindConst
							}
							b := binding{
								kind: kind,
								name: name,
								pos:  n.Pos(),
								// package-scope: position-independent
								scopeStart: token.NoPos,
								spec:       vs,
								node:       vs,
								file:       f, // (I)(3)/(5) declaring file
							}
							if len(vs.Values) == len(vs.Names) {
								b.value = vs.Values[i]
							}
							out = append(out, b)
						}
					}
				case token.TYPE:
					for _, spec := range decl.Specs {
						ts, ok := spec.(*ast.TypeSpec)
						if !ok || ts.Name.Name != name {
							continue
						}
						out = append(out, binding{
							kind:       bindType,
							name:       name,
							pos:        ts.Name.Pos(),
							scopeStart: token.NoPos,
							node:       ts,
							file:       f,
						})
					}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name != nil && decl.Name.Name == name {
					out = append(out, binding{
						kind:       bindFunc,
						name:       name,
						pos:        decl.Name.Pos(),
						scopeStart: token.NoPos,
						node:       decl,
						file:       f,
					})
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// goMutations — scope-blind assign-kind occurrences in the linked FuncDecl.
// ---------------------------------------------------------------------------

func goMutations(fn *ast.FuncDecl, name string) []binding {
	if fn == nil || fn.Body == nil {
		return nil
	}
	var out []binding
	ast.Inspect(fn, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				return true
			}
			// plain = and compound
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
					out = append(out, binding{
						kind: bindAssign,
						name: name,
						pos:  id.Pos(),
						node: s,
					})
				}
			}
		case *ast.IncDecStmt:
			if id, ok := s.X.(*ast.Ident); ok && id.Name == name {
				out = append(out, binding{
					kind: bindAssign,
					name: name,
					pos:  id.Pos(),
					node: s,
				})
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN {
				if id, ok := s.Key.(*ast.Ident); ok && id.Name == name {
					out = append(out, binding{
						kind: bindAssign,
						name: name,
						pos:  id.Pos(),
						node: s,
					})
				}
				if id, ok := s.Value.(*ast.Ident); ok && id.Name == name {
					out = append(out, binding{
						kind: bindAssign,
						name: name,
						pos:  id.Pos(),
						node: s,
					})
				}
			}
		}
		return true
	})
	return out
}

// ---------------------------------------------------------------------------
// goBlockBindings — non-recursive, per-scope.
// ---------------------------------------------------------------------------

func isDeclKind(k bindKind) bool {
	switch k {
	case bindConst, bindVar, bindDefine, bindRange, bindParam, bindType, bindTypeParam:
		return true
	}
	return false
}

// goBlockBindings collects bindings a single scope introduces directly.
func (pkg *pkgContext) goBlockBindings(scope ast.Node, name string) []binding {
	var out []binding

	addValueSpec := func(gd *ast.GenDecl, vs *ast.ValueSpec) {
		for i, n := range vs.Names {
			if n.Name != name {
				continue
			}
			kind := bindVar
			if gd.Tok == token.CONST {
				kind = bindConst
			}
			b := binding{
				kind:       kind,
				name:       name,
				pos:        n.Pos(),
				scopeStart: vs.End(), // (P)(1): ValueSpec.End()
				spec:       vs,
				node:       vs,
			}
			if len(vs.Values) == len(vs.Names) {
				b.value = vs.Values[i]
			}
			out = append(out, b)
		}
	}

	addAssign := func(s *ast.AssignStmt) {
		kind := bindAssign
		if s.Tok == token.DEFINE {
			kind = bindDefine
		}
		for _, lhs := range s.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
				b := binding{
					kind: kind,
					name: name,
					pos:  id.Pos(),
					node: s,
				}
				if kind == bindDefine {
					b.scopeStart = s.End()
				}
				out = append(out, b)
			}
		}
	}

	addParams := func(fl *ast.FieldList, scopeStart token.Pos) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			for _, n := range field.Names {
				if n.Name == name {
					out = append(out, binding{
						kind:       bindParam,
						name:       name,
						pos:        n.Pos(),
						scopeStart: scopeStart,
						paramField: field,
						node:       n,
					})
				}
			}
		}
	}

	addTypeParams := func(fl *ast.FieldList, scopeStart token.Pos) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			for _, n := range field.Names {
				if n.Name == name {
					out = append(out, binding{
						kind:       bindTypeParam,
						name:       name,
						pos:        n.Pos(),
						scopeStart: scopeStart,
						node:       n,
					})
				}
			}
		}
	}

	switch s := scope.(type) {
	case *ast.BlockStmt:
		// Params of enclosing FuncDecl/FuncLit are bound in the Body block.
		if parent, ok := pkg.parents[s]; ok {
			switch p := parent.(type) {
			case *ast.FuncDecl:
				if p.Body == s {
					start := s.Lbrace
					if p.Recv != nil {
						addParams(p.Recv, start)
					}
					if p.Type != nil {
						addParams(p.Type.Params, start)
						addParams(p.Type.Results, start)
						addTypeParams(p.Type.TypeParams, start)
					}
				}
			case *ast.FuncLit:
				if p.Body == s && p.Type != nil {
					start := s.Lbrace
					addParams(p.Type.Params, start)
					addParams(p.Type.Results, start)
					addTypeParams(p.Type.TypeParams, start)
				}
			}
		}
		// Direct statements only — do not descend into nested scopes.
		for _, stmt := range s.List {
			switch st := stmt.(type) {
			case *ast.DeclStmt:
				if gd, ok := st.Decl.(*ast.GenDecl); ok {
					switch gd.Tok {
					case token.CONST, token.VAR:
						for _, spec := range gd.Specs {
							if vs, ok := spec.(*ast.ValueSpec); ok {
								addValueSpec(gd, vs)
							}
						}
					case token.TYPE:
						for _, spec := range gd.Specs {
							if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.Name == name {
								out = append(out, binding{
									kind:       bindType,
									name:       name,
									pos:        ts.Name.Pos(),
									scopeStart: ts.Name.Pos(),
									node:       ts,
								})
							}
						}
					}
				}
			case *ast.AssignStmt:
				addAssign(st)
			case *ast.IncDecStmt:
				if id, ok := st.X.(*ast.Ident); ok && id.Name == name {
					out = append(out, binding{
						kind: bindAssign,
						name: name,
						pos:  id.Pos(),
						node: st,
					})
				}
			}
			// Nested BlockStmt / IfStmt / ForStmt / etc. are separate scopes
			// — not collected here.
		}

	case *ast.IfStmt:
		// Implicit block: Init bindings.
		if s.Init != nil {
			if as, ok := s.Init.(*ast.AssignStmt); ok {
				addAssign(as)
			}
			if ds, ok := s.Init.(*ast.DeclStmt); ok {
				if gd, ok := ds.Decl.(*ast.GenDecl); ok && (gd.Tok == token.CONST || gd.Tok == token.VAR) {
					for _, spec := range gd.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							addValueSpec(gd, vs)
						}
					}
				}
			}
		}

	case *ast.ForStmt:
		if s.Init != nil {
			if as, ok := s.Init.(*ast.AssignStmt); ok {
				addAssign(as)
			}
		}

	case *ast.RangeStmt:
		// := form → bindRange with scope-start rng.X.End()
		// = form → bindAssign (mutation); also collected by goMutations
		if s.Tok == token.DEFINE {
			start := s.X.End()
			if id, ok := s.Key.(*ast.Ident); ok && id.Name == name {
				out = append(out, binding{
					kind:       bindRange,
					name:       name,
					pos:        id.Pos(),
					scopeStart: start,
					node:       s,
				})
			}
			if id, ok := s.Value.(*ast.Ident); ok && id.Name == name {
				out = append(out, binding{
					kind:       bindRange,
					name:       name,
					pos:        id.Pos(),
					scopeStart: start,
					node:       s,
				})
			}
		} else if s.Tok == token.ASSIGN {
			if id, ok := s.Key.(*ast.Ident); ok && id.Name == name {
				out = append(out, binding{kind: bindAssign, name: name, pos: id.Pos(), node: s})
			}
			if id, ok := s.Value.(*ast.Ident); ok && id.Name == name {
				out = append(out, binding{kind: bindAssign, name: name, pos: id.Pos(), node: s})
			}
		}

	case *ast.SwitchStmt:
		if s.Init != nil {
			if as, ok := s.Init.(*ast.AssignStmt); ok {
				addAssign(as)
			}
		}

	case *ast.TypeSwitchStmt:
		// Init + the Assign is on the TypeSwitch itself; guard re-declared
		// per CaseClause (handled under *ast.CaseClause).
		if s.Init != nil {
			if as, ok := s.Init.(*ast.AssignStmt); ok {
				addAssign(as)
			}
		}

	case *ast.CaseClause:
		// Type-switch guard re-declared here.
		// Find enclosing TypeSwitchStmt.
		cur := scope
		for cur != nil {
			if ts, ok := cur.(*ast.TypeSwitchStmt); ok {
				if as, ok := ts.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE {
					start := s.Colon + 1
					for _, lhs := range as.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
							out = append(out, binding{
								kind:       bindDefine,
								name:       name,
								pos:        id.Pos(),
								scopeStart: start,
								node:       as,
							})
						}
					}
				}
				break
			}
			cur = pkg.parents[cur]
		}
		// CaseClause body statements that are direct decls/assigns are in
		// the clause's implicit block — also collect direct non-nested.
		for _, stmt := range s.Body {
			switch st := stmt.(type) {
			case *ast.DeclStmt:
				if gd, ok := st.Decl.(*ast.GenDecl); ok && (gd.Tok == token.CONST || gd.Tok == token.VAR) {
					for _, spec := range gd.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							addValueSpec(gd, vs)
						}
					}
				}
			case *ast.AssignStmt:
				addAssign(st)
			}
		}

	case *ast.CommClause:
		if s.Comm != nil {
			if as, ok := s.Comm.(*ast.AssignStmt); ok && as.Tok == token.DEFINE {
				start := s.Comm.End()
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
						out = append(out, binding{
							kind:       bindDefine,
							name:       name,
							pos:        id.Pos(),
							scopeStart: start,
							node:       as,
						})
					}
				}
			}
		}
		for _, stmt := range s.Body {
			switch st := stmt.(type) {
			case *ast.DeclStmt:
				if gd, ok := st.Decl.(*ast.GenDecl); ok && (gd.Tok == token.CONST || gd.Tok == token.VAR) {
					for _, spec := range gd.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							addValueSpec(gd, vs)
						}
					}
				}
			case *ast.AssignStmt:
				addAssign(st)
			}
		}

	case *ast.File:
		// File scope: ImportSpec bound names only.
		for _, imp := range s.Imports {
			bn := importBoundName(imp)
			if bn == "." || bn == "_" {
				continue
			}
			if bn == name {
				out = append(out, binding{
					kind:       bindImport,
					name:       name,
					pos:        imp.Pos(),
					scopeStart: token.NoPos,
					importSpec: imp,
					node:       imp,
				})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// goScopeChain — innermost-first scope-introducing nodes for an identifier.
// ---------------------------------------------------------------------------

func (pkg *pkgContext) goScopeChain(id *ast.Ident) []ast.Node {
	var chain []ast.Node
	seen := map[ast.Node]bool{}
	add := func(n ast.Node) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		chain = append(chain, n)
	}

	cur := ast.Node(id)
	for cur != nil {
		switch n := cur.(type) {
		case *ast.BlockStmt:
			add(n)
		case *ast.IfStmt:
			add(n)
		case *ast.ForStmt:
			add(n)
		case *ast.RangeStmt:
			add(n)
		case *ast.SwitchStmt:
			add(n)
		case *ast.TypeSwitchStmt:
			add(n)
		case *ast.SelectStmt:
			// Select itself introduces no bindings; CommClauses do.
		case *ast.CaseClause:
			add(n)
		case *ast.CommClause:
			add(n)
		case *ast.File:
			add(n)
		case *ast.FuncDecl, *ast.FuncLit:
			// Params are attributed to the Body block; do not add as separate
			// scope node beyond what Body provides.
		}
		cur = pkg.parents[cur]
	}
	// Ensure File is present.
	add(pkg.linked)
	return chain
}

// ---------------------------------------------------------------------------
// goResolve
// ---------------------------------------------------------------------------

func (pkg *pkgContext) goResolve(id *ast.Ident) resolution {
	if id == nil {
		return resolution{}
	}
	name := id.Name
	var mutations []binding

	// Local / function scopes first. A name bound in an enclosing block is
	// still that local even when the file also carries a dot-import — the
	// poison applies to file + package + universe (I)(4)(0), which is what
	// lets t.Errorf stay admissible so the fixture reports `dot_import` via
	// (W)(4) rather than `bad_testing_t`.
	for _, scope := range pkg.goScopeChain(id) {
		if _, isFile := scope.(*ast.File); isFile {
			continue // handled after the loop
		}
		binds := pkg.goBlockBindings(scope, name)
		if len(binds) == 0 {
			continue
		}
		// Declaration whose scope-start <= id.Pos()?
		var decls []binding
		var assigns []binding
		for _, b := range binds {
			if isDeclKind(b.kind) {
				if b.scopeStart == token.NoPos || b.scopeStart <= id.Pos() {
					decls = append(decls, b)
				}
			} else if b.kind == bindAssign {
				assigns = append(assigns, b)
			}
		}
		if len(decls) > 0 {
			// Binding scope found. Binding set = every occurrence in S.
			return resolution{
				found:     true,
				scope:     scope,
				bindings:  binds,
				declFile:  pkg.linked,
				mutations: append(mutations, goMutations(pkg.fn, name)...),
			}
		}
		if len(assigns) > 0 {
			mutations = append(mutations, assigns...)
			continue
		}
	}

	// (I)(4)(0) / review C3: after locals, dot-import poisons file scope,
	// package scope and the universe — checked *before* any of those are
	// consulted, so a package const or import is never silently admitted.
	if fileHasDotImport(pkg.linked) {
		return resolution{mutations: append(mutations, goMutations(pkg.fn, name)...)}
	}

	// File scope — imports of the linked file.
	fileBinds := pkg.goBlockBindings(pkg.linked, name)
	if len(fileBinds) > 0 {
		// Only import bindings live here; all are declarations.
		return resolution{
			found:     true,
			scope:     pkg.linked,
			bindings:  fileBinds,
			declFile:  pkg.linked,
			mutations: append(mutations, goMutations(pkg.fn, name)...),
		}
	}

	// Package scope — declFile is the file that actually declares the binding
	// so package-const RHS is evaluated with that file's imports (I)(5).
	pkgBinds := pkg.goPackageBindings(name)
	if len(pkgBinds) > 0 {
		declFile := pkg.linked
		if pkgBinds[0].file != nil {
			declFile = pkgBinds[0].file
		}
		return resolution{
			found:     true,
			scope:     nil, // package
			bindings:  pkgBinds,
			declFile:  declFile,
			mutations: append(mutations, goMutations(pkg.fn, name)...),
		}
	}

	// Universe / predeclared.
	return resolution{
		predeclared: true,
		mutations:   append(mutations, goMutations(pkg.fn, name)...),
	}
}

// ---------------------------------------------------------------------------
// Import / test-param admission
// ---------------------------------------------------------------------------

func (pkg *pkgContext) admitsImport(id *ast.Ident, paths map[string]bool) bool {
	if id == nil {
		return false
	}
	// Dot-import poisons every resolution in this file (I)(4)(0) — including
	// explicit imports used as package selectors.
	if fileHasDotImport(pkg.linked) {
		return false
	}
	// Explicit ImportSpec match in the linked file.
	var matches []*ast.ImportSpec
	for _, imp := range pkg.linked.Imports {
		bn := importBoundName(imp)
		if bn == "." || bn == "_" {
			continue
		}
		if bn != id.Name {
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		if paths[path] {
			matches = append(matches, imp)
		}
	}
	if len(matches) != 1 {
		return false
	}
	// No package-scope declaration collides.
	if len(pkg.goPackageBindings(id.Name)) > 0 {
		return false
	}
	// No local shadow of the name on the way to the use (goResolve must land
	// at file-scope import).
	res := pkg.goResolve(id)
	if !res.found {
		return false
	}
	if _, isFile := res.scope.(*ast.File); !isFile {
		return false
	}
	// Exactly one import binding, path in set.
	if len(res.bindings) != 1 || res.bindings[0].kind != bindImport {
		return false
	}
	imp := res.bindings[0].importSpec
	if imp == nil {
		return false
	}
	path := strings.Trim(imp.Path.Value, `"`)
	return paths[path]
}

func (pkg *pkgContext) goAdmittedTestParam(id *ast.Ident) bool {
	if id == nil || pkg.fn == nil || pkg.fn.Body == nil {
		return false
	}
	res := pkg.goResolve(id)
	if !res.found {
		return false
	}
	// Exactly one occurrence, kind param.
	if len(res.bindings) != 1 || res.bindings[0].kind != bindParam {
		return false
	}
	// Binding scope is the linked FuncDecl's own body block.
	body, ok := res.scope.(*ast.BlockStmt)
	if !ok || body != pkg.fn.Body {
		return false
	}
	// Declared type *testing.T / *testing.B / *testing.F.
	field := res.bindings[0].paramField
	if field == nil || !isStarTestingType(field.Type, pkg, "") {
		return false
	}
	// No mutations.
	if len(goMutations(pkg.fn, id.Name)) > 0 {
		return false
	}
	return true
}

// importSpecMatches reports whether id is bound by exactly one ImportSpec in
// the linked file whose path is in paths, with no package-scope collision.
// Unlike admitsImport this does not consult goResolve, so a dot-import does
// not poison *signature* type checks (collection / TestingT param type) while
// still poisoning value-level uses that go through admitsImport (review C3).
func (pkg *pkgContext) importSpecMatches(id *ast.Ident, paths map[string]bool) bool {
	if id == nil {
		return false
	}
	var matches int
	for _, imp := range pkg.linked.Imports {
		bn := importBoundName(imp)
		if bn == "." || bn == "_" || bn != id.Name {
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		if paths[path] {
			matches++
		}
	}
	if matches != 1 {
		return false
	}
	return len(pkg.goPackageBindings(id.Name)) == 0
}

// isStarTestingType reports whether typ is *testing.T/B/F (or a specific sel
// when wantSel != "").
func isStarTestingType(typ ast.Expr, pkg *pkgContext, wantSel string) bool {
	star, ok := typ.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgID, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if wantSel != "" && sel.Sel.Name != wantSel {
		return false
	}
	if wantSel == "" {
		switch sel.Sel.Name {
		case "T", "B", "F":
		default:
			return false
		}
	}
	// Signature type — ImportSpec match only (not goResolve / admitsImport).
	return pkg.importSpecMatches(pkgID, testingPaths)
}

// ---------------------------------------------------------------------------
// Numeric terms
// ---------------------------------------------------------------------------

func (pkg *pkgContext) isNumericTerm(e ast.Expr, depth int) bool {
	if depth > numericDepthCap || e == nil {
		return false
	}
	switch v := e.(type) {
	case *ast.ParenExpr:
		return pkg.isNumericTerm(v.X, depth)
	case *ast.BasicLit:
		return v.Kind == token.INT || v.Kind == token.FLOAT
	case *ast.UnaryExpr:
		if v.Op == token.ADD || v.Op == token.SUB {
			return pkg.isNumericTerm(v.X, depth+1)
		}
	case *ast.BinaryExpr:
		// Form 2: fixed duration
		if v.Op == token.MUL && pkg.isFixedDuration(v, depth) {
			return true
		}
		// Form 3
		if v.Op == token.ADD || v.Op == token.SUB || v.Op == token.MUL || v.Op == token.QUO {
			return pkg.isNumericTerm(v.X, depth+1) && pkg.isNumericTerm(v.Y, depth+1)
		}
	case *ast.Ident:
		// Form 5
		return pkg.isNumericIdent(v, depth)
	}
	return false
}

// isNumericTermStrictLiteral: form 1 or form 4 over form 1 only (no form 5).
func (pkg *pkgContext) isNumericTermStrictLiteral(e ast.Expr, depth int) bool {
	if depth > numericDepthCap || e == nil {
		return false
	}
	switch v := e.(type) {
	case *ast.ParenExpr:
		return pkg.isNumericTermStrictLiteral(v.X, depth)
	case *ast.BasicLit:
		return v.Kind == token.INT || v.Kind == token.FLOAT
	case *ast.UnaryExpr:
		if v.Op == token.ADD || v.Op == token.SUB {
			return pkg.isNumericTermStrictLiteral(v.X, depth+1)
		}
	}
	return false
}

func (pkg *pkgContext) isFixedDuration(bin *ast.BinaryExpr, depth int) bool {
	litSide := func(e ast.Expr) bool {
		return pkg.isNumericTermStrictLiteral(e, depth+1)
	}
	unitSide := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkgID, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		if !durationUnits[sel.Sel.Name] {
			return false
		}
		return pkg.admitsImport(pkgID, timePaths)
	}
	return (litSide(bin.X) && unitSide(bin.Y)) || (unitSide(bin.X) && litSide(bin.Y))
}

func (pkg *pkgContext) isNumericIdent(id *ast.Ident, depth int) bool {
	res := pkg.goResolve(id)
	if !res.found {
		return false
	}
	// Exactly one occurrence, kind const; no other kinds; no mutations.
	if len(res.bindings) != 1 || res.bindings[0].kind != bindConst {
		return false
	}
	if len(res.mutations) > 0 {
		// goMutations already included; also check recorded
		return false
	}
	// Extra safety: scope-blind mutations
	if pkg.fn != nil && len(goMutations(pkg.fn, id.Name)) > 0 {
		return false
	}
	val := res.bindings[0].value
	if val == nil {
		return false
	}
	// Recurse into the value expression in the *declaring* file's import and
	// parent context (I)(5) / review C3). Package-scope const RHS is evaluated
	// with fn=nil so nested idents resolve at file+package scope of declFile.
	savedFn := pkg.fn
	savedLinked := pkg.linked
	savedParents := pkg.parents
	if res.scope == nil {
		pkg.fn = nil
	}
	if res.declFile != nil && res.declFile != pkg.linked {
		pkg.linked = res.declFile
		pkg.parents = buildParentMap(res.declFile)
	}
	ok := pkg.isNumericTerm(val, depth+1)
	pkg.fn = savedFn
	pkg.linked = savedLinked
	pkg.parents = savedParents
	return ok
}

func isOrderingOp(op token.Token) bool {
	return op == token.LSS || op == token.LEQ || op == token.GTR || op == token.GEQ
}

// ---------------------------------------------------------------------------
// Collection shape (M)
// ---------------------------------------------------------------------------

func isTestPrefix(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}

func (pkg *pkgContext) isCollectedShape(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil || fn.Recv != nil || fn.Type == nil {
		return false
	}
	name := fn.Name.Name
	var wantSel string
	switch {
	case isTestPrefix(name, "Test"):
		wantSel = "T"
	case isTestPrefix(name, "Benchmark"):
		wantSel = "B"
	case isTestPrefix(name, "Fuzz"):
		wantSel = "F"
	default:
		return false
	}
	params := fn.Type.Params
	if params == nil || len(params.List) != 1 {
		return false
	}
	field := params.List[0]
	if len(field.Names) != 1 {
		return false
	}
	return isStarTestingType(field.Type, pkg, wantSel)
}

// ---------------------------------------------------------------------------
// Candidate analysis + reason order (W)
// ---------------------------------------------------------------------------

type candidateKind int

const (
	candIf candidateKind = iota
	candTestify
)

type candidate struct {
	kind   candidateKind
	node   ast.Node // *ast.IfStmt or *ast.ExprStmt
	call   *ast.CallExpr
	ifStmt *ast.IfStmt
}

func (pkg *pkgContext) collectCandidates(fn *ast.FuncDecl) []candidate {
	var out []candidate
	var walk func(list []ast.Stmt)
	walk = func(list []ast.Stmt) {
		for _, stmt := range list {
			switch s := stmt.(type) {
			case *ast.IfStmt:
				out = append(out, candidate{kind: candIf, node: s, ifStmt: s})
				if s.Body != nil {
					walk(s.Body.List)
				}
				if s.Else != nil {
					if blk, ok := s.Else.(*ast.BlockStmt); ok {
						walk(blk.List)
					} else if elif, ok := s.Else.(*ast.IfStmt); ok {
						// else-if: the else is itself an IfStmt candidate
						walk([]ast.Stmt{elif})
					}
				}
			case *ast.ExprStmt:
				if call, ok := s.X.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if requireAssertSelectors[sel.Sel.Name] {
							out = append(out, candidate{kind: candTestify, node: s, call: call})
						}
					}
				}
			case *ast.BlockStmt:
				walk(s.List)
			case *ast.ForStmt:
				if s.Body != nil {
					walk(s.Body.List)
				}
			case *ast.RangeStmt:
				if s.Body != nil {
					walk(s.Body.List)
				}
			case *ast.SwitchStmt:
				if s.Body != nil {
					for _, c := range s.Body.List {
						if cc, ok := c.(*ast.CaseClause); ok {
							walk(cc.Body)
						}
					}
				}
			case *ast.TypeSwitchStmt:
				if s.Body != nil {
					for _, c := range s.Body.List {
						if cc, ok := c.(*ast.CaseClause); ok {
							walk(cc.Body)
						}
					}
				}
			case *ast.SelectStmt:
				if s.Body != nil {
					for _, c := range s.Body.List {
						if cc, ok := c.(*ast.CommClause); ok {
							walk(cc.Body)
						}
					}
				}
			case *ast.CaseClause:
				walk(s.Body)
			case *ast.CommClause:
				walk(s.Body)
			}
			// FuncLit bodies are not walked — non-candidates (stay no_candidate).
		}
	}
	if fn.Body != nil {
		walk(fn.Body.List)
	}
	return out
}

// isUnconditionalExit reports whether stmt is an unconditional block exit (R)(1).
func (pkg *pkgContext) isUnconditionalExit(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.BREAK || s.Tok == token.CONTINUE || s.Tok == token.GOTO
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !skipSelectors[sel.Sel.Name] {
			return false
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		return pkg.goAdmittedTestParam(recv)
	}
	return false
}

// candidateIsDead (R)(1): preceded by unconditional block exit at any level.
func (pkg *pkgContext) candidateIsDead(cand candidate, fn *ast.FuncDecl) bool {
	node := cand.node
	// Walk ancestor chain; at each level find the ancestor that is a direct
	// member of a statement list and check earlier siblings.
	cur := node
	for cur != nil && cur != fn {
		parent := pkg.parents[cur]
		if parent == nil {
			break
		}
		var list []ast.Stmt
		var member ast.Node = cur
		switch p := parent.(type) {
		case *ast.BlockStmt:
			list = p.List
		case *ast.CaseClause:
			list = p.Body
		case *ast.CommClause:
			list = p.Body
		case *ast.IfStmt:
			// Body is a BlockStmt — handled when parent is BlockStmt.
			// Else may be BlockStmt or IfStmt.
			cur = parent
			continue
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			cur = parent
			continue
		case *ast.FuncDecl:
			break
		default:
			cur = parent
			continue
		}
		// Find index of member in list.
		idx := -1
		for i, st := range list {
			if st == member {
				idx = i
				break
			}
			// member might be nested inside; compare by walking
			if containsNode(st, member) {
				idx = i
				break
			}
		}
		if idx > 0 {
			for _, earlier := range list[:idx] {
				if pkg.isUnconditionalExit(earlier) {
					return true
				}
			}
		}
		cur = parent
	}
	return false
}

func containsNode(root, target ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

// inDeadBranch (W)(3) row 1a / (AB): ancestor is Body of constantly-false
// If/For or Else of constantly-true If.
func (pkg *pkgContext) inDeadBranch(node ast.Node, fn *ast.FuncDecl) bool {
	cur := node
	for cur != nil && cur != fn {
		parent := pkg.parents[cur]
		if parent == nil {
			break
		}
		switch p := parent.(type) {
		case *ast.IfStmt:
			if p.Body != nil && (cur == p.Body || containsNode(p.Body, cur)) {
				// only if not coming from Else
				if p.Else == nil || (cur != p.Else && !containsNode(p.Else, cur)) {
					if isConstantFalse(p.Cond) {
						return true
					}
				}
			}
			if p.Else != nil && (cur == p.Else || containsNode(p.Else, cur)) {
				if isConstantTrue(p.Cond) {
					return true
				}
			}
		case *ast.ForStmt:
			if p.Body != nil && (cur == p.Body || containsNode(p.Body, cur)) {
				if p.Cond != nil && isConstantFalse(p.Cond) {
					return true
				}
			}
		case *ast.FuncLit:
			// Should not appear — FuncLit excluded from candidates.
			return false
		}
		cur = parent
	}
	return false
}

func (pkg *pkgContext) bodyHasFailStatus(body *ast.BlockStmt) (hasFailSel bool, admitted bool) {
	if body == nil {
		return false, false
	}
	for _, stmt := range body.List {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !failSelectors[sel.Sel.Name] {
			continue
		}
		hasFailSel = true
		recv, ok := sel.X.(*ast.Ident)
		if ok && pkg.goAdmittedTestParam(recv) {
			return true, true
		}
	}
	return hasFailSel, false
}

// bareIdentAtOperand: operand is bare *ast.Ident (after paren unwrap).
func bareIdent(e ast.Expr) *ast.Ident {
	e = unwrapParen(e)
	id, _ := e.(*ast.Ident)
	return id
}

// hasOutsideBinding: name has a package- or file-scope binding.
func (pkg *pkgContext) hasOutsideBinding(name string) bool {
	if len(pkg.goPackageBindings(name)) > 0 {
		return true
	}
	for _, imp := range pkg.linked.Imports {
		if importBoundName(imp) == name {
			return true
		}
	}
	return false
}

// operandReason (W)(4) three-way split when no numeric term / both wrong.
func (pkg *pkgContext) operandReason(operands []ast.Expr, bothNumeric bool) string {
	if bothNumeric {
		return "both_operands_numeric"
	}
	// Row 9: no numeric term path.
	if fileHasDotImport(pkg.linked) {
		return "dot_import"
	}
	for _, op := range operands {
		if id := bareIdent(op); id != nil {
			if pkg.hasOutsideBinding(id.Name) {
				return "unresolved_identifier"
			}
		}
	}
	return "no_numeric_term"
}

func (pkg *pkgContext) evaluateIfCandidate(c candidate) (ok bool, reason string) {
	s := c.ifStmt
	// 1 dead_candidate
	if pkg.candidateIsDead(c, pkg.fn) {
		return false, "dead_candidate"
	}
	// 1a dead branch
	if pkg.inDeadBranch(s, pkg.fn) {
		return false, "not_a_threshold_comparison"
	}
	// 3 Cond is ordering BinaryExpr
	cond := unwrapParen(s.Cond)
	bin, isBin := cond.(*ast.BinaryExpr)
	if !isBin || !isOrderingOp(bin.Op) {
		return false, "not_a_threshold_comparison"
	}
	// 5 / 5′ fail form
	hasSel, admitted := pkg.bodyHasFailStatus(s.Body)
	if !hasSel {
		return false, "no_fail_in_branch"
	}
	if !admitted {
		return false, "bad_testing_t"
	}
	// 8 / 9 operands
	xNum := pkg.isNumericTerm(bin.X, 0)
	yNum := pkg.isNumericTerm(bin.Y, 0)
	if xNum && yNum {
		return false, "both_operands_numeric"
	}
	if !xNum && !yNum {
		return false, pkg.operandReason([]ast.Expr{bin.X, bin.Y}, false)
	}
	// one numeric, one not → qualifies
	return true, ""
}

func (pkg *pkgContext) evaluateTestifyCandidate(c candidate) (ok bool, reason string) {
	call := c.call
	// 1 dead_candidate
	if pkg.candidateIsDead(c, pkg.fn) {
		return false, "dead_candidate"
	}
	// 1a dead branch
	if pkg.inDeadBranch(c.node, pkg.fn) {
		return false, "not_a_threshold_comparison"
	}
	// 3′ receiver resolves to testify
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false, "not_testify"
	}
	pkgID, ok := sel.X.(*ast.Ident)
	if !ok || !requireAssertSelectors[sel.Sel.Name] {
		return false, "not_testify"
	}
	if !pkg.admitsImport(pkgID, testifyPaths) {
		return false, "not_testify"
	}
	// 6 spread / arity (before TestingT when args empty)
	if len(call.Args) < 3 {
		return false, "spread_operand"
	}
	highestOperand := 2
	if inDeltaEpsilon[sel.Sel.Name] {
		highestOperand = 3
	}
	if call.Ellipsis != token.NoPos {
		spreadIdx := len(call.Args) - 1
		if spreadIdx <= highestOperand {
			return false, "spread_operand"
		}
	}
	// 4 TestingT
	tArg := call.Args[0]
	tID, ok := tArg.(*ast.Ident)
	if !ok || !pkg.goAdmittedTestParam(tID) {
		return false, "bad_testing_t"
	}
	// 7 tolerance for InDelta/InEpsilon
	if inDeltaEpsilon[sel.Sel.Name] {
		if len(call.Args) < 4 || !pkg.isNumericTerm(call.Args[3], 0) {
			return false, "bad_tolerance"
		}
	}
	// 8 / 9 operands at Args[1], Args[2]
	n1 := pkg.isNumericTerm(call.Args[1], 0)
	n2 := pkg.isNumericTerm(call.Args[2], 0)
	if n1 && n2 {
		return false, "both_operands_numeric"
	}
	if !n1 && !n2 {
		return false, pkg.operandReason([]ast.Expr{call.Args[1], call.Args[2]}, false)
	}
	return true, ""
}

// funcAssertsThreshold reports whether the named function at linkedPath holds
// at least one qualifying threshold check. Returns (true, "") on success or
// (false, reason) with a closed-vocabulary token on failure.
func funcAssertsThreshold(linkedPath, name string) (bool, string) {
	pkg, reason := loadPackage(linkedPath)
	if reason != "" {
		return false, reason
	}

	// Find Recv==nil declarations named name.
	var matches []*ast.FuncDecl
	for _, d := range pkg.linked.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != name {
			continue
		}
		if fn.Recv != nil {
			continue
		}
		matches = append(matches, fn)
	}
	if len(matches) == 0 {
		return false, "nonexistent_linked_test"
	}
	if len(matches) > 1 {
		return false, "ambiguous_test_name"
	}
	fn := matches[0]
	if !pkg.isCollectedShape(fn) {
		return false, "not_collected"
	}
	pkg.fn = fn

	// Rebuild parents with full linked file (already done).
	cands := pkg.collectCandidates(fn)
	if len(cands) == 0 {
		return false, "no_candidate"
	}
	// First candidate in source order that fails decides the reason when
	// none qualify; any that qualifies succeeds the link.
	var firstReason string
	for _, c := range cands {
		var ok bool
		var r string
		switch c.kind {
		case candIf:
			ok, r = pkg.evaluateIfCandidate(c)
		case candTestify:
			ok, r = pkg.evaluateTestifyCandidate(c)
		}
		if ok {
			return true, ""
		}
		if firstReason == "" {
			firstReason = r
		}
	}
	if firstReason == "" {
		firstReason = "no_candidate"
	}
	return false, firstReason
}

// ---------------------------------------------------------------------------
// Manifest walk + fixture harness
// ---------------------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	manifestPath := filepath.Join("..", "..", "benchmark", "thresholds.yaml")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("thresholds.yaml not found at %s (run from package dir): %v", manifestPath, err)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(manifestPath), "..", ".."))
}

func splitLink(link string) (path, name string, ok bool) {
	parts := strings.SplitN(link, "::", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	path = strings.TrimSpace(parts[0])
	name = strings.TrimSpace(parts[1])
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if path == "" || name == "" {
		return "", "", false
	}
	return path, name, true
}

func TestManifestGoTestsAssertTheirThresholds(t *testing.T) {
	root := repoRoot(t)
	manifestPath := filepath.Join(root, "tests", "benchmark", "thresholds.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read thresholds: %v", err)
	}
	var tf thresholdsFile
	if err := yaml.Unmarshal(raw, &tf); err != nil {
		t.Fatalf("yaml: %v", err)
	}

	var goLinks int
	for _, b := range tf.Benchmarks {
		if b.Status != "covered" {
			continue
		}
		for _, link := range b.Tests {
			pathPart, name, ok := splitLink(link)
			if !ok || !strings.HasSuffix(pathPart, ".go") {
				continue
			}
			goLinks++
			abs := filepath.Join(root, pathPart)
			okCheck, reason := funcAssertsThreshold(abs, name)
			if !okCheck {
				t.Errorf("%s: linked test %s does not qualify: %s", b.ID, link, reason)
			}
		}
	}
	if goLinks == 0 {
		t.Fatal("no .go links at status:covered — guard would pass vacuously")
	}
	if goLinks != 5 {
		t.Logf("note: expected 5 Go links, found %d", goLinks)
	}

	if len(goNegativeFixtures) != 34 {
		t.Fatalf("len(goNegativeFixtures) = %d, want 34", len(goNegativeFixtures))
	}
	if len(goPositiveFixtures) != 14 {
		t.Fatalf("len(goPositiveFixtures) = %d, want 14", len(goPositiveFixtures))
	}

	t.Run("rejects_known_bypasses", func(t *testing.T) {
		for _, fx := range goNegativeFixtures {
			fx := fx
			t.Run(fx.id, func(t *testing.T) {
				if !thresholdReasons[fx.reason] {
					t.Fatalf("expected reason %q not in closed vocabulary", fx.reason)
				}
				dir := writeFixturePkg(t, fx.files)
				linked := filepath.Join(dir, fx.linkedFile)
				ok, reason := funcAssertsThreshold(linked, fx.funcName)
				if ok {
					t.Fatalf("expected reject for %s, got ok=true", fx.id)
				}
				if reason != fx.reason {
					t.Fatalf("reason = %q, want %q", reason, fx.reason)
				}
			})
		}
	})

	t.Run("accepts_real_shapes", func(t *testing.T) {
		for _, fx := range goPositiveFixtures {
			fx := fx
			t.Run(fx.id, func(t *testing.T) {
				dir := writeFixturePkg(t, fx.files)
				linked := filepath.Join(dir, fx.linkedFile)
				ok, reason := funcAssertsThreshold(linked, fx.funcName)
				if !ok {
					t.Fatalf("expected accept for %s, got reason=%q", fx.id, reason)
				}
				if reason != "" {
					t.Fatalf("positive control returned reason %q", reason)
				}
			})
		}
	})
}

func writeFixturePkg(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
// Fixtures: 34 negative + 14 positive (design.md ~8004–8053)
// ---------------------------------------------------------------------------

type goFixture struct {
	id         string
	funcName   string
	linkedFile string
	files      map[string]string
	reason     string // empty for positives
}

const testFunc = "TestB99"

func singleFile(src string) map[string]string {
	return map[string]string{"fixture_test.go": src}
}

var goNegativeFixtures = []goFixture{
	// 1
	{
		id: "no_check_at_all", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_candidate",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	t.Logf("measured %s against %s", elapsed, budget)
}
`),
	},
	// 2
	{
		id: "comment_only_threshold_claim", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_candidate",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	// B3 dispatch p99 < 50ms
	elapsed := 10 * time.Millisecond
	_ = elapsed
	_ = budget
}
`),
	},
	// 3
	{
		id: "equality_instead_of_a_threshold", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "not_a_threshold_comparison",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed != budget {
		t.Errorf("not equal")
	}
}
`),
	},
	// 4
	{
		id: "check_only_inside_a_func_lit", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_candidate",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	_ = func() {
		if elapsed > budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 5
	{
		id: "dead_branch_short_circuit_cond", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "not_a_threshold_comparison",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if false && elapsed > b5Budget {
		t.Errorf("over")
	}
}
`),
	},
	// 6
	{
		id: "comparison_call_in_a_dead_branch", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "not_a_threshold_comparison",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if false {
		require.Less(t, elapsed, budget)
	}
}
`),
	},
	// 7
	{
		id: "runtime_derived_budget", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_numeric_term",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

func TestB99(t *testing.T) {
	start := time.Now()
	elapsed := 10 * time.Millisecond
	runtimeBudget := time.Since(start)
	if elapsed > runtimeBudget+1 {
		t.Errorf("over")
	}
}
`),
	},
	// 8 — package-level var (final table)
	{
		id: "var_budget_reassigned_at_runtime", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

var budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	t0 := time.Now()
	budget = time.Since(t0)
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 9
	{
		id: "both_operands_are_numeric_terms", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "both_operands_numeric",
		files: singleFile(`package fixture

import "testing"

func TestB99(t *testing.T) {
	if 1 > 2 {
		t.Errorf("impossible")
	}
}
`),
	},
	// 10
	{
		id: "fake_package_comparison_call", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "not_testify",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

type noopT struct{}

func (noopT) Less(t *testing.T, a, b interface{}, msgAndArgs ...interface{}) {}

var noop noopT

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	measured := 10 * time.Millisecond
	noop.Less(t, measured, budget)
}
`),
	},
	// 11
	{
		id: "message_argument_is_the_only_numeric_term", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_numeric_term",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestB99(t *testing.T) {
	start := time.Now()
	measured := 10 * time.Millisecond
	runtimeBudget := time.Since(start)
	require.Less(t, measured, runtimeBudget, 100)
}
`),
	},
	// 12
	{
		id: "local_variable_shadows_a_package_const", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	t0 := time.Now()
	budget := time.Since(t0)
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 13
	{
		id: "in_delta_with_a_runtime_tolerance", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_tolerance",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestB99(t *testing.T) {
	t0 := time.Now()
	measured := 100.0
	runtimeDelta := float64(time.Since(t0))
	require.InDelta(t, 100.0, measured, runtimeDelta)
}
`),
	},
	// 14
	{
		id: "duration_unit_read_from_a_shadowed_time_identifier", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_numeric_term",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

type fakeClock struct{}

func TestB99(t *testing.T) {
	time := fakeClock{}
	_ = time
	const budget = 50 * time.Millisecond
	elapsed := 10
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 15
	{
		id: "fail_call_on_a_lookalike_receiver", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_testing_t",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

type fakeLog struct{}

func (fakeLog) Errorf(string, ...interface{}) {}

var logger fakeLog

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		logger.Errorf("over")
	}
}
`),
	},
	// 16
	{
		id: "duration_multiplier_resolved_through_a_const", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const factor = 50
const budget = factor * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 17
	{
		id: "spread_argument_in_an_operand_position", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "spread_operand",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	rest := []interface{}{budget}
	require.Less(t, elapsed, rest...)
}
`),
	},
	// 18
	{
		id: "nested_block_const_does_not_vouch_for_a_package_var", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

var budget = time.Since(time.Now())

func TestB99(t *testing.T) {
	{
		const budget = 50 * time.Millisecond
		_ = budget
	}
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 19
	{
		id: "switch_case_const_does_not_vouch_outside_its_clause", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

var budget = time.Since(time.Now())

func TestB99(t *testing.T) {
	switch {
	case true:
		const budget = 50 * time.Millisecond
		_ = budget
	}
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 20
	{
		id: "sibling_file_rebinds_the_budget_as_a_var", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: map[string]string{
			"fixture_test.go": `package fixture

import (
	"testing"
	"time"
)

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`,
			"sibling.go": `package fixture

import "time"

var budget = time.Since(time.Now())
`,
		},
	},
	// 21
	{
		// Review C3: direct-literal threshold + measured local must still be
		// rejected under a dot-import (I)(4)(0) poisons every resolution,
		// including admitsImport for time.Millisecond).
		id: "dot_import_poisons_the_file", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "dot_import",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	. "fmt"
)

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > 50*time.Millisecond {
		t.Errorf("over")
	}
}
`),
	},
	// 22
	{
		id: "test_param_shadowed_before_the_fail_call", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_testing_t",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

type noopT struct{}

func (noopT) Errorf(string, ...interface{}) {}

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	t := noopT{}
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 23
	{
		id: "panic_is_not_an_admitted_fail_form", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "no_fail_in_branch",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		panic("over budget")
	}
}
`),
	},
	// 24
	{
		id: "testify_reports_to_a_local_no_op_testing_t", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_testing_t",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type noopT struct{}

func (noopT) Errorf(string, ...interface{}) {}
func (noopT) FailNow()                      {}

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	noop := noopT{}
	elapsed := 10 * time.Millisecond
	require.Less(noop, elapsed, b5Budget)
}
`),
	},
	// 25
	{
		id: "testify_first_argument_is_not_a_bare_identifier", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_testing_t",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type noopT struct{}

func (noopT) Errorf(string, ...interface{}) {}
func (noopT) FailNow()                      {}

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	require.Less(&noopT{}, elapsed, b5Budget)
}
`),
	},
	// 26
	{
		id: "linked_file_excluded_by_a_build_constraint", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "build_context",
		files: singleFile(`//go:build ignore

package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 27
	{
		id: "linked_declaration_is_a_method", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "nonexistent_linked_test",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

type suite struct{}

func (s *suite) TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 28
	{
		id: "linked_function_has_the_wrong_signature", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "not_collected",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T, extra int) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 29
	{
		id: "range_variable_shadows_a_package_const", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	t0 := time.Now()
	budgets := []time.Duration{time.Since(t0)}
	elapsed := 10 * time.Millisecond
	for _, budget := range budgets {
		if elapsed > budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 30
	{
		id: "type_switch_guard_shadows_a_package_const", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	var v interface{} = time.Since(time.Now())
	elapsed := 10 * time.Millisecond
	switch budget := v.(type) {
	default:
		_ = budget
		if elapsed > budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 31
	{
		id: "select_comm_clause_binding_shadows_a_package_const", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "unresolved_identifier",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	ch := make(chan time.Duration, 1)
	ch <- time.Since(time.Now())
	elapsed := 10 * time.Millisecond
	select {
	case budget := <-ch:
		if elapsed > budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 32
	{
		id: "test_param_reassigned_by_a_range_clause", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "bad_testing_t",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	fakes := []*testing.T{t}
	for _, t = range fakes {
	}
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 33
	{
		id: "check_after_an_unconditional_return", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "dead_candidate",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	return
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 34
	{
		id: "check_after_an_unconditional_skip", funcName: testFunc, linkedFile: "fixture_test.go",
		reason: "dead_candidate",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	t.Skip("later")
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
}

var goPositiveFixtures = []goFixture{
	// 1
	{
		id: "require_less_call", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	require.Less(t, elapsed, b5Budget)
}
`),
	},
	// 2
	{
		id: "paren_wrapped_cond", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	p99 := 10 * time.Millisecond
	if (p99 > budget) {
		t.Errorf("over")
	}
}
`),
	},
	// 3
	{
		id: "require_less_call_with_a_message_argument", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	require.Less(t, elapsed, b5Budget, "B5 over budget")
}
`),
	},
	// 4
	{
		id: "assert_package_comparison_call", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestB99(t *testing.T) {
	rate := 1500.0
	assert.Greater(t, rate, 1000.0)
}
`),
	},
	// 5
	{
		id: "in_delta_with_fixed_operands_and_tolerance", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestB99(t *testing.T) {
	measured := 100.2
	require.InDelta(t, 100.0, measured, 0.5)
}
`),
	},
	// 6
	{
		id: "function_local_const_budget", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

func TestB99(t *testing.T) {
	const budget = 100 * time.Millisecond
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 7
	{
		id: "require_less_call_with_spread_message_args", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	msgs := []interface{}{"over"}
	require.Less(t, elapsed, b5Budget, msgs...)
}
`),
	},
	// 8
	{
		// (I)(3)/(5) / review C3: package const lives in a sibling; its RHS
		// must be evaluated with the *sibling's* imports (time), not only the
		// linked file's. Linked still imports time for the measured elapsed.
		id: "package_scope_const_in_a_sibling_file", funcName: testFunc, linkedFile: "fixture_test.go",
		files: map[string]string{
			"fixture_test.go": `package fixture

import (
	"testing"
	"time"
)

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`,
			"budget.go": `package fixture

import "time"

const budget = 100 * time.Millisecond
`,
		},
	},
	// 9
	{
		id: "const_in_an_enclosing_block_of_the_use_site", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	warm := true
	if warm {
		const budget = 100 * time.Millisecond
		if elapsed > budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 10
	{
		id: "linked_file_with_a_satisfied_build_constraint", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`//go:build !race

package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 11
	{
		id: "check_after_a_conditional_skip", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func TestB99(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		t.Errorf("over")
	}
}
`),
	},
	// 12
	{
		id: "range_loop_body_uses_an_outer_const", funcName: testFunc, linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const b5Budget = 100 * time.Millisecond

func TestB99(t *testing.T) {
	payloads := []int{1, 2}
	elapsed := 10 * time.Millisecond
	for _, payload := range payloads {
		_ = payload
		if elapsed > b5Budget {
			t.Errorf("over")
		}
	}
}
`),
	},
	// 13
	{
		id: "benchmark_style_linked_function", funcName: "BenchmarkB99", linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func BenchmarkB99(b *testing.B) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		b.Errorf("over")
	}
}
`),
	},
	// 14
	{
		id: "fuzz_style_linked_function", funcName: "FuzzB99", linkedFile: "fixture_test.go",
		files: singleFile(`package fixture

import (
	"testing"
	"time"
)

const budget = 50 * time.Millisecond

func FuzzB99(f *testing.F) {
	elapsed := 10 * time.Millisecond
	if elapsed > budget {
		f.Errorf("over")
	}
}
`),
	},
}
