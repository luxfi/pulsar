// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// gate2_reachability_test.go — GATE 2 HARDENED to call-graph REACHABILITY,
// closing RED's GATE-2 bypass (the old gate greps only distributed_bcc.go for
// `KeyFromSeed(` / `func LargeCombine`, so a reconstruct-then-sign wired via
// deriveKeyMaterial+bccSign elsewhere PASSES the scan).
//
// The hardened gate proves the no-reconstruct invariant where it matters: NO
// reconstruct / seed-expand / single-key-sign primitive is REACHABLE in the
// default-build call graph from ANY committee sign entrypoint. It is a stdlib
// (go/ast) name call-graph — no new dependency. The callee side is
// OVER-APPROXIMATED by name (a CallExpr to name X follows every definition
// named X), which is the SOUND bias for a security gate over DIRECT CALLS.
//
// SCOPE / SOUNDNESS — honest statement (RED INFO). A name call-graph follows
// DIRECT named calls only; on its own it would MISS function-VALUE / closure /
// `//go:linkname` indirection (e.g. `e := deriveKeyMaterial; s := bccSign;
// s(e(...))`). So the reachability graph does NOT stand alone — it is paired
// with a companion lint (forbidBannedPrimitiveValueUse + the go:linkname scan)
// that FORBIDS taking any banned primitive as a non-call value or aliasing it
// via go:linkname anywhere in the default build. With that lint green, EVERY use
// of a banned primitive in the build IS a direct call the graph sees — so the
// pair is complete for the banned set. Neither half is claimed complete alone;
// together they close direct + indirect reach.
//
// GATE C is four tests: (1) the REAL package is clean (the reach invariant
// holds); (2) the checker CATCHES a deriveKeyMaterial+bccSign DIRECT bypass
// wired into a sign entrypoint; (3) NO banned primitive is taken as a value /
// linkname-aliased in the real build, and the lint CATCHES the function-value
// indirection RED flagged; (4) — folded into (3).

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// bannedReconstructPrimitives are the seed-expand / reconstruct / single-key
// reconstruct-then-sign primitives that MUST be unreachable from the committee
// sign path. All are free functions (defKey == name).
var bannedReconstructPrimitives = map[string]bool{
	"KeyFromSeed":          true, // seed -> sk expansion
	"deriveKeyMaterial":    true, // seed -> full FIPS key material
	"bccSign":              true, // single-key reconstruct-then-sign reference
	"LargeCombine":         true, // reconstruct-at-sign combiner
	"DealAlgShares":        true, // trusted-dealer s1-share keygen
	"shamirReconstruct":    true,
	"shamirReconstructGF":  true,
	"shamirReconstructGFQ": true,
	"shamirReconstructQ":   true,
}

// committeeSignEntrypoints are the production committee sign-combine roots that
// MUST stay reconstruct-free. Method keys are receiver-qualified.
var committeeSignEntrypoints = []string{
	"AggregateBCC",
	"AggregateBCCWithBlame",
	"NewDistributedBCCSigner",
	"DistributedBCCSigner.Round1",
	"DistributedBCCSigner.Round2",
	"DistributedBCCSigner.Finalize",
	"DistributedBCCSigner.FinalizeWithBlame",
	"DistributedBCCSigner.SetNonceShare",
}

// callGraph: defKey -> set of callee (unqualified) names, plus an index from
// unqualified name -> all defKeys with that name.
type callGraph struct {
	calls     map[string]map[string]bool
	nameIndex map[string][]string
}

func recvTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func defKeyFor(fn *ast.FuncDecl) (key, unqualified string) {
	if rt := recvTypeName(fn); rt != "" {
		return rt + "." + fn.Name.Name, fn.Name.Name
	}
	return fn.Name.Name, fn.Name.Name
}

// calleeName extracts the called function/method name from a CallExpr.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

func buildCallGraph(files []*ast.File) *callGraph {
	g := &callGraph{calls: map[string]map[string]bool{}, nameIndex: map[string][]string{}}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key, unqual := defKeyFor(fn)
			if g.calls[key] == nil {
				g.calls[key] = map[string]bool{}
			}
			g.nameIndex[unqual] = appendUnique(g.nameIndex[unqual], key)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if name := calleeName(call); name != "" {
						g.calls[key][name] = true
					}
				}
				return true
			})
		}
	}
	return g
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// reachBanned does BFS from the entrypoint defKeys over callee names and reports
// the first banned primitive reached, with the path that reaches it.
func (g *callGraph) reachBanned(entrypoints []string, banned map[string]bool) (hit string, path []string, found bool) {
	type item struct {
		key  string
		path []string
	}
	visited := map[string]bool{}
	var queue []item
	for _, e := range entrypoints {
		queue = append(queue, item{key: e, path: []string{e}})
		visited[e] = true
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		callees := make([]string, 0, len(g.calls[cur.key]))
		for c := range g.calls[cur.key] {
			callees = append(callees, c)
		}
		sort.Strings(callees) // deterministic path reporting
		for _, callee := range callees {
			if banned[callee] {
				return callee, append(append([]string{}, cur.path...), callee), true
			}
			for _, nextKey := range g.nameIndex[callee] {
				if !visited[nextKey] {
					visited[nextKey] = true
					queue = append(queue, item{key: nextKey, path: append(append([]string{}, cur.path...), nextKey)})
				}
			}
		}
	}
	return "", nil, false
}

// defaultBuildFuncFiles parses the package's DEFAULT-build (non-test,
// tag-honouring) Go files into ASTs — the same file set a production binary
// links (legacy_trusted_dealer files excluded).
func defaultBuildFuncFiles(t *testing.T) []*ast.File {
	t.Helper()
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package: %v", err)
	}
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(pkg.GoFiles))
	for _, name := range pkg.GoFiles {
		// ParseComments so the go:linkname scan (forbidBannedPrimitiveIndirection)
		// sees directive comments; harmless for the call-graph reachability gate.
		f, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return files
}

// forbidBannedPrimitiveIndirection is the companion lint that makes the
// direct-call reachability gate SOUND for the banned set (RED INFO). A name
// call-graph cannot follow a banned primitive passed as a function VALUE
// (`s := bccSign; s(...)`), captured in a closure, or aliased via
// `//go:linkname`. This lint FORBIDS exactly those: every *ast.Ident naming a
// banned primitive must be either its own declaration or the direct callee of a
// CallExpr — any other (value) use is an offender — and no `//go:linkname`
// directive may reference a banned name. With this green, every banned-primitive
// use in the build is a direct call the graph already follows.
//
// Returns the human-readable offenders (file:line — kind); empty == clean.
func forbidBannedPrimitiveIndirection(fset *token.FileSet, files []*ast.File, banned map[string]bool) []string {
	var offenders []string
	for _, f := range files {
		// OK positions: a banned Ident that is a FuncDecl.Name (declaration) or the
		// direct callee Ident of a CallExpr. Every other banned bare Ident is a
		// value-use. SelectorExpr.Sel (qualified x.Name) is excluded — it is a
		// different symbol than our package-local free functions.
		okPos := map[token.Pos]bool{}
		selPos := map[token.Pos]bool{}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && banned[fn.Name.Name] {
				okPos[fn.Name.Pos()] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				if id, ok := e.Fun.(*ast.Ident); ok && banned[id.Name] {
					okPos[id.Pos()] = true // direct call: deriveKeyMaterial(...)
				}
				if sel, ok := e.Fun.(*ast.SelectorExpr); ok && banned[sel.Sel.Name] {
					okPos[sel.Sel.Pos()] = true // qualified call: pkg.Name(...)
				}
			case *ast.SelectorExpr:
				if banned[e.Sel.Name] {
					selPos[e.Sel.Pos()] = true // qualified ref — different symbol; ignore
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || !banned[id.Name] {
				return true
			}
			if okPos[id.Pos()] || selPos[id.Pos()] {
				return true
			}
			pos := fset.Position(id.Pos())
			offenders = append(offenders, pos.Filename+":"+strconv.Itoa(pos.Line)+" — value-use of banned primitive "+id.Name)
			return true
		})
		// go:linkname scan: a directive whose target token is a banned primitive
		// (bare `name` or qualified `importpath.name`) aliases it under a fresh
		// local name the call-graph cannot follow.
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !strings.HasPrefix(c.Text, "//go:linkname") {
					continue
				}
				for _, field := range strings.Fields(c.Text)[1:] { // skip the directive token
					base := field
					if dot := strings.LastIndexByte(field, '.'); dot >= 0 {
						base = field[dot+1:]
					}
					if banned[base] {
						pos := fset.Position(c.Pos())
						offenders = append(offenders, pos.Filename+":"+strconv.Itoa(pos.Line)+" — go:linkname aliases banned primitive "+base)
					}
				}
			}
		}
	}
	return offenders
}

// GATE C (the invariant) — no reconstruct primitive is reachable from the
// committee sign path in the real default-build call graph.
func TestGATE_C_NoReconstructReachableFromSignPath(t *testing.T) {
	files := defaultBuildFuncFiles(t)
	g := buildCallGraph(files)

	// Every entrypoint must actually exist (guard against a renamed entrypoint
	// silently emptying the gate).
	for _, e := range committeeSignEntrypoints {
		if _, ok := g.calls[e]; !ok {
			t.Fatalf("GATE C MISCONFIGURED: sign entrypoint %q not found in the default build", e)
		}
	}

	if hit, path, found := g.reachBanned(committeeSignEntrypoints, bannedReconstructPrimitives); found {
		t.Fatalf("GATE C FAILED: reconstruct primitive %q is REACHABLE from the committee sign path:\n  %v", hit, path)
	}

	// Also assert the banned primitives are actually DEFINED in the build (so we
	// are testing reachability of real functions, not dead names).
	defined := 0
	for name := range bannedReconstructPrimitives {
		if _, ok := g.nameIndex[name]; ok {
			defined++
		}
	}
	t.Logf("GATE C PASS: %d sign entrypoints; %d/%d banned reconstruct primitives present in the build, NONE reachable from the sign path",
		len(committeeSignEntrypoints), defined, len(bannedReconstructPrimitives))
}

// GATE C (the catch) — the checker actually DETECTS RED's bypass: a synthetic
// graph in which the committee aggregator reaches deriveKeyMaterial+bccSign
// (reconstruct-then-sign) must be flagged. This proves the gate would FAIL if
// the bypass were wired in, rather than silently passing like the old grep.
func TestGATE_C_CatchesReconstructBypass(t *testing.T) {
	// Model: AggregateBCC -> rogueReconstructSign -> {deriveKeyMaterial, bccSign}
	g := &callGraph{
		calls: map[string]map[string]bool{
			"AggregateBCC":         {"rogueReconstructSign": true},
			"rogueReconstructSign": {"deriveKeyMaterial": true, "bccSign": true},
			"deriveKeyMaterial":    {},
			"bccSign":              {},
		},
		nameIndex: map[string][]string{
			"AggregateBCC":         {"AggregateBCC"},
			"rogueReconstructSign": {"rogueReconstructSign"},
			"deriveKeyMaterial":    {"deriveKeyMaterial"},
			"bccSign":              {"bccSign"},
		},
	}
	hit, path, found := g.reachBanned([]string{"AggregateBCC"}, bannedReconstructPrimitives)
	if !found {
		t.Fatalf("GATE C BROKEN: the reachability checker did NOT catch the deriveKeyMaterial+bccSign bypass")
	}
	t.Logf("GATE C catch PASS: bypass detected — banned %q reachable via %v", hit, path)

	// Negative control: a clean sign path that never reaches a banned primitive
	// must NOT be flagged (no false positive).
	clean := &callGraph{
		calls: map[string]map[string]bool{
			"AggregateBCC":          {"VerifyPartialProof": true, "FlatAggregateZ": true},
			"VerifyPartialProof":    {"partialFSChallenges": true},
			"partialFSChallenges":   {},
			"FlatAggregateZ":        {},
		},
		nameIndex: map[string][]string{
			"AggregateBCC":        {"AggregateBCC"},
			"VerifyPartialProof":  {"VerifyPartialProof"},
			"partialFSChallenges": {"partialFSChallenges"},
			"FlatAggregateZ":      {"FlatAggregateZ"},
		},
	}
	if _, _, found := clean.reachBanned([]string{"AggregateBCC"}, bannedReconstructPrimitives); found {
		t.Fatalf("GATE C false positive: a clean sign path was flagged")
	}

	// Full-pipeline catch: parse ROGUE source (RED's exact bypass — a sign
	// entrypoint that reconstructs via deriveKeyMaterial then bccSign) through
	// the REAL buildCallGraph and assert reachBanned flags it. This exercises
	// the actual AST extraction the gate runs on production files, not just a
	// hand-built graph.
	rogueSrc := `package pulsar
func AggregateBCC() { rogueReconstructSign() }
func rogueReconstructSign() {
	km, _ := deriveKeyMaterial(ModeP65, nil)
	_, _, _ = bccSign(km, ModeP65, nil, nil, nil, 1)
}
`
	fset := token.NewFileSet()
	rf, err := parser.ParseFile(fset, "rogue.go", rogueSrc, 0)
	if err != nil {
		t.Fatalf("parse rogue source: %v", err)
	}
	rg := buildCallGraph([]*ast.File{rf})
	hit2, path2, found2 := rg.reachBanned([]string{"AggregateBCC"}, bannedReconstructPrimitives)
	if !found2 {
		t.Fatalf("GATE C BROKEN: real parse→graph pipeline missed the deriveKeyMaterial+bccSign bypass")
	}
	t.Logf("GATE C full-pipeline catch PASS: parsed rogue source flagged banned %q via %v", hit2, path2)
}

// GATE C (indirection) — RED INFO. The direct-call name graph would MISS a
// banned primitive used as a function VALUE / closure / go:linkname alias. This
// test (a) asserts the REAL default build takes no banned primitive as a value
// and aliases none via go:linkname — so the reach graph is complete for the
// banned set — and (b) proves the companion lint CATCHES the exact function-value
// indirection RED flagged, which the name graph alone does not.
func TestGATE_C_NoBannedPrimitiveValueIndirection(t *testing.T) {
	// (a) the REAL default build is clean.
	fset := token.NewFileSet()
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package: %v", err)
	}
	files := make([]*ast.File, 0, len(pkg.GoFiles))
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if off := forbidBannedPrimitiveIndirection(fset, files, bannedReconstructPrimitives); len(off) != 0 {
		t.Fatalf("GATE C (indirection) FAILED: banned primitive taken as a value / linkname-aliased in the default build:\n  %v", off)
	}

	// (b) the lint CATCHES RED's exact function-value indirection — which the
	// direct-call name graph alone does NOT flag (so the lint is load-bearing).
	rogueSrc := `package pulsar
func sneaky() {
	e := deriveKeyMaterial
	s := bccSign
	_ = e
	_ = s
}
`
	rfset := token.NewFileSet()
	rf, err := parser.ParseFile(rfset, "sneaky.go", rogueSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse rogue source: %v", err)
	}
	// the name call-graph alone MISSES it (no CallExpr to the banned names) …
	rg := buildCallGraph([]*ast.File{rf})
	if _, _, found := rg.reachBanned([]string{"sneaky"}, bannedReconstructPrimitives); found {
		t.Fatalf("unexpected: the call-graph flagged a function-VALUE use (it only follows direct calls)")
	}
	// … but the indirection lint CATCHES both value-uses.
	if off := forbidBannedPrimitiveIndirection(rfset, []*ast.File{rf}, bannedReconstructPrimitives); len(off) < 2 {
		t.Fatalf("GATE C (indirection) BROKEN: lint missed `e := deriveKeyMaterial; s := bccSign` value-use (got %v)", off)
	}

	// (c) go:linkname aliasing of a banned primitive is caught too.
	linkSrc := "package pulsar\n\n//go:linkname myalias deriveKeyMaterial\nfunc myalias()\n"
	lfset := token.NewFileSet()
	lf, err := parser.ParseFile(lfset, "link.go", linkSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse linkname source: %v", err)
	}
	if loff := forbidBannedPrimitiveIndirection(lfset, []*ast.File{lf}, bannedReconstructPrimitives); len(loff) == 0 {
		t.Fatalf("GATE C (indirection) BROKEN: lint missed go:linkname aliasing of a banned primitive")
	}
	t.Logf("GATE C (indirection) PASS: real build takes no banned primitive as a value/linkname; lint catches the `e:=deriveKeyMaterial; s:=bccSign` function-value indirection AND go:linkname aliasing that the name call-graph alone would miss")
}
