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
// named X), which is the SOUND bias for a security gate: it can over-report a
// reach, never miss one.
//
// GATE C is two tests: (1) the REAL package is clean (the invariant holds);
// (2) the checker actually CATCHES a deriveKeyMaterial+bccSign bypass wired into
// a sign entrypoint (a synthetic graph modeling RED's PoC).

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
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
		f, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return files
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
