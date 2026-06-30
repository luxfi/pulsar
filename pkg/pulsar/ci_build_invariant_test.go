// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// ci_build_invariant_test.go — the structural proof that the reconstruct-at-sign
// + trusted-dealer rip is COMPLETE and PERMANENT.
//
// The legacy_trusted_dealer quarantine tag, the reconstruct-at-sign combiner
// LargeCombine (was large_threshold.go), and the trusted-dealer keygen
// DealAlgShares (was bootstrap_dealer_test.go) have all been DELETED. There is
// no longer any reconstruct path to quarantine, so the old "the production build
// excludes the tag" invariant is obsolete. This file replaces it with the
// stronger, permanent guard: scan EVERY .go file in the package — production,
// test, and any build-constrained — and FAIL if any ripped declaration or the
// quarantine tag ever reappears.
//
// This is the single home (one and only one way) for the "these do not exist"
// guard. The complementary "no reconstruct PRIMITIVE is reachable from the sign
// path" invariant lives in GATE-2 (no_reconstruct_committee_test.go) and GATE-C
// (gate2_reachability_test.go). As the sole holder of the forbidden strings (its
// own scan targets), this file is the documented exception to the package-wide
// no-`DealAlgShares`/`func LargeCombine`/`legacy_trusted_dealer` rule.
//
// It also keeps TestCI_NoAssemblyOrCgoFiles, which seals GATE-C's blind spot by
// asserting the package is pure Go — no .s/.c/cgo unit can hide a reconstruct
// primitive from the AST gates.

import (
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const legacyTrustedDealerTag = "legacy_trusted_dealer"

// rippedDeclarations are the exact source signatures the rip removed. The
// reconstruct-at-sign combiner (LargeCombine, the H-1 footgun that materialised
// the master key in the aggregator) and the trusted-dealer s1-share keygen
// (DealAlgShares) must never reappear in any .go file in the package.
var rippedDeclarations = []string{
	"func LargeCombine(",  // reconstruct-at-sign combiner (was large_threshold.go)
	"func DealAlgShares(", // trusted-dealer s1-share keygen (was bootstrap_dealer_test.go)
}

// goBuildConstraint returns the `//go:build ...` constraint line of a Go source
// (or ""). Build constraints must precede the package clause.
func goBuildConstraint(src string) string {
	for _, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "//go:build ") {
			return l
		}
		if strings.HasPrefix(l, "package ") {
			break
		}
	}
	return ""
}

// TestCI_ReconstructAndDealerRipIsComplete scans every .go file in the package
// and fails if a ripped declaration or the legacy_trusted_dealer quarantine tag
// reappears. Stronger than the old "production build excludes the tag" check: it
// forbids the symbols and the tag EVERYWHERE — production, test, and any
// build-constrained file — so the no-reconstruct property is now structural
// (there is literally no reconstruct path left to quarantine).
func TestCI_ReconstructAndDealerRipIsComplete(t *testing.T) {
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package: %v", err)
	}
	entries, err := os.ReadDir(pkg.Dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	const self = "ci_build_invariant_test.go"
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// This guard file necessarily contains the forbidden strings (they ARE
		// its scan targets) — it is the ONE legitimate holder of them.
		if e.Name() == self {
			scanned++
			continue
		}
		src, err := os.ReadFile(filepath.Join(pkg.Dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		text := string(src)
		for _, decl := range rippedDeclarations {
			if strings.Contains(text, decl) {
				t.Errorf("RIP INCOMPLETE: %s declares %q — the reconstruct-at-sign / trusted-dealer path was removed and must not return", e.Name(), decl)
			}
		}
		if line := goBuildConstraint(text); strings.Contains(line, legacyTrustedDealerTag) {
			t.Errorf("RIP INCOMPLETE: %s carries a %q build constraint — the quarantine tag was removed (there is no legacy to quarantine)", e.Name(), legacyTrustedDealerTag)
		}
		scanned++
	}

	// Belt-and-suspenders: the real production paths the rip is supposed to LEAVE
	// IN must still be present (a rip that also deleted the live signer/keygen
	// would pass a pure forbid-scan). The dealerless keygen and the
	// no-reconstruct combiner are load-bearing.
	for _, want := range []struct{ file, decl string }{
		{"mithril_rss.go", "func MithrilRSSKeygen("},  // dealerless keygen (production)
		{"distributed_bcc.go", "func AggregateBCC("},  // no-reconstruct sign-combine
	} {
		src, err := os.ReadFile(filepath.Join(pkg.Dir, want.file))
		if err != nil || !strings.Contains(string(src), want.decl) {
			t.Fatalf("RIP OVERREACHED: production path %q in %s is missing — the dealerless/no-reconstruct surface must remain", want.decl, want.file)
		}
	}

	t.Logf("CI PASS: rip complete — %d .go files scanned, none declares LargeCombine/DealAlgShares, none carries the %q tag; dealerless MithrilRSSKeygen + no-reconstruct AggregateBCC present", scanned, legacyTrustedDealerTag)
}

// TestCI_NoAssemblyOrCgoFiles seals GATE-C's blind spot (RED LOW/INFO). GATE-C's
// reachability + indirection lint (gate2_reachability_test.go) is complete for Go
// ASTs (+ go:linkname), but it CANNOT model hand-written assembly (.s) or C
// (.c / cgo): a banned reconstruct primitive implemented in asm/C, or a cgo
// escape hatch, would be INVISIBLE to the AST gates. The no-reconstruct soundness
// claim therefore rests on the package being PURE GO. This asserts exactly that —
// no non-Go compiled source units and no cgo — so the GATE-C pair stays complete
// for the WHOLE linked package, not just its .go files.
func TestCI_NoAssemblyOrCgoFiles(t *testing.T) {
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package: %v", err)
	}

	// (a) go/build's own classification of the DEFAULT (production) build: every
	//     non-Go compiled-source bucket MUST be empty, and there must be no cgo.
	classified := []struct {
		name  string
		files []string
	}{
		{".s assembly", pkg.SFiles},
		{".c C", pkg.CFiles},
		{".h C header", pkg.HFiles},
		{".cc/.cpp C++", pkg.CXXFiles},
		{".m Objective-C", pkg.MFiles},
		{".f Fortran", pkg.FFiles},
		{`cgo (import "C")`, pkg.CgoFiles},
		{"SWIG .swig", pkg.SwigFiles},
		{"SWIG .swigcxx", pkg.SwigCXXFiles},
		{".syso prebuilt object", pkg.SysoFiles},
	}
	for _, b := range classified {
		if len(b.files) != 0 {
			t.Fatalf("GATE-C blind spot OPENED: default build contains %s file(s) %v — the AST reachability/indirection gates cannot model these; the no-reconstruct soundness claim no longer holds", b.name, b.files)
		}
	}

	// (b) RAW directory scan — catches non-Go source files that build.Default
	//     EXCLUDES by a build constraint (e.g. a //go:build-guarded .s that still
	//     ships in the tree and could be linked under some tag). Any compiled
	//     source-unit extension is a blind spot regardless of constraints.
	bannedExt := map[string]bool{
		".s": true, ".c": true, ".h": true,
		".cc": true, ".cpp": true, ".cxx": true, ".hpp": true, ".hh": true,
		".m": true, ".mm": true, ".f": true, ".f90": true,
		".syso": true, ".swig": true, ".swigcxx": true,
	}
	entries, err := os.ReadDir(pkg.Dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var extOffenders []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if bannedExt[strings.ToLower(filepath.Ext(e.Name()))] {
			extOffenders = append(extOffenders, e.Name())
		}
	}
	if len(extOffenders) != 0 {
		t.Fatalf("GATE-C blind spot OPENED: package directory contains non-Go source file(s) %v (even if build-constrained out today) — pure-Go is required for the AST gates' soundness", extOffenders)
	}

	// (c) Scan EVERY .go file in the dir (incl. build-constrained and _test files)
	//     for a cgo import. A constraint-hidden `import "C"` escapes both the build
	//     classification (a) and the extension scan (b), yet still exposes C to a
	//     tagged build. Robust AST parse (ImportsOnly), not a text grep.
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(pkg.Dir, e.Name()), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"C"` {
				t.Fatalf("GATE-C blind spot OPENED: %s imports \"C\" (cgo) — C code is invisible to the AST gates", e.Name())
			}
		}
	}
	t.Logf("GATE-C blind spot SEALED: %d default-build .go files, ZERO .s/.c/.h/.cc/.cpp/.m/.f/.syso/SWIG/cgo units — the reachability + indirection gates are complete for the whole linked package", len(pkg.GoFiles))
}
