// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// ci_build_invariant_test.go — item 4: the PRODUCTION build must never ship the
// reconstruct-at-sign quarantine. RED LOW: the structural GATE-2 inspects
// build.Default (no tags), so CI must ALSO assert the production binary is never
// compiled with `-tags legacy_trusted_dealer` (which would re-link LargeCombine,
// the H-1 reconstruct footgun) and that the trusted-dealer keygen is test-only.

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

func defaultBuildGoFiles(t *testing.T) (dir string, files map[string]bool) {
	t.Helper()
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package: %v", err)
	}
	files = make(map[string]bool, len(pkg.GoFiles))
	for _, f := range pkg.GoFiles {
		files[f] = true
	}
	return pkg.Dir, files
}

func taggedBuildGoFiles(t *testing.T, tag string) map[string]bool {
	t.Helper()
	ctx := build.Default
	ctx.BuildTags = append(append([]string{}, ctx.BuildTags...), tag)
	pkg, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate %s-tagged package: %v", tag, err)
	}
	out := make(map[string]bool, len(pkg.GoFiles))
	for _, f := range pkg.GoFiles {
		out[f] = true
	}
	return out
}

// goBuildLine returns the `//go:build ...` constraint line of a file (or "").
func goBuildLine(t *testing.T, path string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "//go:build ") {
			return l
		}
		// build constraints must precede the package clause.
		if strings.HasPrefix(l, "package ") {
			break
		}
	}
	return ""
}

// TestCI_ProductionBuildExcludesLegacyTrustedDealer asserts the default build
// excludes every legacy_trusted_dealer file, that the tag actually gates real
// reconstruct files, and that the reconstruct-at-sign combiner is never in prod.
func TestCI_ProductionBuildExcludesLegacyTrustedDealer(t *testing.T) {
	dir, defaultFiles := defaultBuildGoFiles(t)
	taggedFiles := taggedBuildGoFiles(t, legacyTrustedDealerTag)

	// Files the tag ADDS (present under -tags legacy_trusted_dealer, absent by
	// default): these are the quarantined reconstruct files.
	var legacyOnly []string
	for f := range taggedFiles {
		if !defaultFiles[f] {
			legacyOnly = append(legacyOnly, f)
		}
	}
	if len(legacyOnly) == 0 {
		t.Fatalf("CI invariant MISCONFIGURED: the %q tag gates NO files — quarantine mechanism is inert", legacyTrustedDealerTag)
	}

	// Every tag-gated file must (a) be absent from the default/production build
	// and (b) carry the legacy_trusted_dealer constraint (intentional gating).
	for _, f := range legacyOnly {
		if defaultFiles[f] {
			t.Fatalf("CI FAILED: %s is in BOTH the default and tagged build", f)
		}
		line := goBuildLine(t, filepath.Join(dir, f))
		if !strings.Contains(line, legacyTrustedDealerTag) {
			t.Fatalf("CI FAILED: %s is tag-gated but its build line %q does not mention %q", f, line, legacyTrustedDealerTag)
		}
	}

	// The reconstruct-at-sign combiner MUST be quarantined, never in prod.
	if defaultFiles["large_threshold.go"] {
		t.Fatalf("CI FAILED: large_threshold.go (LargeCombine, reconstruct-at-sign) is in the PRODUCTION build")
	}
	if !taggedFiles["large_threshold.go"] {
		t.Fatalf("CI MISCONFIGURED: large_threshold.go not found even under the legacy tag")
	}

	// No default-build file may itself require the legacy tag (belt-and-suspenders
	// against an accidental positive constraint that only builds under the tag).
	for f := range defaultFiles {
		if line := goBuildLine(t, filepath.Join(dir, f)); strings.Contains(line, legacyTrustedDealerTag) {
			t.Fatalf("CI FAILED: default-build file %s carries a %q constraint", f, legacyTrustedDealerTag)
		}
	}

	t.Logf("CI PASS: production build excludes %d legacy_trusted_dealer file(s) %v; LargeCombine quarantined", len(legacyOnly), legacyOnly)
}

// TestCI_TrustedDealerKeygenIsTestOnly asserts the trusted-dealer s1-share
// keygen (DealAlgShares) is defined ONLY in _test.go (uncompilable into any
// production binary) — the quarantine the no-reconstruct claim rests on.
func TestCI_TrustedDealerKeygenIsTestOnly(t *testing.T) {
	dir, defaultFiles := defaultBuildGoFiles(t)
	for f := range defaultFiles {
		src, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(src), "func DealAlgShares(") {
			t.Fatalf("CI FAILED: DealAlgShares (trusted-dealer keygen) defined in PRODUCTION file %s — must be _test.go only", f)
		}
	}
	// Sanity: it IS defined somewhere in the test build (the bootstrap file).
	if _, err := os.Stat(filepath.Join(dir, "bootstrap_dealer_test.go")); err != nil {
		t.Fatalf("bootstrap_dealer_test.go missing — trusted-dealer keygen quarantine file gone: %v", err)
	}
	t.Logf("CI PASS: DealAlgShares is test-only (bootstrap_dealer_test.go); never in the production build")
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
