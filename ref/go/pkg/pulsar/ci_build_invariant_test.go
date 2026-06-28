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
