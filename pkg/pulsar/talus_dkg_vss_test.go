// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_dkg_vss_test.go — Phase-3b DKG-rewire proofs (step 2):
//
//  1. DealerlessDKGViaVSS produces the (*AlgSetup, []*AlgShare) shape the TALUS
//     signer consumes, bound to ExpandA(rho), with a non-trivial sharing.
//  2. No-reconstruct survives: an AST scan of the DKG-via-vss source proves no
//     reconstruction primitive (KeyFromSeed / reconstruct / Lagrange / …) is
//     DEFINED or CALLED in the path. The group key comes from the PUBLIC commit;
//     forming σ / s1 / sk is structurally absent.
//  3. The honest obstruction (HANDOFF-PHASE3 §67-79) is PROVEN, not asserted: the
//     vss group key T = A·s1 + B·u has a LARGE s2 = B·u, so HighBits(A·s1) ≠ t1
//     in the vast majority of coefficients — the root of why the BCC signer's
//     FindHint cannot reach t1 and a stock FIPS-204 signature cannot be produced
//     against this key. (Stock-verifiable signing keeps the trusted-dealer key.)

import (
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// reconstructS1 Lagrange-combines t AlgShares at X=0 to recover s1. TEST-ONLY
// scaffolding to VALIDATE the dealerless sharing; DealerlessDKGViaVSS performs no
// such reconstruction.
func reconstructS1(shares []*AlgShare, L int) polyVec {
	evals := make([]uint32, len(shares))
	for i, sh := range shares {
		evals[i] = sh.EvalPoint
	}
	s1 := make(polyVec, L)
	for _, sh := range shares {
		lambda := LagrangeAtZeroQ(sh.EvalPoint, evals)
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				s1[l][j] = uint32((uint64(s1[l][j]) + uint64(lambda)*uint64(sh.S1Share[l][j])) % mldsaQ)
			}
		}
	}
	return s1
}

// TestDKG_NoReconstruct_ViaVSS proves the adapter output shape, the ExpandA(rho)
// binding, and a non-trivial (no-single-party-holds-s1) sharing.
func TestDKG_NoReconstruct_ViaVSS(t *testing.T) {
	const n, threshold = 5, 3
	var rho [32]byte
	for i := range rho {
		rho[i] = byte(0x70 + i)
	}
	committee := make([]NodeID, n)
	for i := range committee {
		committee[i] = NodeID{byte(i + 1), 0xDC}
	}

	setup, shares, err := DealerlessDKGViaVSS(ModeP65, rho, committee, threshold, rand.Reader)
	if err != nil {
		t.Fatalf("DealerlessDKGViaVSS: %v", err)
	}
	K, L, _ := modeShape(ModeP65)

	// Setup shape.
	if setup == nil || setup.Pub == nil {
		t.Fatal("nil setup/pub")
	}
	if len(setup.t1) != K || len(setup.a) != K {
		t.Fatalf("setup shape: t1=%d a=%d, want K=%d", len(setup.t1), len(setup.a), K)
	}
	if len(setup.Pub.Bytes) != 32+320*K {
		t.Fatalf("packed pk size %d, want %d", len(setup.Pub.Bytes), 32+320*K)
	}

	// ExpandA(rho) binding: setup.a == pulsar ExpandA(rho).
	wantA := expandAPulsar(rho, K, L)
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			if setup.a[i][j] != wantA[i][j] {
				t.Fatalf("A not bound to ExpandA(rho) at [%d][%d]", i, j)
			}
		}
	}

	// Share shape + eval points.
	if len(shares) != n {
		t.Fatalf("share count %d, want %d", len(shares), n)
	}
	for i, sh := range shares {
		if len(sh.S1Share) != L {
			t.Fatalf("share %d S1Share len %d, want L=%d", i, len(sh.S1Share), L)
		}
		if sh.EvalPoint != uint32(i+1) {
			t.Fatalf("share %d eval point %d, want %d", i, sh.EvalPoint, i+1)
		}
		if sh.NodeID != committee[i] {
			t.Fatalf("share %d NodeID mismatch", i)
		}
	}

	// Non-trivial sharing: no single party's share equals the reconstructed s1.
	s1 := reconstructS1(shares[:threshold], L)
	for i, sh := range shares {
		if polyVecEqual(sh.S1Share, s1) {
			t.Fatalf("party %d's share equals s1 — sharing trivial/broken", i)
		}
	}

	// t-1 shares reconstruct a DIFFERENT value (threshold privacy).
	below := reconstructS1(shares[:threshold-1], L)
	if polyVecEqual(below, s1) {
		t.Fatal("t-1 shares reconstructed s1 — threshold broken")
	}
}

// TestDKG_NoReconstruct_SourceStructural parses the DKG-via-vss source (comments
// excluded) and fails if any reconstruction primitive is defined or called — the
// pulsar-side analogue of luxfi/dkg/vss's TestNoReconstruct_SourceStructural.
func TestDKG_NoReconstruct_SourceStructural(t *testing.T) {
	const file = "talus_dkg_vss.go"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0) // 0 = comments dropped
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	forbidden := []string{
		"reconstruct", "lagrange", "interpolate",
		"keyfromseed", "combineshares", "recoversecret", "modinverse",
	}
	check := func(name string) {
		low := strings.ToLower(name)
		for _, bad := range forbidden {
			if strings.Contains(low, bad) {
				t.Errorf("forbidden reconstruction identifier %q (matches %q) in the DKG-via-vss path", name, bad)
			}
		}
	}
	ast.Inspect(parsed, func(nd ast.Node) bool {
		switch node := nd.(type) {
		case *ast.FuncDecl:
			check(node.Name.Name)
		case *ast.Ident:
			check(node.Name)
		case *ast.SelectorExpr:
			check(node.Sel.Name)
		}
		return true
	})
}

// TestDKG_VSS_NotDirectlyBCCSignable PROVES the honest obstruction: the vss group
// key T = A·s1 + B·u has a LARGE s2 = B·u, so HighBits(A·s1) disagrees with the
// group-key t1 in the vast majority of coefficients. A small-s2 FIPS key would
// agree up to a handful of boundary coefficients; the disagreement is exactly why
// the BCC signer's FindHint cannot reach t1 (the per-coefficient correction
// spans many HighBits buckets), so no stock FIPS-204 signature can be produced
// against this key. The no-reconstruct DKG is the ROOT, not the signing key.
func TestDKG_VSS_NotDirectlyBCCSignable(t *testing.T) {
	const n, threshold = 5, 3
	var rho [32]byte
	for i := range rho {
		rho[i] = byte(0x33 + i)
	}
	committee := make([]NodeID, n)
	for i := range committee {
		committee[i] = NodeID{byte(i + 1), 0x5A}
	}
	setup, shares, err := DealerlessDKGViaVSS(ModeP65, rho, committee, threshold, rand.Reader)
	if err != nil {
		t.Fatalf("DealerlessDKGViaVSS: %v", err)
	}
	K, L, _ := modeShape(ModeP65)
	gamma2 := uint32(mldsaGamma2P65)

	// Reconstruct s1 (TEST-ONLY) and compute HighBits(A·s1) via pulsar's ring.
	s1 := reconstructS1(shares[:threshold], L)
	s1Hat := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1Hat[l] = s1[l]
		s1Hat[l].ntt()
	}
	as1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&as1[k], setup.a[k], s1Hat)
		as1[k].reduceLe2Q()
		as1[k].invNTT()
		as1[k].normalize()
	}
	hbAs1 := highBitsVec(as1, gamma2)

	diff := 0
	total := K * mldsaN
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			if hbAs1[k][j] != setup.t1[k][j] {
				diff++
			}
		}
	}
	// A small-s2 FIPS key ⇒ diff ≈ 0. The vss key's large s2 = B·u ⇒ diff is the
	// vast majority. Require > 50% to PROVE s2 is large (key not BCC-signable).
	if diff*2 <= total {
		t.Fatalf("HighBits(A·s1) agrees with vss t1 in %d/%d coeffs — s2 unexpectedly small; obstruction NOT demonstrated",
			total-diff, total)
	}
	t.Logf("obstruction proven: HighBits(A·s1) differs from group-key t1 in %d/%d coeffs (s2 = B·u large) — not stock-BCC-signable", diff, total)
}
