// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// pedersen_vss_noreconstruct_test.go — the STRUCTURAL no-reconstruct invariant
// (task step 3) and the ≤t−1 privacy property (task step 5) for the v0.2
// Pedersen-VSS dealing layer.
//
// The dealing layer's defining improvement over v0.1 dkg.go is that the
// transport carries ONLY Shamir shares (f_i(j), g_i(j)), never the dealer's full
// 32-byte contribution c_i, and the path NEVER expands a seed into a key. These
// tests pin that structurally (source scan + reflection) and at runtime
// (reconstruction needs t shares; one share ≠ the secret; no seed is formed).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

// TestPedersenVSS_SourceHasNoSeedReconstruction parses the v0.2 production source
// (pedersen_vss.go) and asserts the CODE (AST identifiers — comments excluded by
// construction) references NONE of the v0.1 seed-reconstruction machinery: no
// KeyFromSeed / deriveKeyMaterial expansion, no master seed, and no v0.1 envelope
// (sealEnvelope/sealOpenEnvelope) that carries the full contribution c_i. This is
// the structural witness that the v0.2 dealing path cannot reconstruct a master
// secret even in principle. (Scanning the AST, not raw text, correctly ignores
// the explanatory comments that NAME these functions to describe the contrast.)
func TestPedersenVSS_SourceHasNoSeedReconstruction(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pedersen_vss.go", nil, 0) // 0 ⇒ comments dropped
	if err != nil {
		t.Fatalf("parse pedersen_vss.go: %v", err)
	}
	forbidden := map[string]string{
		"KeyFromSeed":          "FIPS-204 seed→key expansion",
		"deriveKeyMaterial":    "seed→key expansion",
		"masterSeed":           "v0.1 reconstructed master seed",
		"myContribution":       "v0.1 full 32-byte contribution",
		"sealEnvelope":         "v0.1 full-contribution envelope",
		"sealOpenEnvelope":     "v0.1 full-contribution open",
		"shamirReconstructQ":   "byte/seed reconstruction",
		"shamirReconstructGFQ": "byte/seed reconstruction",
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if why, bad := forbidden[id.Name]; bad {
				t.Errorf("pedersen_vss.go code references %q (%s) — reintroduces seed reconstruction", id.Name, why)
			}
		}
		return true
	})
}

// TestPedersenVSS_ShareTypeCarriesNoSeed reflects over VSSShare and asserts no
// field is a raw [SeedSize]byte secret seed (the only [32]byte-shaped field
// permitted is the NodeID identity, which is public). The secret-bearing fields
// must be polyVec Shamir shares.
func TestPedersenVSS_ShareTypeCarriesNoSeed(t *testing.T) {
	nodeIDType := reflect.TypeOf(NodeID{})
	polyVecType := reflect.TypeOf(polyVec(nil))
	st := reflect.TypeOf(VSSShare{})
	sawShare := false
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		// A raw fixed [SeedSize]byte array that is NOT the NodeID identity type
		// would be a smuggled seed/contribution. Forbid it.
		if f.Type.Kind() == reflect.Array && f.Type.Elem().Kind() == reflect.Uint8 &&
			f.Type.Len() == SeedSize && f.Type != nodeIDType {
			t.Errorf("VSSShare.%s is a raw [%d]byte field — a smuggled seed/contribution", f.Name, SeedSize)
		}
		if f.Type == polyVecType {
			sawShare = true
		}
	}
	if !sawShare {
		t.Error("VSSShare must carry its secret payload as polyVec Shamir shares")
	}
}

// TestPedersenVSS_NoReconstruct_PrivacyTMinus1 runs the dealing layer and asserts
// the no-reconstruct + privacy invariants at runtime:
//   - reconstruction REQUIRES t shares: a t-subset recovers the joint s1, a
//     (t−1)-subset does NOT (the Lagrange system is under-determined → wrong value);
//   - one party's share is NOT the secret;
//   - no 32-byte master seed is ever formed (the only secret state is polyVec shares).
func TestPedersenVSS_NoReconstruct_PrivacyTMinus1(t *testing.T) {
	mode := ModeP65
	const n, threshold = 5, 3

	km, err := deriveKeyMaterial(mode, bccTestSeed(0x66))
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	A := km.a
	B, err := expandB(mode)
	if err != nil {
		t.Fatalf("expandB: %v", err)
	}
	ids := make([]NodeID, n)
	evalPoints := make([]uint32, n)
	for i := 0; i < n; i++ {
		ids[i][0] = byte(i + 1)
		ids[i][1] = 0xA5
		evalPoints[i] = EvalPointFromIDQ(ids[i])
	}

	rng := newBCCDeterministicRNG("PVSS/noreconstruct")
	commits := make([]VSSCommit, n)
	dealt := make([][]VSSShare, n)
	for i := 0; i < n; i++ {
		c, sh, err := VSSDealerRound1(mode, A, B, ids[i], evalPoints, threshold, rng)
		if err != nil {
			t.Fatalf("VSSDealerRound1[%d]: %v", i, err)
		}
		commits[i], dealt[i] = c, sh
	}
	algShares := make([]*AlgShare, n)
	for p := 0; p < n; p++ {
		recv := make([]VSSShare, n)
		for i := 0; i < n; i++ {
			recv[i] = dealt[i][p]
		}
		as, _, err := AggregateVSSShares(mode, ids[p], recv)
		if err != nil {
			t.Fatalf("AggregateVSSShares[%d]: %v", p, err)
		}
		algShares[p] = as
	}

	// t shares reconstruct the joint s1 consistently; a different t-subset agrees.
	s1True := reconstructS1AtZero(algShares, []int{0, 1, 2})
	if !polyVecEqMod(s1True, reconstructS1AtZero(algShares, []int{1, 3, 4})) {
		t.Fatal("two t-subsets disagree — sharing is inconsistent")
	}

	// A (t−1)-subset CANNOT reconstruct: Lagrange over 2 points evaluates a
	// degree-1 interpolant at 0, which differs from the degree-2 f(0) = s1.
	s1Partial := reconstructS1AtZero(algShares, []int{0, 1})
	if polyVecEqMod(s1Partial, s1True) {
		t.Fatal("t−1 shares reconstructed s1 — the threshold is broken (privacy violated)")
	}

	// One party's share is not the secret.
	if polyVecEqMod(algShares[0].S1Share, s1True) {
		t.Fatal("a single party's share equals s1 — no threshold structure")
	}

	// Structural no-seed: the per-party secret state is exactly one polyVec share
	// at one eval point — there is no 32-byte master seed anywhere in AlgShare.
	asType := reflect.TypeOf(AlgShare{})
	for i := 0; i < asType.NumField(); i++ {
		f := asType.Field(i)
		if f.Type.Kind() == reflect.Array && f.Type.Elem().Kind() == reflect.Uint8 &&
			f.Type.Len() == SeedSize && f.Type != reflect.TypeOf(NodeID{}) {
			t.Errorf("AlgShare.%s is a raw [%d]byte seed-shaped field", f.Name, SeedSize)
		}
	}
}
