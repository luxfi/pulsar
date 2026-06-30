// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// naive_additive_seta_obstruction_test.go — pins the dealerless-DKG obstruction
// arithmetic. The fail-closed Part-2 verdict is DERIVED from the FIPS 204
// bounds (naive_additive_seta_obstruction.go assessDealerlessFIPS), and these
// tests reproduce every load-bearing number so the obstruction is computable,
// not asserted. They also rule out the t0 red herring by computation.

import (
	"errors"
	"testing"
)

// TestDealerless_BoundaryHypothesisBreaksAtTwoParties is the load-bearing
// computation: a dealerless joint secret summed over N ≥ 2 contributions has
// ‖c·s2‖∞ ≤ N·β, which exceeds the FIXED BCC boundary margin's β-coverage
// for every N ≥ 2 — so no FIPS-204-valid no-leak signature exists. N = 1
// (the degenerate single-contributor = dealer) is the only case the
// hypothesis holds.
func TestDealerless_BoundaryHypothesisBreaksAtTwoParties(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		o1, ok := assessDealerlessFIPS(mode, 1)
		if !ok {
			t.Fatalf("%s should be in BCC scope", mode)
		}
		if !o1.BoundaryHypothesisHolds {
			t.Fatalf("%s N=1: boundary hypothesis must hold (‖c·s2‖∞=%d ≤ β=%d)",
				mode, o1.JointCS2Linf, o1.BCCMarginCovers)
		}
		if o1.JointCS2Linf != o1.Beta {
			t.Fatalf("%s N=1: ‖c·s2‖∞ should equal β=%d, got %d", mode, o1.Beta, o1.JointCS2Linf)
		}

		for n := 2; n <= 8; n++ {
			o, _ := assessDealerlessFIPS(mode, n)
			if o.BoundaryHypothesisHolds {
				t.Fatalf("%s N=%d: boundary hypothesis must FAIL (‖c·s2‖∞=%d > β=%d) — the dealerless wall",
					mode, n, o.JointCS2Linf, o.BCCMarginCovers)
			}
			if o.JointCS2Linf != uint32(n)*o.Beta {
				t.Fatalf("%s N=%d: ‖c·s2‖∞ should be N·β=%d, got %d", mode, n, uint32(n)*o.Beta, o.JointCS2Linf)
			}
			if o.ByteFIPSReachable {
				t.Fatalf("%s N=%d: byte-FIPS-204 must be UNREACHABLE dealerlessly", mode, n)
			}
		}
	}
}

// TestDealerless_T0IsNotTheObstruction rules out the t0 red herring by
// computation: t0 = Power2Round-low(joint t) ∈ (−2^(d−1), 2^(d−1)] for ANY
// joint t, so ‖c·t0‖∞ ≤ τ·2^(d−1) < γ2 holds for EVERY N. The wall is the
// secret (s1, s2) distribution, never t0.
func TestDealerless_T0IsNotTheObstruction(t *testing.T) {
	cases := map[Mode]uint32{
		ModeP65: 49 * 4096, // τ·2^(d−1) = 200704
		ModeP87: 60 * 4096, // τ·2^(d−1) = 245760
	}
	for mode, wantCT0 := range cases {
		for _, n := range []int{1, 2, 5, 100, 1000} {
			o, _ := assessDealerlessFIPS(mode, n)
			if o.JointCT0Linf != wantCT0 {
				t.Fatalf("%s N=%d: ‖c·t0‖∞ should be %d (N-independent), got %d", mode, n, wantCT0, o.JointCT0Linf)
			}
			if !o.T0BoundHolds {
				t.Fatalf("%s N=%d: ‖c·t0‖∞=%d must stay < γ2=%d for all N (t0 is via Power2Round)",
					mode, n, o.JointCT0Linf, o.Gamma2)
			}
		}
	}
}

// TestDealerless_ExactParameterNumbers pins the concrete FIPS 204 numbers the
// obstruction rests on, so a parameter drift is caught.
func TestDealerless_ExactParameterNumbers(t *testing.T) {
	o65, _ := assessDealerlessFIPS(ModeP65, 2)
	if o65.Eta != 4 || o65.Tau != 49 || o65.Beta != 196 || o65.Gamma2 != 261888 || o65.T0Bound != 4096 {
		t.Fatalf("ML-DSA-65 parameters drifted: η=%d τ=%d β=%d γ2=%d 2^(d-1)=%d",
			o65.Eta, o65.Tau, o65.Beta, o65.Gamma2, o65.T0Bound)
	}
	// N=2 joint shift is 2β = 392, already over the β=196 the fixed margin covers.
	if o65.JointCS2Linf != 392 || o65.BCCMarginCovers != 196 {
		t.Fatalf("ML-DSA-65 N=2: ‖c·s2‖∞=%d (want 392) vs margin %d (want 196)", o65.JointCS2Linf, o65.BCCMarginCovers)
	}

	o87, _ := assessDealerlessFIPS(ModeP87, 2)
	if o87.Eta != 2 || o87.Tau != 60 || o87.Beta != 120 || o87.Gamma2 != 261888 {
		t.Fatalf("ML-DSA-87 parameters drifted: η=%d τ=%d β=%d γ2=%d", o87.Eta, o87.Tau, o87.Beta, o87.Gamma2)
	}
	// ML-DSA-87 single-key c·t0 headroom is only ~6.2% of γ2 — tight but valid.
	if o87.JointCT0Linf != 245760 {
		t.Fatalf("ML-DSA-87 ‖c·t0‖∞ should be 245760, got %d", o87.JointCT0Linf)
	}
}

// TestDealerless_ML_DSA44_OutOfScope confirms the BCC scope gate: ML-DSA-44
// is outside the proven no-leak scope, so the assessment reports ok=false.
func TestDealerless_ML_DSA44_OutOfScope(t *testing.T) {
	if _, ok := assessDealerlessFIPS(ModeP44, 3); ok {
		t.Fatalf("ML-DSA-44 must be reported out of BCC scope")
	}
}

// TestDealerless_EntryPointFailsClosed proves DealerlessMLDSADKG never fakes
// a key and never silently falls back to a dealer/TEE: it returns the
// computed obstruction with ErrDealerlessByteFIPSUnreachable for a real
// committee.
func TestDealerless_EntryPointFailsClosed(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := make([]NodeID, 5)
	for i := range committee {
		committee[i][0] = byte(i + 1)
	}
	o, err := DealerlessMLDSADKG(params, committee, 3)
	if !errors.Is(err, ErrDealerlessByteFIPSUnreachable) {
		t.Fatalf("DealerlessMLDSADKG must fail closed, got err=%v", err)
	}
	if o == nil || o.ByteFIPSReachable {
		t.Fatalf("obstruction must report byte-FIPS unreachable for a 5-party committee")
	}
	if o.JointCS2Linf <= o.BCCMarginCovers {
		t.Fatalf("5-party ‖c·s2‖∞=%d must exceed the β=%d the fixed margin covers", o.JointCS2Linf, o.BCCMarginCovers)
	}
}
