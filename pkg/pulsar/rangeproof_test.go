// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"math"
	"testing"
)

// rangeproof_test.go — proves, by arithmetic over the LIVE parameters,
// that the small-norm range gate is honestly fail-closed: a faithful
// BDLOP/LNS Euclidean-norm proof cannot imply the FIPS 204 ℓ∞ bounds the
// DKG and nonce checks need. These tests are the soundness-boundary
// argument in executable form (see rangeproof.go for the construction and
// citations), plus the completeness/closed-by-default/registry checks.

// l2BoundForwardImpliesLinf: the ONLY useful ℓ2↔ℓ∞ inequality is
// ‖x‖∞ ≤ ‖x‖2. So an ℓ2 proof of a bound B DOES imply ‖x‖∞ ≤ B — but only
// because B is large. The point is whether that implied ℓ∞ bound is tight
// enough to be the FIPS bound. It is not: completeness forces B up by a
// √-dimension factor. This test pins that factor for every real
// requirement and asserts the implied ℓ∞ bound strictly exceeds the FIPS
// requirement (so the gate must stay closed).
func TestRangeL2CannotImplyFIPSLinf(t *testing.T) {
	type row struct {
		req fipsRangeRequirement
	}
	var rows []row
	for _, m := range []Mode{ModeP65, ModeP87} {
		for _, r := range dkgRangeRequirements(m) {
			rows = append(rows, row{r})
		}
		if r, ok := nonceRangeRequirement(m); ok {
			rows = append(rows, row{r})
		}
	}
	if len(rows) == 0 {
		t.Fatal("no requirements assembled")
	}
	for _, rw := range rows {
		r := rw.req
		// A vector with every coefficient at the FIPS ℓ∞ bound B∞ has
		// ‖·‖2 up to B∞·√(numCoeffs). Completeness forces any sound ℓ2
		// proof to certify a bound B ≥ this value (else it rejects real
		// witnesses). The implied per-coefficient bound is then ≥ B, i.e.
		// ≥ B∞·√(numCoeffs).
		impliedLinf := float64(r.linfBound) * math.Sqrt(float64(r.numCoeffs))
		if impliedLinf <= float64(r.linfBound) {
			t.Fatalf("%s: implied ℓ∞ bound %.1f should exceed FIPS bound %d "+
				"(numCoeffs=%d)", r.name, impliedLinf, r.linfBound, r.numCoeffs)
		}
		// And the package's decision function must agree: an ℓ2 proof
		// (approx or exact) does NOT imply this ℓ∞ requirement.
		if approxRangeImpliesFIPS(rangeApproxL2, r) {
			t.Fatalf("%s: approx-ℓ2 proof wrongly reported as implying FIPS ℓ∞ bound", r.name)
		}
		if approxRangeImpliesFIPS(rangeExactL2, r) {
			t.Fatalf("%s: exact-ℓ2 proof wrongly reported as implying FIPS ℓ∞ bound", r.name)
		}
	}
}

// TestRangeNonceW0ImpliedBoundIsVacuous: for w0 the gap is not merely
// loose — the ℓ2-implied ℓ∞ bound exceeds q, so it is satisfied by EVERY
// element of R_q. An ℓ2 proof on w0 therefore gates nothing at all.
func TestRangeNonceW0ImpliedBoundIsVacuous(t *testing.T) {
	for _, m := range []Mode{ModeP65, ModeP87} {
		req, ok := nonceRangeRequirement(m)
		if !ok {
			t.Fatalf("%s: nonce requirement unexpectedly out of scope", m)
		}
		impliedLinf := float64(req.linfBound) * math.Sqrt(float64(req.numCoeffs))
		if impliedLinf <= float64(mldsaQ) {
			t.Fatalf("%s: expected w0 ℓ2-implied ℓ∞ bound %.3e to exceed q=%d "+
				"(vacuous); it did not", m, impliedLinf, mldsaQ)
		}
	}
}

// TestRangeExactLinfWouldOpenGate: the decision logic is not trivially
// "always closed" — the EXACT ℓ∞ range proof (the construction that needs
// the BDLOP commitment layer Pulsar lacks) WOULD imply every FIPS ℓ∞
// requirement. This guards against the gate being closed for the wrong
// reason (e.g. a bug that rejects all classes).
func TestRangeExactLinfWouldOpenGate(t *testing.T) {
	for _, m := range []Mode{ModeP65, ModeP87} {
		for _, r := range dkgRangeRequirements(m) {
			if !approxRangeImpliesFIPS(rangeExactLinf, r) {
				t.Fatalf("%s/%s: exact-ℓ∞ range proof must imply the FIPS ℓ∞ bound", m, r.name)
			}
		}
		if r, ok := nonceRangeRequirement(m); ok {
			if !approxRangeImpliesFIPS(rangeExactLinf, r) {
				t.Fatalf("%s/%s: exact-ℓ∞ range proof must imply the FIPS ℓ∞ bound", m, r.name)
			}
		}
	}
}

// TestRangeAvailableClassIsL2: the strongest range proof faithfully
// available to the package is an ℓ2 proof (not exact ℓ∞). This is the
// fact that forces the gate closed — pinned so a change to it is
// deliberate and visible in review.
func TestRangeAvailableClassIsL2(t *testing.T) {
	if availableRangeProofClass == rangeExactLinf {
		t.Fatal("availableRangeProofClass claims an exact ℓ∞ range proof is " +
			"faithfully available; that requires a BDLOP commitment + Module-SIS " +
			"layer Pulsar does not have — do not set this without a real impl")
	}
	// rangeGateOpen must be closed for the real DKG + nonce requirements
	// using the available class.
	for _, m := range []Mode{ModeP65, ModeP87} {
		if rangeGateOpen(dkgRangeRequirements(m)) {
			t.Fatalf("%s: DKG range gate must be closed under the available ℓ2 proof", m)
		}
		if r, ok := nonceRangeRequirement(m); ok {
			if rangeGateOpen([]fipsRangeRequirement{r}) {
				t.Fatalf("%s: nonce range gate must be closed under the available ℓ2 proof", m)
			}
		}
	}
}

// TestRangeGateRejectsEmpty: rangeGateOpen on no requirements is closed
// (a gate with nothing to prove must not report "open").
func TestRangeGateRejectsEmpty(t *testing.T) {
	if rangeGateOpen(nil) {
		t.Fatal("rangeGateOpen(nil) must be closed")
	}
}

// TestDKGRangeFailClosedIsDerived: the DKG range verifier fails closed AND
// the decision tracks the parameters (it consults rangeGateOpen, which is
// closed for every real mode). DKGRangeProofReady stays false.
func TestDKGRangeFailClosedIsDerived(t *testing.T) {
	if DKGRangeProofReady() {
		t.Fatal("DKG range proof must be fail-closed by default")
	}
	for _, m := range []Mode{ModeP65, ModeP87} {
		st := &DKGWellFormedStatement{Mode: m}
		if err := registeredDKGRangeVerifier.VerifyDKGRange(st, nil); err != ErrDKGRangeProofUnsound {
			t.Fatalf("%s: DKG range verifier must fail closed, got %v", m, err)
		}
	}
}

// TestNonceRangeFailClosedIsDerived: the new nonce w0 range verifier
// mirrors the DKG one — fail-closed by default, decision derived from the
// bound arithmetic, Ready false. Out-of-BCC-scope modes (P44) also refuse.
func TestNonceRangeFailClosedIsDerived(t *testing.T) {
	if NonceRangeProofReady() {
		t.Fatal("nonce range proof must be fail-closed by default")
	}
	for _, m := range []Mode{ModeP65, ModeP87, ModeP44} {
		st := &NonceConsistencyStatement{Mode: m}
		if err := registeredNonceRangeVerifier.VerifyNonceRange(st, nil); err != ErrNonceRangeProofUnsound {
			t.Fatalf("%s: nonce range verifier must fail closed, got %v", m, err)
		}
	}
}

// TestNonceRangeRegistryRoundTrip: registering a verifier flips Ready and
// is consulted; mirrors the DKG registry contract so the two range gates
// have one identical surface.
func TestNonceRangeRegistryRoundTrip(t *testing.T) {
	orig := registeredNonceRangeVerifier
	t.Cleanup(func() { registeredNonceRangeVerifier = orig })

	if NonceRangeProofReady() {
		t.Fatal("must start fail-closed")
	}
	RegisterNonceRangeProofVerifier(stubNonceRange{})
	if !NonceRangeProofReady() {
		t.Fatal("registering a verifier must flip NonceRangeProofReady to true")
	}
	if err := registeredNonceRangeVerifier.VerifyNonceRange(&NonceConsistencyStatement{Mode: ModeP65}, nil); err != nil {
		t.Fatalf("registered verifier should be consulted, got %v", err)
	}
}

type stubNonceRange struct{}

func (stubNonceRange) VerifyNonceRange(*NonceConsistencyStatement, []byte) error { return nil }
