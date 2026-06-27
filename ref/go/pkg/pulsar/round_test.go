// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"math"
	"testing"
)

// TestRoundContext_Encode_Deterministic verifies the wire encoding
// of a RoundContext is deterministic and per-field unique. Changing
// any field changes the encoding -- catches accidental field reorder
// in future refactors.
func TestRoundContext_Encode_Deterministic(t *testing.T) {
	base := RoundContext{
		Epoch:         1,
		Round:         2,
		Item:          [32]byte{0xab},
		CommitteeRoot: [32]byte{0xcd},
	}
	e1 := base.Encode()
	e2 := base.Encode()
	if string(e1) != string(e2) {
		t.Fatalf("Encode is non-deterministic")
	}
	// Mutate each field; each mutation must change the encoding.
	for i, mutate := range []func(*RoundContext){
		func(c *RoundContext) { c.Epoch++ },
		func(c *RoundContext) { c.Round++ },
		func(c *RoundContext) { c.Item[0] = 0xff },
		func(c *RoundContext) { c.CommitteeRoot[0] = 0xff },
	} {
		mutated := base
		mutate(&mutated)
		if string(mutated.Encode()) == string(e1) {
			t.Fatalf("mutation %d did not change encoding", i)
		}
	}
}

// TestRoundSessionID_PerRoundDistinct verifies that two consecutive
// Lux rounds get distinct session IDs even when item + committee
// match -- so the Pulsar PRNG is forced to re-seed every round
// (the CRIT-1 cross-round replay defense from del Pino-Niot).
func TestRoundSessionID_PerRoundDistinct(t *testing.T) {
	ctxR1 := RoundContext{Epoch: 7, Round: 1, Item: [32]byte{0x11}, CommitteeRoot: [32]byte{0x22}}
	ctxR2 := ctxR1
	ctxR2.Round = 2
	if RoundSessionID(ctxR1) == RoundSessionID(ctxR2) {
		t.Fatalf("session IDs collide across Lux rounds")
	}
}

// TestRoundCommitteeRoot_OrderIndependent verifies the committee
// root is canonical under permutation -- Wave's K-sample order is
// not stable, so the root must be too.
func TestRoundCommitteeRoot_OrderIndependent(t *testing.T) {
	a := []NodeID{{0x01}, {0x02}, {0x03}}
	b := []NodeID{{0x03}, {0x01}, {0x02}}
	if RoundCommitteeRoot(a) != RoundCommitteeRoot(b) {
		t.Fatalf("committee root depends on order")
	}
}

// TestApproxRoundSecurity_BoundsMatchExpectedShape exercises the
// binomial-tail closed form for the (K, alpha) -> per-round security
// mapping. We check three properties:
//  1. rho=0 gives 0 (adversary controls 0 fraction -> can't agree).
//  2. rho=1 gives 1 (adversary controls everything).
//  3. monotonically increasing in rho.
func TestApproxRoundSecurity_BoundsMatchExpectedShape(t *testing.T) {
	policy := DefaultRoundQuorumPolicy // K=21, alpha=15, beta=12.
	if got := ApproxRoundSecurity(0.0, policy); got != 0 {
		t.Fatalf("rho=0: got %v, want 0", got)
	}
	if got := ApproxRoundSecurity(1.0, policy); math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("rho=1: got %v, want 1", got)
	}
	// Monotonicity check.
	prev := 0.0
	for _, rho := range []float64{0.1, 0.2, 0.3, 0.5, 0.7, 0.9} {
		v := ApproxRoundSecurity(rho, policy)
		if v < prev {
			t.Fatalf("non-monotonic: rho=%v gave %v < prev %v", rho, v, prev)
		}
		prev = v
	}
}

// TestApproxRoundSecurity_DefaultPolicyAt1OfThird verifies that the
// default policy (K=21, alpha=15) gives a non-trivial per-round
// adversary advantage at rho=1/3 (the standard Byzantine bound).
// The per-round binomial-tail bound at these parameters is
// ~4*10^-4 ≈ 2^-11.3; after the beta=12 amplification this
// compounds to (4e-4)^12 ≈ 2^-135 -- ample security for finality.
// See proofs/pulsar-m/lux-round-metastable.tex for the full claim.
func TestApproxRoundSecurity_DefaultPolicyAt1OfThird(t *testing.T) {
	v := ApproxRoundSecurity(1.0/3.0, DefaultRoundQuorumPolicy)
	if v >= math.Pow(2, -10) {
		t.Fatalf("at rho=1/3, K=21, alpha=15: per-round adv %v too high (>= 2^-10)", v)
	}
	if v <= math.Pow(2, -20) {
		t.Fatalf("at rho=1/3, K=21, alpha=15: per-round adv %v unexpectedly low (<= 2^-20)", v)
	}
	// Amplified bound after beta=12 rounds (assuming independent rounds).
	amplified := math.Pow(v, float64(DefaultRoundQuorumPolicy.Beta))
	if amplified >= math.Pow(2, -100) {
		t.Fatalf("beta=12 amplified bound %v too high (>= 2^-100)", amplified)
	}
}
