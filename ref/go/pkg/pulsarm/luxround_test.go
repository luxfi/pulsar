// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"crypto/sha512"
	"math"
	"testing"
)

// TestLuxRoundContext_Encode_Deterministic verifies the wire encoding
// of a LuxRoundContext is deterministic and per-field unique. Changing
// any field changes the encoding -- catches accidental field reorder
// in future refactors.
func TestLuxRoundContext_Encode_Deterministic(t *testing.T) {
	base := LuxRoundContext{
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
	for i, mutate := range []func(*LuxRoundContext){
		func(c *LuxRoundContext) { c.Epoch++ },
		func(c *LuxRoundContext) { c.Round++ },
		func(c *LuxRoundContext) { c.Item[0] = 0xff },
		func(c *LuxRoundContext) { c.CommitteeRoot[0] = 0xff },
	} {
		mutated := base
		mutate(&mutated)
		if string(mutated.Encode()) == string(e1) {
			t.Fatalf("mutation %d did not change encoding", i)
		}
	}
}

// TestLuxRoundSessionID_PerRoundDistinct verifies that two consecutive
// Lux rounds get distinct session IDs even when item + committee
// match -- so the Pulsar-M PRNG is forced to re-seed every round
// (the CRIT-1 cross-round replay defense from del Pino-Niot).
func TestLuxRoundSessionID_PerRoundDistinct(t *testing.T) {
	ctxR1 := LuxRoundContext{Epoch: 7, Round: 1, Item: [32]byte{0x11}, CommitteeRoot: [32]byte{0x22}}
	ctxR2 := ctxR1
	ctxR2.Round = 2
	if LuxRoundSessionID(ctxR1) == LuxRoundSessionID(ctxR2) {
		t.Fatalf("session IDs collide across Lux rounds")
	}
}

// TestLuxRoundCommitteeRoot_OrderIndependent verifies the committee
// root is canonical under permutation -- Wave's K-sample order is
// not stable, so the root must be too.
func TestLuxRoundCommitteeRoot_OrderIndependent(t *testing.T) {
	a := []NodeID{{0x01}, {0x02}, {0x03}}
	b := []NodeID{{0x03}, {0x01}, {0x02}}
	if LuxRoundCommitteeRoot(a) != LuxRoundCommitteeRoot(b) {
		t.Fatalf("committee root depends on order")
	}
}

// TestLuxRound_E2E_BetaRounds_Pulsar_M is the headline metastable
// signing test. It simulates:
//   1. Validator pool of 100 (beyond GF(257) cap not needed; tests math).
//   2. β = 4 consecutive Lux rounds.
//   3. Each Lux round: prism.Cut.Sample(K=3) → Pulsar-M (3,2) sign.
//   4. After β rounds: 4 separate FIPS 204 ML-DSA signatures, each
//      valid under the per-round group pubkey produced by per-round
//      DKG.
//
// This validates the per-Lux-round Pulsar-M math without requiring
// the Wave / Focus / Cut wiring (those live in consensus). The
// test asserts that each per-Lux-round signature verifies under
// unmodified FIPS 204 ML-DSA.Verify.
func TestLuxRound_E2E_BetaRounds_Pulsar_M(t *testing.T) {
	const validatorPool = 100
	const K = 3
	const T = 2
	const beta = 4

	params := MustParamsFor(ModeP65)
	pool := make([]NodeID, validatorPool)
	for i := range pool {
		pool[i] = NodeID{byte(i + 1), byte((i + 1) >> 8), 'V'}
	}

	// The "item" being voted on across all β Lux rounds.
	itemBytes := sha512.Sum512([]byte("lux-block-7-finality"))
	var item [32]byte
	copy(item[:], itemBytes[:32])

	for round := uint64(1); round <= beta; round++ {
		// Deterministic per-round K-sample (mock Prism.Cut.Sample).
		seed := []byte{byte(round)}
		idxs := mockSampleK(validatorPool, K, seed)
		committee := make([]NodeID, K)
		for i, idx := range idxs {
			committee[i] = pool[idx]
		}
		committeeRoot := LuxRoundCommitteeRoot(committee)
		ctx := LuxRoundContext{
			Epoch:         1,
			Round:         round,
			Item:          item,
			CommitteeRoot: committeeRoot,
		}
		sessionID := LuxRoundSessionID(ctx)

		// Per-round DKG.
		dkg := make([]*DKGSession, K)
		for i := 0; i < K; i++ {
			rng := deterministicReader([]byte{byte(round), byte(i), 'D'})
			s, err := NewDKGSession(params, committee, T, committee[i], rng)
			if err != nil {
				t.Fatalf("round %d DKG party %d: %v", round, i, err)
			}
			dkg[i] = s
		}
		dkgR1 := make([]*DKGRound1Msg, K)
		for i, s := range dkg {
			m, err := s.Round1()
			if err != nil {
				t.Fatalf("round %d DKG Round1 party %d: %v", round, i, err)
			}
			dkgR1[i] = m
		}
		dkgR2 := make([]*DKGRound2Msg, K)
		for i, s := range dkg {
			m, err := s.Round2(dkgR1)
			if err != nil {
				t.Fatalf("round %d DKG Round2 party %d: %v", round, i, err)
			}
			dkgR2[i] = m
		}
		outs := make([]*DKGOutput, K)
		for i, s := range dkg {
			out, err := s.Round3(dkgR1, dkgR2)
			if err != nil {
				t.Fatalf("round %d DKG Round3 party %d: %v", round, i, err)
			}
			outs[i] = out
		}
		groupPK := outs[0].GroupPubkey

		// Per-round Pulsar-M (3,2) threshold sign on the same item.
		quorum := committee[:T]
		myShares := make(map[NodeID]*KeyShare)
		for i := 0; i < T; i++ {
			myShares[committee[i]] = outs[i].SecretShare
		}
		signers := make([]*ThresholdSigner, T)
		for i := 0; i < T; i++ {
			rng := deterministicReader([]byte{byte(round), byte(i), 'S'})
			ts, err := NewThresholdSigner(params, sessionID, uint32(round), quorum, myShares[committee[i]], item[:], rng)
			if err != nil {
				t.Fatalf("round %d signer %d: %v", round, i, err)
			}
			signers[i] = ts
		}
		r1 := make([]*Round1Message, T)
		for i, ts := range signers {
			m, err := ts.Round1(item[:])
			if err != nil {
				t.Fatalf("round %d Round1 %d: %v", round, i, err)
			}
			r1[i] = m
		}
		r2 := make([]*Round2Message, T)
		for i, ts := range signers {
			m, ev, err := ts.Round2(r1)
			if err != nil {
				t.Fatalf("round %d Round2 %d: %v (ev=%+v)", round, i, err, ev)
			}
			r2[i] = m
		}
		allShares := make([]*KeyShare, K)
		for i := 0; i < K; i++ {
			allShares[i] = outs[i].SecretShare
		}
		sig, err := Combine(params, groupPK, item[:], nil, false, sessionID, uint32(round), quorum, T, r1, r2, allShares)
		if err != nil {
			t.Fatalf("round %d Combine: %v", round, err)
		}

		// FIPS 204 ML-DSA.Verify -- the Class N1 manifesto applies
		// per-Lux-round.
		if err := Verify(params, groupPK, item[:], sig); err != nil {
			t.Fatalf("round %d FIPS 204 verify: %v", round, err)
		}
	}
}

// TestApproxRoundSecurity_BoundsMatchExpectedShape exercises the
// binomial-tail closed form for the (K, alpha) -> per-round security
// mapping. We check three properties:
//   1. rho=0 gives 0 (adversary controls 0 fraction -> can't agree).
//   2. rho=1 gives 1 (adversary controls everything).
//   3. monotonically increasing in rho.
func TestApproxRoundSecurity_BoundsMatchExpectedShape(t *testing.T) {
	policy := DefaultLuxRoundQuorumPolicy // K=21, alpha=15, beta=12.
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
	v := ApproxRoundSecurity(1.0/3.0, DefaultLuxRoundQuorumPolicy)
	if v >= math.Pow(2, -10) {
		t.Fatalf("at rho=1/3, K=21, alpha=15: per-round adv %v too high (>= 2^-10)", v)
	}
	if v <= math.Pow(2, -20) {
		t.Fatalf("at rho=1/3, K=21, alpha=15: per-round adv %v unexpectedly low (<= 2^-20)", v)
	}
	// Amplified bound after beta=12 rounds (assuming independent rounds).
	amplified := math.Pow(v, float64(DefaultLuxRoundQuorumPolicy.Beta))
	if amplified >= math.Pow(2, -100) {
		t.Fatalf("beta=12 amplified bound %v too high (>= 2^-100)", amplified)
	}
}

// mockSampleK is a deterministic K-out-of-N sampler used to simulate
// prism.Cut.Sample in tests. Production uses prism.UniformCut /
// prism.StakeWeightedCut.
func mockSampleK(n, k int, seed []byte) []int {
	// Fisher-Yates with seed as the SHAKE expansion key.
	stream := cshake256(seed, n*4, "TEST-MOCK-SAMPLE-V1")
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	for i := n - 1; i > 0; i-- {
		r := uint32(stream[4*i])<<24 | uint32(stream[4*i+1])<<16 |
			uint32(stream[4*i+2])<<8 | uint32(stream[4*i+3])
		j := int(r % uint32(i+1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm[:k]
}
