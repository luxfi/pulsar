// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// nonce_reuse_gate_test.go — GATE A (RED finding, HIGH: nonce reuse ⇒ full key
// recovery). Ported from RED's TestRED_NonceReuse_RecoversS1.
//
// The gate has two halves:
//
//	(1) THE VULNERABILITY IS REAL. Reusing one joint nonce for two messages
//	    yields the PUBLIC linear system z_A − z_B = (c_A − c_B)·s1 in which
//	    everything but s1 is public. We assert the identity holds (via the
//	    package's own arithmetic) AND actually RECOVER the whole expanded key
//	    s1 from it by solving the negacyclic system over Z_q — matching the
//	    dealer's secret bit-for-bit. This leak is intrinsic to the LINEAR
//	    response; it cannot be patched in the algebra.
//
//	(2) THE GUARD BLOCKS THE ATTACK. Driving the REAL signer API, an honest
//	    validator that has emitted a z-partial for a nonce REFUSES to emit a
//	    second partial for the same nonce — even relabeled under a fresh
//	    nonceID — so the attacker can never assemble (z_A, z_B) on one nonce.
//	    PRE-FIX this Round2 succeeded (key recovered); POST-FIX it returns
//	    ErrNonceReused. The gate is the second partial FAILING to be produced.

import (
	"crypto/rand"
	"sort"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────
// negacyclic linear algebra over Z_q (test-only attacker math)
// ─────────────────────────────────────────────────────────────────────────

func powModQ(a uint32, e uint32) uint32 {
	r := uint64(1)
	b := uint64(a) % mldsaQ
	for e > 0 {
		if e&1 == 1 {
			r = r * b % mldsaQ
		}
		b = b * b % mldsaQ
		e >>= 1
	}
	return uint32(r)
}

// invModQ returns a^(q-2) mod q (Fermat inverse; q prime).
func invModQ(a uint32) uint32 { return powModQ(a, mldsaQ-2) }

// negacyclicMatrix builds the n×n matrix M_d over Z_q with (d·s)[k] = Σ_j M[k][j]·s[j]
// for the ring R_q = Z_q[X]/(X^n+1): M[k][j] = d[k-j] for k≥j, else −d[k-j+n].
func negacyclicMatrix(d *poly) [][]uint32 {
	n := mldsaN
	M := make([][]uint32, n)
	for k := 0; k < n; k++ {
		M[k] = make([]uint32, n)
		for j := 0; j < n; j++ {
			if k >= j {
				M[k][j] = d[k-j] % mldsaQ
			} else {
				M[k][j] = (mldsaQ - d[k-j+n]%mldsaQ) % mldsaQ
			}
		}
	}
	return M
}

// solveModQ solves M·x = b over Z_q by Gauss–Jordan elimination. Returns
// ok=false iff M is singular (d not invertible in R_q).
func solveModQ(M [][]uint32, b []uint32) ([]uint32, bool) {
	n := len(b)
	A := make([][]uint64, n)
	for i := 0; i < n; i++ {
		A[i] = make([]uint64, n+1)
		for j := 0; j < n; j++ {
			A[i][j] = uint64(M[i][j])
		}
		A[i][n] = uint64(b[i])
	}
	for col := 0; col < n; col++ {
		piv := -1
		for r := col; r < n; r++ {
			if A[r][col]%mldsaQ != 0 {
				piv = r
				break
			}
		}
		if piv == -1 {
			return nil, false
		}
		A[col], A[piv] = A[piv], A[col]
		inv := uint64(invModQ(uint32(A[col][col] % mldsaQ)))
		for j := col; j <= n; j++ {
			A[col][j] = A[col][j] % mldsaQ * inv % mldsaQ
		}
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			f := A[r][col] % mldsaQ
			if f == 0 {
				continue
			}
			for j := col; j <= n; j++ {
				A[r][j] = (A[r][j] + (mldsaQ-A[col][j]*f%mldsaQ)) % mldsaQ
			}
		}
	}
	x := make([]uint32, n)
	for i := 0; i < n; i++ {
		x[i] = uint32(A[i][n] % mldsaQ)
	}
	return x, true
}

// challengeFor derives the challenge poly c = SampleInBall(H(μ, w1)) for a
// message under a FIXED nonce commitment w1 — the per-message challenge a
// reused nonce produces.
func challengeFor(mode Mode, tr [64]byte, ctx, msg []byte, w1 polyVec, gamma2 uint32, K, tau int) poly {
	cTilde := deriveCTilde(mode, tr, ctx, msg, w1, gamma2, K)
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)
	return c
}

// ─────────────────────────────────────────────────────────────────────────
// GATE A
// ─────────────────────────────────────────────────────────────────────────

func TestRED_NonceReuse_RecoversS1(t *testing.T) {
	const n, threshold = 5, 3
	mode := ModeP65
	params := MustParamsFor(mode)
	gamma2, _, _, ok := bccParams(mode)
	if !ok {
		t.Fatalf("bccParams(%v) not in scope", mode)
	}
	K, L, _ := modeShape(mode)
	tau, _, _, _ := modeTauOmega(mode)

	// Deal a committee. We KEEP the seed so we can derive the reference s1 the
	// attack must recover (the dealer wipes its own copy).
	committee := make([]NodeID, n)
	for i := range committee {
		if _, err := rand.Read(committee[i][:]); err != nil {
			t.Fatalf("committee entropy: %v", err)
		}
	}
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("seed entropy: %v", err)
	}
	setup, shares, err := DealAlgShares(params, committee, threshold, seed, rand.Reader)
	if err != nil {
		t.Fatalf("DealAlgShares: %v", err)
	}
	sort.Slice(shares, func(i, j int) bool { return nodeIDLess(shares[i].NodeID, shares[j].NodeID) })

	// Reference secret the attack must recover: s1 normalized to [0,q).
	refKM, err := deriveKeyMaterial(mode, &seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial(ref): %v", err)
	}
	refS1 := make(polyVec, L)
	for l := 0; l < L; l++ {
		refS1[l] = refKM.s1[l]
		refS1[l].normalize()
	}

	// The signing quorum (threshold members) + their eval points / Lagrange λ.
	quorum := make([]NodeID, threshold)
	evalPoints := make([]uint32, threshold)
	qshares := make([]*AlgShare, threshold)
	for i := 0; i < threshold; i++ {
		quorum[i] = shares[i].NodeID
		evalPoints[i] = shares[i].EvalPoint
		qshares[i] = shares[i]
	}

	// ONE joint nonce, shared across the quorum (the reused nonce).
	var nonceID [32]byte
	nonceID[0] = 0xA1
	deal, err := DealNonceMPCDebug(setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("DealNonceMPCDebug: %v", err)
	}
	w1vec, err := unpackW1Vec(deal.Cert.W1, gamma2, K)
	if err != nil {
		t.Fatalf("unpackW1Vec: %v", err)
	}

	// ── Part 1: the vulnerability is real — recover the WHOLE s1. ──
	//
	// Two messages, SAME nonce ⇒ two challenges; per-party partials
	// z_i = λ_i(y_i + c·s1_i) aggregate to z = ȳ + c·s1. We try candidate
	// second messages until (c_A − c_B) is invertible in R_q, then solve.
	msgA := []byte("transfer 1 LUX to alice — first use of the nonce")
	candidatesB := [][]byte{
		[]byte("transfer 1000000 LUX to mallory — REUSED nonce, message 2"),
		[]byte("mallory variant 2"),
		[]byte("mallory variant 3"),
		[]byte("mallory variant 4"),
	}

	cA := challengeFor(mode, setup.tr, nil, msgA, w1vec, gamma2, K, tau)
	cAHat := cA
	cAHat.ntt()

	aggregateFor := func(cHat *poly) polyVec {
		parts := make([]polyVec, threshold)
		for i := 0; i < threshold; i++ {
			lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
			y := deal.YShares[quorum[i]]
			parts[i] = partialLinearMap(lambda, cHat, y, qshares[i].S1Share)
		}
		return FlatAggregateZ(parts, L)
	}
	zA := aggregateFor(&cAHat)

	recovered := false
	for _, msgB := range candidatesB {
		cB := challengeFor(mode, setup.tr, nil, msgB, w1vec, gamma2, K, tau)
		cBHat := cB
		cBHat.ntt()
		zB := aggregateFor(&cBHat)

		// d = c_A − c_B (normal domain).
		var d poly
		for j := 0; j < mldsaN; j++ {
			d[j] = (cA[j] + (mldsaQ - cB[j]%mldsaQ)) % mldsaQ
		}

		// (a) Assert the leak identity z_A − z_B == d·s1 via the package's
		//     own NTT/Montgomery arithmetic — the public solvable system.
		dHat := d
		dHat.ntt()
		for l := 0; l < L; l++ {
			var diff poly
			for j := 0; j < mldsaN; j++ {
				diff[j] = (zA[l][j] + (mldsaQ - zB[l][j]%mldsaQ)) % mldsaQ
			}
			s1Hat := refS1[l]
			s1Hat.reduceLe2Q()
			s1Hat.ntt()
			var ds poly
			ds.mulHat(&dHat, &s1Hat)
			ds.reduceLe2Q()
			ds.invNTT()
			ds.normalize()
			if ds != diff {
				t.Fatalf("leak identity (z_A−z_B == (c_A−c_B)·s1) failed at l=%d — math model wrong", l)
			}
		}

		// (b) Actually RECOVER s1 from the public system (needs d invertible).
		M := negacyclicMatrix(&d)
		probe, okSolve := solveModQ(M, func() []uint32 {
			b := make([]uint32, mldsaN)
			for j := 0; j < mldsaN; j++ {
				b[j] = (zA[0][j] + (mldsaQ - zB[0][j]%mldsaQ)) % mldsaQ
			}
			return b
		}())
		if !okSolve {
			continue // (c_A − c_B) singular — pick another second message
		}
		// verify coordinate 0 then solve the rest.
		for j := 0; j < mldsaN; j++ {
			if probe[j] != refS1[0][j] {
				t.Fatalf("recovered s1[0] mismatch at coeff %d: got %d want %d", j, probe[j], refS1[0][j])
			}
		}
		for l := 1; l < L; l++ {
			b := make([]uint32, mldsaN)
			for j := 0; j < mldsaN; j++ {
				b[j] = (zA[l][j] + (mldsaQ - zB[l][j]%mldsaQ)) % mldsaQ
			}
			x, ok2 := solveModQ(M, b)
			if !ok2 {
				t.Fatalf("solve l=%d unexpectedly singular", l)
			}
			for j := 0; j < mldsaN; j++ {
				if x[j] != refS1[l][j] {
					t.Fatalf("recovered s1[%d] mismatch at coeff %d", l, j)
				}
			}
		}
		recovered = true
		t.Logf("VULN CONFIRMED: nonce reuse over 2 messages recovered the FULL %d-poly s1 (the master signing key) by solving (c_A−c_B)·s1 = z_A−z_B over Z_q", L)
		break
	}
	if !recovered {
		t.Fatalf("could not find an invertible (c_A−c_B) across %d candidates (vanishingly unlikely)", len(candidatesB))
	}

	// ── Part 2: the guard blocks the attack via the REAL signer API. ──
	//
	// Model ONE honest validator (share[0]) handed two signing requests on the
	// SAME nonce. It uses ONE shared ledger across both signer instances (a
	// validator's per-share ledger). The first emits its partial; the second
	// MUST be refused, so the attacker never gets the second partial.
	ledger := NewInMemoryNonceLedger()
	var sidA, sidB [32]byte
	copy(sidA[:], []byte("session-A-first-use"))
	copy(sidB[:], []byte("session-B-replay-attempt"))

	signerA, err := NewDistributedBCCSigner(params, setup, qshares[0], quorum, evalPoints, sidA, nil, msgA, rand.Reader)
	if err != nil {
		t.Fatalf("signerA: %v", err)
	}
	signerA.SetNonceLedger(ledger)
	if err := signerA.SetNonceShare(nonceID, deal.YShares[quorum[0]]); err != nil {
		t.Fatalf("signerA SetNonceShare: %v", err)
	}
	r1A, err := signerA.Round1(sidA, nonceID, deal.Cert)
	if err != nil {
		t.Fatalf("signerA Round1: %v", err)
	}
	if _, err := signerA.Round2(r1A, PartialInput{}); err != nil {
		t.Fatalf("signerA Round2 (first, honest use) must succeed: %v", err)
	}

	// Second signing request on the SAME nonce, different message — the attack.
	signerB, err := NewDistributedBCCSigner(params, setup, qshares[0], quorum, evalPoints, sidB, nil, candidatesB[0], rand.Reader)
	if err != nil {
		t.Fatalf("signerB: %v", err)
	}
	signerB.SetNonceLedger(ledger) // SAME validator, SAME share, SAME ledger
	if err := signerB.SetNonceShare(nonceID, deal.YShares[quorum[0]]); err != nil {
		t.Fatalf("signerB SetNonceShare: %v", err)
	}
	r1B, err := signerB.Round1(sidB, nonceID, deal.Cert)
	if err != nil {
		t.Fatalf("signerB Round1: %v", err)
	}
	if _, err := signerB.Round2(r1B, PartialInput{}); err != ErrNonceReused {
		t.Fatalf("GATE A FAILED: nonce-reuse Round2 returned %v, want ErrNonceReused — the second partial was produced, key recovery is possible", err)
	}

	// ── Part 3: relabel bypass is closed — same ȳ/w1 under a NEW nonceID. ──
	var nonceID2 [32]byte
	nonceID2[0] = 0xB2 // different label …
	relabeled := deal.Cert
	relabeled.NonceID = nonceID2 // … same W1 (same joint nonce material)
	signerC, err := NewDistributedBCCSigner(params, setup, qshares[0], quorum, evalPoints, sidB, nil, candidatesB[1], rand.Reader)
	if err != nil {
		t.Fatalf("signerC: %v", err)
	}
	signerC.SetNonceLedger(ledger)
	if err := signerC.SetNonceShare(nonceID2, deal.YShares[quorum[0]]); err != nil {
		t.Fatalf("signerC SetNonceShare: %v", err)
	}
	r1C, err := signerC.Round1(sidB, nonceID2, relabeled)
	if err != nil {
		t.Fatalf("signerC Round1: %v", err)
	}
	if _, err := signerC.Round2(r1C, PartialInput{}); err != ErrNonceReused {
		t.Fatalf("GATE A FAILED (relabel): reusing the same w1 under a new nonceID returned %v, want ErrNonceReused", err)
	}

	t.Logf("GATE A PASS: nonce reuse mathematically recovers the full key, but the single-use guard refuses the second partial (ErrNonceReused) — incl. the relabel bypass — so the (c_A−c_B)·s1 system can never be assembled via honest signers")
}
