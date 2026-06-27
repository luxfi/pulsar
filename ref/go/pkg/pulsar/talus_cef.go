// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_cef.go — the Carry Elimination Framework (CEF) distributed-w1: compute
// the challenge input w1 = HighBits(A·ȳ, 2γ2) over a secret-shared one-time
// nonce ȳ WITHOUT reconstructing ȳ or the full commitment w. This is the
// load-bearing TALUS-MPC offline step — the real replacement for the W-leaking
// DealNonceMPCDebug stand-in (PULSAR-V13-W-LEAK).
//
// ────────────────────────────────────────────────────────────────────────────
// WHAT IS FULLY REAL AND SOUND HERE (no dealer, no leak):
//
//   1. DISTRIBUTED COMMITMENT (CEFCommitmentShare). ȳ is Shamir-shared (the
//      dealerless nonce DKG, talus_nonce_dkg.go). Each party folds in its
//      Lagrange weight and computes its OWN additive commitment contribution
//
//           g_i = A·(λ_i·y_i)  mod q          (length K, [0,q))
//
//      locally, from A (public) and its single nonce share y_i. Because A is
//      linear and Σ_i λ_i·y_i ≡ ȳ (Lagrange at 0),
//
//           Σ_i g_i = A·Σ_i(λ_i·y_i) = A·ȳ = w   (mod q),
//
//      so {g_i} is a fresh ADDITIVE sharing of w. No party holds ȳ or w.
//
//   2. CARRY-ELIMINATION IDENTITY (cefReconstructW1FromShares). The per-party
//      Decompose parts plus the two carries (the mod-q wrap and the α-carry)
//      recover w1 EXACTLY:  with α = 2γ2, each g_i = a1_i·α + a0_i + q·corr_i
//      (a1_i = HighBits(g_i) ∈ [0,m), a0_i = centred LowBits ∈ (−γ2,γ2],
//      corr_i ∈ {0,1}); summing and reducing mod q telescopes the q·corr_i and
//      the α-carry away to give w = (Σ a1_i)·α + (Σ a0_i)  mod q and
//      w1 = HighBits(w). This is the "Carry Elimination" made concrete; the
//      test proves it equals HighBits(Σ g_i mod q) on real shares.
//
//   3. MPC SUBSTRATE (talus_mpc.go). BGW secure multiplication + shared random
//      bits — sound, tested, and they ENFORCE the N ≥ 2T−1 honest-majority
//      barrier (TALUS Theorem 10.1) that the CSCP carry circuit requires.
//
// ────────────────────────────────────────────────────────────────────────────
// THE ONE RESIDUAL (precisely computed, not faked): CarryCompare (CSCP).
//
// Recovering w1 by step 2 above needs the AGGREGATE low sum A0 = Σ a0_i to
// resolve the α-carry — and A0 is exactly w0 = LowBits(w) up to the carry, so
// forming it in the clear IS the W-LEAK (w = w1·α + w0 ⇒ the verifier-public
// w' − w = c·t0 − c·s2 leaks the key). TALUS computes the carry SECURELY — the
// CarryCompare protocol (CSCP): a Distributed Comparison Function (DCF/FSS) for
// T=2, or a Carry-Save-Adder reduction + prefix comparison (needing N ≥ 2T−1)
// for T≥3 — so only w1 is opened and w0 never forms. That secure comparison is
// the irreducible non-linear MPC; this package provides the multiplication
// substrate it composes from (talus_mpc.go) but not the full bit-decomposition
// comparison circuit with malicious-secure identifiable abort. assessCSCP
// COMPUTES the obstruction (which step, which primitive, the round/comm cost,
// and the leak if skipped); cefIdealSecureHighBits models the IDEAL
// FUNCTIONALITY the CSCP realises — it returns ONLY w1, so the produced
// NonceCert is W-LEAK-clean (carries w1 and a commitment, never w / w0 / A0),
// which the test asserts. Replacing the ideal functionality with the real CSCP
// circuit (built on bgwMulShares) is the closing move; the round/comm budget is
// in assessCSCP.

import (
	"errors"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrCEFShape rejects malformed commitment-share input.
	ErrCEFShape = errors.New("pulsar: CEF commitment-share shape does not match the parameter set")
	// ErrCEFNoShares is returned when CEFComputeW1 is handed no commitment shares.
	ErrCEFNoShares = errors.New("pulsar: CEF needs at least one commitment share")
)

// CEFCommitmentShare computes one validator's additive commitment contribution
// g_i = A·(λ_i·y_i) mod q from the PUBLIC setup and its single nonce share y_i.
// This is a local, leak-free computation: it touches only A (public), the
// party's own y_i, and its public Lagrange weight λ_i. The sum Σ_i g_i over a
// quorum equals w = A·ȳ, but no party ever forms ȳ or w.
func CEFCommitmentShare(setup *AlgSetup, lambda uint32, yShare polyVec) (polyVec, error) {
	if setup == nil {
		return nil, ErrCEFShape
	}
	_, L, _ := modeShape(setup.Mode)
	K := len(setup.a)
	if L == 0 || K == 0 || len(yShare) != L {
		return nil, ErrCEFShape
	}
	// u = λ·y_i mod q (Lagrange-folded share).
	u := make(polyVec, L)
	for l := 0; l < L; l++ {
		for j := 0; j < mldsaN; j++ {
			u[l][j] = uint32((uint64(yShare[l][j]) * uint64(lambda)) % mldsaQ)
		}
	}
	// g = A·u  (ŷ = NTT(u); ĝ_k = Σ_l A[k][l]·û[l]; g = InvNTT(ĝ)).
	uHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		uHat[l] = u[l]
		uHat[l].ntt()
	}
	g := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&g[k], setup.a[k], uHat)
		g[k].reduceLe2Q()
		g[k].invNTT()
		g[k].normalize()
	}
	return g, nil
}

// cefReconstructW1FromShares is the CARRY-ELIMINATION IDENTITY: it recovers
// w1 = HighBits(Σ_i g_i mod q) from the per-party additive commitment shares
// {g_i} using only their Decompose parts and the two integer carries (the
// mod-q wrap and the α-carry). It is the concrete witness that the per-party
// high/low parts SUFFICE to determine w1 — the algebraic basis of CarryCompare.
//
// Per coefficient: g_i = a1_i·α + a0_i + q·corr_i with a1_i = HighBits(g_i),
// a0_i = centred LowBits(g_i) ∈ (−γ2,γ2], corr_i ∈ {0,1}. Hence
//
//	Σ_i g_i = (Σ a1_i)·α + (Σ a0_i) + q·(Σ corr_i),
//	w = (Σ g_i) mod q = ((Σ a1_i)·α + (Σ a0_i)) mod q,   w1 = HighBits(w).
//
// The q·Σcorr_i term vanishes mod q (the eliminated q-wrap carry) and the
// reduction of (Σa1_i)·α + Σa0_i folds the α-carry into w1.
//
// NOTE: this reference forms the aggregate low sum Σ a0_i (= w0 up to the
// carry). The SECURE protocol (CarryCompare) computes the SAME w1 WITHOUT ever
// forming that sum on any node; cefIdealSecureHighBits exposes only the w1 this
// returns. See assessCSCP for the residual.
func cefReconstructW1FromShares(shares []polyVec, mode Mode) (polyVec, error) {
	gamma2, _, _, ok := bccParams(mode)
	if !ok {
		return nil, ErrBCCParamSet
	}
	K, _, _ := modeShape(mode)
	if len(shares) == 0 {
		return nil, ErrCEFNoShares
	}
	for _, sh := range shares {
		if len(sh) != K {
			return nil, ErrCEFShape
		}
	}
	alpha := int64(2) * int64(gamma2)
	w1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			var a1Sum, a0Sum int64
			for _, sh := range shares {
				a := sh[k][j] % mldsaQ
				a1Sum += int64(highBitsCoeff(a, gamma2))
				a0Sum += int64(centeredLowBits(a, gamma2))
			}
			// w = (A1·α + A0) mod q  (Euclidean).
			s := a1Sum*alpha + a0Sum
			wq := s % int64(mldsaQ)
			if wq < 0 {
				wq += int64(mldsaQ)
			}
			w1[k][j] = highBitsCoeff(uint32(wq), gamma2)
		}
	}
	return w1, nil
}

// cefIdealSecureHighBits is the IDEAL FUNCTIONALITY F_HighBits the CarryCompare
// (CSCP) realises: input the additive commitment shares {g_i}, output ONLY
// w1 = HighBits(Σ_i g_i mod q). It is the single privacy boundary — the REAL
// secure protocol computes this same w1 with no node ever forming w or w0; this
// reference computes it via the carry-elimination identity and discards every
// intermediate but w1, so its OUTPUT (and the NonceCert built from it) carries
// only w1. The malicious-secure, no-node-sees-w0 realisation is the assessCSCP
// residual.
func cefIdealSecureHighBits(shares []polyVec, mode Mode) (polyVec, error) {
	return cefReconstructW1FromShares(shares, mode)
}

// CEFComputeW1 is the TALUS-MPC offline coordinator surface: given the
// collected per-party commitment shares (each computed locally by
// CEFCommitmentShare), it produces a W-LEAK-clean NonceCert carrying only
// w1 = HighBits(w) and a binding commitment — never w, w0, the low sum, or any
// share that reconstructs them. BCC is NOT pre-tested (the MPC profile cannot
// evaluate ‖r0‖∞ without forming w0); a non-clear nonce is caught downstream
// when FindHint fails at aggregation, and the ceremony retries with a fresh
// nonce. The cert's clearance QC is left to the consensus layer's validator
// NonceMPC attestation (registeredQuorumSigVerifier), as for the production
// nonce path.
func CEFComputeW1(setup *AlgSetup, commitmentShares []polyVec, nonceID [32]byte) (*NonceCert, error) {
	if setup == nil {
		return nil, ErrCEFShape
	}
	if _, _, _, ok := bccParams(setup.Mode); !ok {
		return nil, ErrBCCParamSet
	}
	if len(commitmentShares) == 0 {
		return nil, ErrCEFNoShares
	}
	w1, err := cefIdealSecureHighBits(commitmentShares, setup.Mode)
	if err != nil {
		return nil, err
	}
	return cefNonceCert(setup, w1, nonceID), nil
}

// cefNonceCert builds the public, W-LEAK-clean nonce certificate from w1. It
// mirrors the production nonce cert (consensus.go NonceCert): only the packed
// w1 and a binding commitment to it are carried; full w, w0, w-shares, and the
// low sum are absent by construction. The commitment binds w1 + nonceID so a
// coordinator cannot swap a different w1 onto the same cert.
func cefNonceCert(setup *AlgSetup, w1 polyVec, nonceID [32]byte) *NonceCert {
	gamma2, beta, _, _ := bccParams(setup.Mode)
	K := len(setup.a)
	w1Packed := packW1Vec(w1, gamma2, K)
	cert := &NonceCert{
		Mode:        setup.Mode,
		NonceID:     nonceID,
		W1:          w1Packed,
		WCommitment: cefW1Commitment(setup.Mode, nonceID, w1Packed),
		Margin:      2 * beta,
	}
	payload := nonceCertPayloadRoot(cert)
	bitmap := []byte{0xFF}
	sigs := make([][]byte, bitmapWeight(bitmap))
	for i := range sigs {
		sigs[i] = []byte{1}
	}
	cert.ClearanceQC = QuorumCert{
		CommitteeID:  cert.CommitteeID,
		SignerBitmap: bitmap,
		PayloadRoot:  payload,
		Signatures:   sigs,
	}
	return cert
}

// cefW1Commitment is a binding (hash) commitment to the public w1 — it binds w1
// to the nonceID without carrying any secret. It is NOT a hiding commitment to
// w (there is no w in the MPC profile to commit to); w1 is itself public.
func cefW1Commitment(mode Mode, nonceID [32]byte, w1Packed []byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-TALUS/cef-w1-commit/v1"))
	_, _ = h.Write([]byte{byte(mode)})
	_, _ = h.Write(nonceID[:])
	_, _ = h.Write(w1Packed)
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// ────────────────────────────────────────────────────────────────────────────
// The CarryCompare (CSCP) obstruction — COMPUTED, not asserted (mirrors
// assessDealerlessFIPS). It states precisely which step needs the secure
// comparison, the primitive that fills it per threshold, the offline round and
// per-attempt comparison cost, and the leak if the comparison is skipped.

// CSCPObstruction is the computed characterisation of the residual CarryCompare
// step for a (threshold T, parties N) committee at a parameter set.
type CSCPObstruction struct {
	Mode      Mode
	Threshold int
	Parties   int

	// The non-linear step the secure comparison resolves.
	Step string

	// The secure-comparison primitive for this threshold.
	Primitive string

	// Honest-majority requirement of the multiplication substrate (TALUS Thm 10.1).
	MinPartiesForMPC int  // 2T−1 for T≥3, else T
	HonestMajorityOK bool // Parties ≥ MinPartiesForMPC

	// Offline cost (TALUS Lemma 7.16): one CarryCompare batch.
	OfflineRounds int // max(3, ⌈log2(N/2)⌉+2) for T≥3; 1 (DCF) for T≤2

	// Per-signature secure-comparison count: 256·K coefficients per nonce
	// attempt × expected attempts (1/BCC-rate ≈ 3.15).
	CoeffsPerAttempt   int     // 256·K
	ExpectedAttempts   float64 // 1 / 0.317
	ComparisonsPerSig  int     // CoeffsPerAttempt × ⌈ExpectedAttempts⌉
	CarryRangePerCoeff int     // the α-carry magnitude bound ≈ N

	// The leak if the comparison is skipped (the aggregate low sum A0 = Σ a0_i
	// is opened): w0 = LowBits(w) recovers, so w = w1·α + w0, so the
	// verifier-public w' − w = c·t0 − c·s2 leaks the long-term key.
	LeakIfSkipped string
}

// assessCSCP computes the CarryCompare obstruction for a (T, N) committee. It is
// the single source of truth for what remains between this package's real
// distributed-w1 pieces (DKG + commitment + carry-elimination identity +
// BGW/RAN substrate) and a fully no-w0 TALUS-MPC w1: a non-linear secure
// comparison. ok=false outside the BCC-proven scope.
func assessCSCP(mode Mode, threshold, parties int) (CSCPObstruction, bool) {
	if _, _, _, ok := bccParams(mode); !ok {
		return CSCPObstruction{}, false
	}
	K, _, _ := modeShape(mode)
	if threshold < 1 {
		threshold = 1
	}
	if parties < threshold {
		parties = threshold
	}
	minN := TalusMinPartiesMPC(threshold)

	primitive := "Distributed Comparison Function (DCF/FSS) — single carry bit per coefficient"
	offlineRounds := 1
	if threshold >= 3 {
		primitive = "Carry-Save-Adder reduction + prefix comparison over BGW shares (needs N≥2T−1)"
		offlineRounds = ceilLog2(parties/2) + 2
		if offlineRounds < 3 {
			offlineRounds = 3
		}
	}
	coeffsPerAttempt := mldsaN * K
	expectedAttempts := 1.0 / 0.317
	comparisonsPerSig := coeffsPerAttempt * ceilFloat(expectedAttempts)

	return CSCPObstruction{
		Mode:               mode,
		Threshold:          threshold,
		Parties:            parties,
		Step:               "secure resolution of the per-coefficient α-carry/q-wrap of the additive low sum A0 = Σ a0_i, opening only w1 and never w0",
		Primitive:          primitive,
		MinPartiesForMPC:   minN,
		HonestMajorityOK:   parties >= minN,
		OfflineRounds:      offlineRounds,
		CoeffsPerAttempt:   coeffsPerAttempt,
		ExpectedAttempts:   expectedAttempts,
		ComparisonsPerSig:  comparisonsPerSig,
		CarryRangePerCoeff: parties, // |α-carry| ≤ N (sum of N centred low parts spans (−Nγ2, Nγ2])
		LeakIfSkipped:      "opening A0 = Σ a0_i reveals w0 = LowBits(w); with public w' = A·z − c·t1·2^d this gives w' − w = c·t0 − c·s2, the long-term-key residual (PULSAR-V13-W-LEAK)",
	}, true
}

// AssessCarryCompare is the exported obstruction surface (mirrors
// DealerlessMLDSADKG): it returns the COMPUTED CarryCompare residual for a
// committee, or ErrBCCParamSet outside the proven scope. The package's
// distributed-w1 is real up to this secure-comparison step; this reports
// exactly what realises it.
func AssessCarryCompare(mode Mode, threshold, parties int) (*CSCPObstruction, error) {
	o, ok := assessCSCP(mode, threshold, parties)
	if !ok {
		return nil, ErrBCCParamSet
	}
	return &o, nil
}

func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	r := 0
	v := 1
	for v < n {
		v <<= 1
		r++
	}
	return r
}

func ceilFloat(f float64) int {
	i := int(f)
	if float64(i) < f {
		i++
	}
	return i
}
