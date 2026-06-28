// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// pedersen_vss.go — the v0.2 module-Pedersen VSS DKG of spec/pulsar.tex
// (§"Distributed key generation", Construction con:pedersen, Rounds 1/1.5/2).
// See docs/dkg-v02-mapping.md for the full spec→Go symbol map.
//
// WHAT IS SOUND HERE (real, tested, reusable — the no-leak DEALING layer):
//
//   - expandB                 the PULSAR-EXPANDB-V1 public hiding matrix B,
//                             uniform and domain-separated from A.
//   - modulePedersenCommit    Comm_{A,B}(c;r) = A·c + B·r ∈ R_q^k.
//   - VSSDealerRound1         each dealer samples f_i, g_i (deg t−1 over R_q^ℓ),
//                             broadcasts Pedersen commits C_{i,k}, and sends each
//                             party j ONLY the Shamir pair (f_i(j), g_i(j)) —
//                             never the full contribution c_{i,0}. This is the
//                             decisive no-leak improvement over v0.1 dkg.go,
//                             whose envelope reveals the full 32-byte c_i to every
//                             recipient ("every committee member learns the master
//                             secret", dkg.go:366).
//   - VerifyVSSShare          Round-2 Pedersen identity A·f_i(j)+B·g_i(j) =
//                             Σ_k j^k C_{i,k}; failure ⇒ ComplaintBadDelivery
//                             (identifiable abort, binding under MSIS over [A|B]).
//   - AggregateVSSShares      s_j = Σ_i f_i(j) → AlgShare.S1Share (s1 share);
//                             u_j = Σ_i g_i(j). NO seed / s1 / sk ever formed.
//   - AggregateVSSCommits     t = Σ_i C_{i,0} = A·s1 + B·u (public commit).
//
// WHERE IT FAILS CLOSED (the structural wall, COMPUTED not asserted):
//
//   PedersenVSSFormFIPSKey refuses. The v0.2 key sets the second secret
//   component to s2 = B·u. Because B is uniform (required by the hiding theorem
//   thm:pedersen-hiding — hiding reduces to M-LWE in B), B·u is M-LWE-pseudo-
//   uniform: ‖B·u‖∞ ≈ q/2, hence ‖c·s2‖∞ ≫ γ2 ≫ β. The FIPS-204 correctness
//   lemma (and the package's own BCC path, bcc_sign.go) needs ‖c·s2‖∞ ≤ β so
//   that HighBits(w − c·s2) = HighBits(w); with B·u that fails for ~every
//   coefficient, FindHint returns ok=false (ErrNoFIPSHint), and NO FIPS-204-
//   verifiable signature exists for the v0.2 key.
//
//   This is the package's documented Residual B (naive_additive_seta_obstruction
//   .go / assessDealerlessFIPS), specialized to the Pedersen B·u case — strictly
//   worse than the naive S_{Nη} sum (B·u is pseudo-uniform, not merely N·η).
//   Hiding (DKG-PRIV, needs B uniform ⇒ s2 large) and signing correctness (needs
//   s2 small) are irreconcilable at the FIPS-204 parameters. The wall is
//   empirically demonstrated end-to-end in pedersen_vss_obstruction_test.go: the
//   real bccSign returns ErrBCCExhausted on a s2=B·u key while succeeding AND
//   circl-verifying on a small-s2 key built from the SAME s1.
//
//   The real path to dealerless / no-reconstruct byte-FIPS-204 keygen is SHORT
//   replicated secret sharing + local rejection (Mithril, ia.cr/2026/013), not
//   Pedersen-VSS Shamir; until adopted, KEYGEN stays trusted-dealer
//   (DealAlgShares) and permissionless safety rests on the dealerless Corona leg.

import (
	"errors"
	"io"
)

// tagExpandB ("PULSAR-EXPANDB-V1", declared in transcript.go) is the SP 800-185
// cSHAKE customisation for the nothing-up-my-sleeve B-matrix seed
// ρ_B = cSHAKE(empty, 256, "Pulsar", "PULSAR-EXPANDB-V1"). Its distinct
// customisation domain-separates B from A (ExpandA over ρ), satisfying the
// A ⟂ B independence requirement of thm:pedersen-hiding.

// ErrPedersenVSSNotByteFIPS is returned by PedersenVSSFormFIPSKey: the v0.2
// Pedersen-VSS public commit t = A·s1 + B·u cannot be a signable FIPS-204 key,
// because the implied s2 = B·u is M-LWE-pseudo-uniform (‖B·u‖∞ ≈ q/2), so
// ‖c·s2‖∞ ≫ β and no FIPS-204 hint reaches w1. It fails CLOSED — it NEVER
// fabricates a key, NEVER reconstructs a seed, and NEVER falls back to a dealer.
var ErrPedersenVSSNotByteFIPS = errors.New(
	"pulsar: v0.2 Pedersen-VSS commit t = A·s1 + B·u is not a signable FIPS-204 " +
		"key — s2 = B·u is M-LWE-pseudo-uniform (‖B·u‖∞ ≈ q/2), so ‖c·s2‖∞ ≫ β " +
		"and HighBits(w − c·s2) ≠ HighBits(w): no FIPS-204 hint exists. This is the " +
		"package's Residual B (assessDealerlessFIPS) specialized to the Pedersen B·u " +
		"case. Use DealAlgShares (dealer/TEE genesis, no-reconstruct at SIGN time) and " +
		"the dealerless Corona leg; the byte-FIPS-204 dealerless target is Mithril " +
		"(short replicated shares, ia.cr/2026/013), not Pedersen-VSS Shamir")

// expandB derives the public hiding matrix B ∈ R_q^{k×ℓ} (NTT domain, the same
// representation as the ExpandA matrix km.a) from the fixed nothing-up-my-sleeve
// seed ρ_B. B is uniform and independent of A (distinct cSHAKE customisation).
func expandB(mode Mode) ([]polyVec, error) {
	K, L, _ := modeShape(mode)
	if K == 0 {
		return nil, ErrUnknownMode
	}
	var rhoB [32]byte
	copy(rhoB[:], cshake256(nil, 32, tagExpandB))
	B := make([]polyVec, K)
	for i := 0; i < K; i++ {
		B[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			polyDeriveUniform(&B[i][j], &rhoB, uint16(i)<<8|uint16(j))
		}
	}
	return B, nil
}

// modulePedersenCommit returns Comm_{A,B}(c;r) = A·c + B·r ∈ R_q^k. aRows and
// bRows are the K×L public matrices in NTT domain (km.a / expandB); c and r are
// length-L vectors in normalized [0,q) coefficient form. The result is in
// normalized coefficient form, matching how km.t is computed (deriveKeyMaterial).
func modulePedersenCommit(aRows, bRows []polyVec, c, r polyVec) polyVec {
	K := len(aRows)
	cHat := make(polyVec, len(c))
	for l := range c {
		cHat[l] = c[l]
		cHat[l].ntt()
	}
	rHat := make(polyVec, len(r))
	for l := range r {
		rHat[l] = r[l]
		rHat[l].ntt()
	}
	out := make(polyVec, K)
	for i := 0; i < K; i++ {
		var ac, br poly
		polyDotHat(&ac, aRows[i], cHat)
		ac.reduceLe2Q()
		polyDotHat(&br, bRows[i], rHat)
		br.reduceLe2Q()
		out[i].add(&ac, &br)
		out[i].reduceLe2Q()
		out[i].invNTT()
		out[i].normalize()
	}
	return out
}

// VSSCommit is dealer i's PUBLIC Round-1 broadcast: the Pedersen commits to each
// coefficient pair of (f_i, g_i). Commits[k] = C_{i,k} = A·c_{i,k} + B·r_{i,k}
// ∈ R_q^k, for k ∈ {0,…,t−1}.
type VSSCommit struct {
	DealerID NodeID
	Commits  []polyVec // length t; each is a length-K poly-vector (R_q^k)
}

// VSSShare is dealer i's PRIVATE point-to-point message to one recipient j. It
// carries ONLY the Shamir pair (f_i(j), g_i(j)) — never the full contribution
// c_{i,0}, no 32-byte seed, no master secret. This is the structural no-leak
// invariant: the dealing transport cannot carry a reconstructable secret.
type VSSShare struct {
	DealerID   NodeID
	EvalPoint  uint32  // recipient's GF(q) Shamir x-coordinate in [1,q)
	S1Share    polyVec // f_i(j), length L
	BlindShare polyVec // g_i(j), length L
}

// VSSDealerRound1 is one dealer's Round-1: sample the degree-(t−1) sharing
// polynomial f_i (constant term c_{i,0} ← χ_η, its contribution to s1) and the
// blinding polynomial g_i (coeffs ← χ_η), broadcast the Pedersen commits
// C_{i,k}, and emit the per-recipient share-only messages (f_i(j), g_i(j)).
//
// Spec-faithful coefficient distribution (con:pedersen): every coefficient of
// f_i and g_i is short (χ_η), so all commit openings are short and binding holds
// under MSIS over [A|B]. (Share privacy is therefore computational via the commit
// hiding, not information-theoretic Shamir — consistent with what the M-LWE-based
// DKG-PRIV reduction actually provides.)
//
// aRows/bRows are km.a and expandB(mode); evalPoints are the committee's GF(q)
// Shamir points (parallel to the recipient list); rng supplies the χ_η seeds.
func VSSDealerRound1(mode Mode, aRows, bRows []polyVec, dealerID NodeID, evalPoints []uint32, threshold int, rng io.Reader) (VSSCommit, []VSSShare, error) {
	_, L, eta := modeShape(mode)
	if L == 0 {
		return VSSCommit{}, nil, ErrUnknownMode
	}
	if threshold < 1 {
		return VSSCommit{}, nil, ErrInvalidThreshold
	}
	n := len(evalPoints)
	if n < threshold {
		return VSSCommit{}, nil, ErrInvalidThreshold
	}

	// Two independent χ_η seeds (domain-separated) for f_i and g_i coefficients.
	var seedF, seedG [64]byte
	if _, err := io.ReadFull(rng, seedF[:]); err != nil {
		return VSSCommit{}, nil, ErrShortRand
	}
	if _, err := io.ReadFull(rng, seedG[:]); err != nil {
		return VSSCommit{}, nil, ErrShortRand
	}

	// Sample fCoeffs[k], gCoeffs[k] ∈ R_q^ℓ (k = 0..t−1), normalized to [0,q).
	fCoeffs := make([]polyVec, threshold)
	gCoeffs := make([]polyVec, threshold)
	for k := 0; k < threshold; k++ {
		fCoeffs[k] = make(polyVec, L)
		gCoeffs[k] = make(polyVec, L)
		for l := 0; l < L; l++ {
			nonce := uint16(k*L + l)
			polyDeriveUniformLeqEta(&fCoeffs[k][l], &seedF, nonce, eta)
			fCoeffs[k][l].normalize()
			polyDeriveUniformLeqEta(&gCoeffs[k][l], &seedG, nonce, eta)
			gCoeffs[k][l].normalize()
		}
	}

	// Commit to each coefficient pair: C_{i,k} = A·c_{i,k} + B·r_{i,k}.
	commits := make([]polyVec, threshold)
	for k := 0; k < threshold; k++ {
		commits[k] = modulePedersenCommit(aRows, bRows, fCoeffs[k], gCoeffs[k])
	}

	// Deal: evaluate (f_i(j), g_i(j)) at each recipient's Shamir point — share only.
	shares := make([]VSSShare, n)
	for p := 0; p < n; p++ {
		shares[p] = VSSShare{
			DealerID:   dealerID,
			EvalPoint:  evalPoints[p],
			S1Share:    evalPolyVecAt(fCoeffs, evalPoints[p]),
			BlindShare: evalPolyVecAt(gCoeffs, evalPoints[p]),
		}
	}

	// Wipe the dealer's secret sampling seeds; the sharing polynomials live only
	// as the per-recipient shares + the public commits from here on.
	for i := range seedF {
		seedF[i] = 0
		seedG[i] = 0
	}
	return VSSCommit{DealerID: dealerID, Commits: commits}, shares, nil
}

// evalPolyVecAt evaluates the degree-(t−1) poly-vector polynomial whose
// coefficients are coeffs[0..t−1] (each ∈ R_q^ℓ) at GF(q) point x, coefficient-
// wise: out[l][j] = Σ_k coeffs[k][l][j]·x^k mod q. Horner from the top degree.
func evalPolyVecAt(coeffs []polyVec, x uint32) polyVec {
	t := len(coeffs)
	if t == 0 {
		return nil
	}
	L := len(coeffs[0])
	out := make(polyVec, L)
	xu := uint64(x)
	for l := 0; l < L; l++ {
		for j := 0; j < mldsaN; j++ {
			var acc uint64
			for k := t - 1; k >= 0; k-- {
				acc = (acc*xu + uint64(coeffs[k][l][j])) % shamirPrimeQ
			}
			out[l][j] = uint32(acc)
		}
	}
	return out
}

// evalCommitAt evaluates Σ_k x^k · C_{i,k} ∈ R_q^k coefficient-wise over GF(q),
// the Round-2 verification right-hand side. commits[k] = C_{i,k} (length K).
func evalCommitAt(commits []polyVec, x uint32) polyVec {
	t := len(commits)
	if t == 0 {
		return nil
	}
	K := len(commits[0])
	out := make(polyVec, K)
	xu := uint64(x)
	for m := 0; m < K; m++ {
		for j := 0; j < mldsaN; j++ {
			var acc uint64
			for k := t - 1; k >= 0; k-- {
				acc = (acc*xu + uint64(commits[k][m][j])) % shamirPrimeQ
			}
			out[m][j] = uint32(acc)
		}
	}
	return out
}

// VerifyVSSShare is the Round-2 Pedersen identity check for one received share:
// A·f_i(j) + B·g_i(j) =? Σ_k j^k C_{i,k}. It is exact (both sides Z_q-linear) and
// scans every coefficient slot (no early exit) for constant-time comparison.
// A false result is evidence for a ComplaintBadDelivery naming the dealer.
func VerifyVSSShare(aRows, bRows []polyVec, share VSSShare, commit VSSCommit) bool {
	lhs := modulePedersenCommit(aRows, bRows, share.S1Share, share.BlindShare)
	rhs := evalCommitAt(commit.Commits, share.EvalPoint)
	if len(lhs) != len(rhs) {
		return false
	}
	var diff uint32
	for m := range lhs {
		for j := 0; j < mldsaN; j++ {
			diff |= lhs[m][j] ^ rhs[m][j]
		}
	}
	return diff == 0
}

// AggregateVSSShares aggregates the verified shares a party received from every
// dealer into its own s1 share s_j = Σ_i f_i(j) (returned as an AlgShare) and its
// blinding share u_j = Σ_i g_i(j). Every share must carry the same EvalPoint
// (this party's). NO seed, s1, or sk is formed — only a GF(q) sum of shares.
func AggregateVSSShares(mode Mode, myID NodeID, shares []VSSShare) (*AlgShare, polyVec, error) {
	_, L, _ := modeShape(mode)
	if L == 0 {
		return nil, nil, ErrUnknownMode
	}
	if len(shares) == 0 {
		return nil, nil, ErrNotEnoughShares
	}
	evalPoint := shares[0].EvalPoint
	s1 := make(polyVec, L)
	u := make(polyVec, L)
	for _, sh := range shares {
		if sh.EvalPoint != evalPoint {
			return nil, nil, ErrAlgShareShape
		}
		if len(sh.S1Share) != L || len(sh.BlindShare) != L {
			return nil, nil, ErrAlgShareShape
		}
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				s1[l][j] = uint32((uint64(s1[l][j]) + uint64(sh.S1Share[l][j])) % shamirPrimeQ)
				u[l][j] = uint32((uint64(u[l][j]) + uint64(sh.BlindShare[l][j])) % shamirPrimeQ)
			}
		}
	}
	return &AlgShare{NodeID: myID, EvalPoint: evalPoint, S1Share: s1, Mode: mode}, u, nil
}

// AggregateVSSCommits aggregates the public Round-1 commits into the joint public
// commit t = Σ_i C_{i,0} ∈ R_q^k. This is A·s1 + B·u by construction.
func AggregateVSSCommits(mode Mode, commits []VSSCommit) (polyVec, error) {
	K, _, _ := modeShape(mode)
	if K == 0 {
		return nil, ErrUnknownMode
	}
	if len(commits) == 0 {
		return nil, ErrNotEnoughShares
	}
	t := make(polyVec, K)
	for _, c := range commits {
		if len(c.Commits) == 0 || len(c.Commits[0]) != K {
			return nil, ErrAlgShareShape
		}
		c0 := c.Commits[0] // C_{i,0}
		for m := 0; m < K; m++ {
			for j := 0; j < mldsaN; j++ {
				t[m][j] = uint32((uint64(t[m][j]) + uint64(c0[m][j])) % shamirPrimeQ)
			}
		}
	}
	return t, nil
}

// PedersenVSSObstruction is the COMPUTED obstruction to forming a signable
// FIPS-204 key from the v0.2 commit t = A·s1 + B·u. Every field is derived from
// the FIPS-204 bounds + the M-LWE pseudo-uniformity of B·u; the test pins them.
type PedersenVSSObstruction struct {
	Mode Mode

	Eta    uint32 // η
	Beta   uint32 // β = τ·η — the boundary-clearance bound ‖c·s2‖∞ ≤ β
	Gamma2 uint32 // γ2 — HighBits bucket half-width
	Q      uint32 // the modulus q

	// s2 = B·u with B uniform is M-LWE-indistinguishable from uniform (thm:outind
	// proof), so its worst-case ℓ∞ is the full half-modulus.
	S2LinfPseudoUniform uint32 // ≈ (q−1)/2 — worst-case ‖B·u‖∞
	BoundaryCovers      uint32 // β — the shift the FIPS/BCC hint can absorb

	// Verdict: a signable key needs S2LinfPseudoUniform ≤ BoundaryCovers, which is
	// false by ~5 orders of magnitude (q/2 vs τ·η).
	ByteFIPSReachable bool
}

// assessPedersenVSSFIPS computes the FIPS-204 obstruction for the Pedersen-VSS
// commit at `mode`. ByteFIPSReachable is always false in the BCC-proven scope:
// s2 = B·u is pseudo-uniform (‖·‖∞ ≈ q/2) while the hint can only absorb ‖c·s2‖∞
// ≤ β. ok=false for parameter sets outside BCC scope (ML-DSA-44).
func assessPedersenVSSFIPS(mode Mode) (PedersenVSSObstruction, bool) {
	gamma2, beta, _, ok := bccParams(mode)
	if !ok {
		return PedersenVSSObstruction{}, false
	}
	_, _, eta := modeShape(mode)
	o := PedersenVSSObstruction{
		Mode:                mode,
		Eta:                 eta,
		Beta:                beta,
		Gamma2:              gamma2,
		Q:                   mldsaQ,
		S2LinfPseudoUniform: (mldsaQ - 1) / 2,
		BoundaryCovers:      beta,
	}
	o.ByteFIPSReachable = o.S2LinfPseudoUniform <= o.BoundaryCovers // structurally false
	return o, true
}

// PedersenVSSFormFIPSKey is Round-3's key-formation step. It takes the aggregated
// public commit t = Σ_i C_{i,0} and FAILS CLOSED: t = A·s1 + B·u cannot be a
// signable FIPS-204 key because the implied s2 = B·u is pseudo-uniform. It
// returns the COMPUTED obstruction alongside ErrPedersenVSSNotByteFIPS so the
// caller has the derived evidence, never a fabricated key. (Contrast: the sound
// dealing layer above is what a future short-replicated-share construction would
// reuse for verifiable dealing; only this final aggregation is barred.)
func PedersenVSSFormFIPSKey(mode Mode, t polyVec) (*PedersenVSSObstruction, error) {
	K, _, _ := modeShape(mode)
	if K == 0 {
		return nil, ErrUnknownMode
	}
	if len(t) != K {
		return nil, ErrAlgShareShape
	}
	o, ok := assessPedersenVSSFIPS(mode)
	if !ok {
		return nil, ErrBCCParamSet
	}
	return &o, ErrPedersenVSSNotByteFIPS
}
