// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_cscp_dkg.go — Phase-3b CSCP lift (luxfi/dkg rewire, step 4).
//
// The TALUS Phase-B secure-HighBits boundary-count circuit (CarryCompare) now
// runs on the SHARED, MALICIOUS-secure luxfi/dkg `cscp` package instead of
// pulsar's in-house semi-honest copy. This is the keystone deduplication: the
// boundary-count fold, additive→Shamir reshare, bit-decomposition by mask-open,
// and prefix less-than were carried in BOTH corona and pulsar; luxfi/dkg now
// owns ONE malicious-secure implementation and both consume it.
//
// SECURITY UPGRADE. pulsar's `cscpSecureHighBitsVec` (talus_cscp.go) is
// semi-honest: it realises the ideal secure HighBits but assumes parties follow
// the protocol. `cscp.SecureHighBitsVec` is malicious-secure (committed
// re-shares + identifiable-open + batched bit-validity, per luxfi/dkg's CSCP
// closers a/b/c). The arithmetic on honest inputs is byte-identical (both proven
// == FIPS-204 Decompose over all 8 380 417 residues, m=16 buckets), so the
// stock-verifiable signature is unchanged; the deviation surface shrinks.
//
// FAITHFUL TYPE BRIDGE. The circuit operates per coefficient over GF(q)
// (q = 8 380 417, N = 256), never in the NTT domain and never touching the
// public A/B matrices. pulsar's commitment shares are length-K poly-vectors in
// STANDARD coefficient form, already normalize()'d to [0, q) by
// CEFCommitmentShare. The bridge is therefore a direct coefficient copy into the
// dkg ring's Coeffs[0] lane — exactly the conversion the pin-4 KAT
// (dkg_vss_kat_test.go) proved carries pulsar's arithmetic faithfully.
//
// ML-DSA-87 NOTE. luxfi/dkg ships ring.MLDSA65() (K=6) but not an MLDSA87()
// profile. FIPS-204 fixes q = 8 380 417, N = 256, and γ2 = 261888 for BOTH
// ML-DSA-65 and ML-DSA-87 — only the module dimension K differs (6 vs 8). The
// boundary-count circuit needs ONLY (field, K, γ2); it never reads A/B and
// cscp.SecureHighBitsVec does not Validate() the profile. So ML-DSA-87 reuses
// ML-DSA-65's GF(q) ring with K overridden to 8. The ring (the only shared,
// read-only object) is identical; the shallow copy isolates the K field.

import (
	"io"

	dkgcscp "github.com/luxfi/dkg/cscp"
	dkgmpc "github.com/luxfi/dkg/mpc"
	dkgring "github.com/luxfi/dkg/ring"
)

// cscpProfileForMode returns the dkg ring profile carrying the GF(q) field and
// the commit-row count K for the given ML-DSA parameter set. ML-DSA-65 uses the
// stock dkg profile directly; ML-DSA-87 reuses its ring with K=8 (see header).
func cscpProfileForMode(mode Mode) (*dkgring.Profile, error) {
	base, err := dkgring.MLDSA65()
	if err != nil {
		return nil, err
	}
	k, _, _ := modeShape(mode)
	if k == 0 {
		return nil, ErrBCCParamSet
	}
	if k == base.K {
		return base, nil
	}
	p := *base // shallow copy: shares only the read-only GF(q) ring
	p.K = k
	return &p, nil
}

// cscpSecureHighBitsVecDKG is the production CarryCompare. It computes
// w1 = HighBits(Σ_i g_i mod q) per coefficient over GF(q) via the malicious-
// secure luxfi/dkg cscp package, so NO node and NO process ever forms the joint
// commitment w, the low part w0, or the aggregate low sum A0. It is the
// byte-faithful, malicious-secure replacement for the in-house semi-honest
// cscpSecureHighBitsVec; the in-house ideal cefIdealSecureHighBits survives only
// as the TEST ORACLE proving the two agree.
//
// Inputs match CEFComputeW1's contract exactly: commitShares are the per-party
// ADDITIVE commitment shares {g_i} (Lagrange already folded by
// CEFCommitmentShare, so Σ_i g_i = w), evalPoints[i] is party i's GF(q) Shamir
// x-coordinate for the internal additive→Shamir reshare, and N ≥ 2T−1 is
// required (the malicious reshare runs a BGW multiply).
func cscpSecureHighBitsVecDKG(mode Mode, commitShares []polyVec, evalPoints []uint32, threshold int, rng io.Reader) (polyVec, error) {
	profile, err := cscpProfileForMode(mode)
	if err != nil {
		return nil, err
	}
	R := profile.Ring
	K := profile.K
	n := len(commitShares)
	if n == 0 || len(evalPoints) != n {
		return nil, ErrCEFShape
	}

	// pulsar polyVec (standard coeff form, [0, q)) -> dkg ring.Vector. The
	// conversion is a direct coefficient copy (no NTT): the circuit is a
	// per-coefficient GF(q) computation.
	ringShares := make([]dkgring.Vector, n)
	for i := 0; i < n; i++ {
		if len(commitShares[i]) != K {
			return nil, ErrCEFShape
		}
		v := dkgring.NewVec(R, K)
		for k := 0; k < K; k++ {
			for j := 0; j < mldsaN; j++ {
				v[k].Coeffs[0][j] = uint64(commitShares[i][k][j])
			}
		}
		ringShares[i] = v
	}

	eval := make([]dkgmpc.Elem, n)
	for i := range evalPoints {
		eval[i] = dkgmpc.Elem(evalPoints[i])
	}

	w1ring, _, err := dkgcscp.SecureHighBitsVec(profile, dkgcscp.MLDSAGamma2, ringShares, eval, threshold, rng, nil)
	if err != nil {
		return nil, err
	}

	// dkg ring.Vector (w1, K polys with coefficients in [0, 16)) -> pulsar polyVec.
	w1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			w1[k][j] = uint32(w1ring[k].Coeffs[0][j])
		}
	}
	return w1, nil
}
