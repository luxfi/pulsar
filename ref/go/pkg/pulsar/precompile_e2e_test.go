// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// precompile_e2e_test.go — Class N1 manifesto closure for the EVM
// precompile context.
//
// The Lux Pulsar EVM precompile (at 0x012204, code in
// github.com/luxfi/precompile/pulsar) verifies signatures with the
// FIPS 204 context string `lux-evm-precompile-pulsar-v1`. The Class
// N1 claim is that a threshold-Combine output verifies as a single-
// party FIPS 204 ML-DSA signature under the SAME ctx — i.e. the
// signature bytes flow unchanged through:
//
//	(DKG) -> (Round1 + Round2) -> (Combine, ctx=PRECOMPILE_CTX) ->
//	      -> mldsa65.Verify(pk, M, ctx=PRECOMPILE_CTX, sig)        // raw FIPS 204
//	      -> pulsar.VerifyCtx(params, pk, M, ctx, sig)            // wrapper
//
// Both verifiers MUST accept. If either rejects, the precompile is
// not interchangeable with single-party ML-DSA at this ctx, and the
// Class N1 manifesto is empirically false.
//
// CRIT-2 closure: prior to this test, every threshold round-trip
// passed ctx=nil and verified under the empty context. The
// precompile never appeared in a test, so the ctx-propagation
// guarantee (Combine -> mldsaSign -> SignTo's ctx argument) was
// unverified end-to-end.

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// precompileCtx mirrors github.com/luxfi/precompile/pulsar.precompileCtx
// exactly. Keeping a local copy avoids importing the precompile (which
// would create a dependency cycle pulsar-m <-> precompile); the byte
// string is the load-bearing value, not the import.
var precompileCtx = []byte("lux-evm-precompile-pulsar-v1")

// TestPrecompile_E2E_LargeCombine_FIPS204_VerifyCtx is the parallel
// Class N1 manifesto closure for the GF(q) (wide-committee) path.
//
// Same shape as the GF(257) test above, but uses LargeDKGSession /
// LargeThresholdSigner / LargeCombine. The precompile dispatches to
// the same FIPS 204 verifier regardless of which Combine path the
// quorum used to produce the signature.
func TestPrecompile_E2E_LargeCombine_FIPS204_VerifyCtx(t *testing.T) {
	const n, threshold = 3, 2
	params := MustParamsFor(ModeP65)
	committee := makeLargeCommittee(n)
	ident := newIdentityFixture(t, committee, []byte("precompile-large"))

	// ---- DKG ----
	sessions := make([]*LargeDKGSession, n)
	for i := 0; i < n; i++ {
		rng := deterministicReader([]byte{byte(i), 'D', 'K', 'G', 'L'})
		s, err := NewLargeDKGSession(params, committee, threshold, committee[i], ident.keys[committee[i]], ident.directory, rng)
		if err != nil {
			t.Fatalf("NewLargeDKGSession party %d: %v", i, err)
		}
		sessions[i] = s
	}
	r1 := make([]*LargeDKGRound1Msg, n)
	for i, s := range sessions {
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("DKG Round1 party %d: %v", i, err)
		}
		r1[i] = m
	}
	r2 := make([]*LargeDKGRound2Msg, n)
	for i, s := range sessions {
		m, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("DKG Round2 party %d: %v", i, err)
		}
		r2[i] = m
	}
	outs := make([]*LargeDKGOutput, n)
	for i, s := range sessions {
		out, err := s.Round3(r1, r2)
		if err != nil {
			t.Fatalf("DKG Round3 party %d: %v", i, err)
		}
		if out.AbortEvidence != nil {
			t.Fatalf("DKG party %d aborted: %s", i, out.AbortEvidence.Kind)
		}
		outs[i] = out
	}
	groupPK := outs[0].GroupPubkey

	// ---- Threshold sign ----
	quorum := committee[:threshold]
	msg := []byte("pulsar large threshold -> precompile ctx -> FIPS 204")
	var sid [16]byte
	copy(sid[:], "precompile-lg-01")
	attempt := uint32(0)

	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*LargeThresholdSigner, threshold)
	for i := 0; i < threshold; i++ {
		rng := deterministicReader([]byte{byte(i), 'L', 'P', 'C'})
		ts, err := NewLargeThresholdSigner(params, sid, attempt, quorum, outs[i].SecretShare, sessionKeys[committee[i]], msg, rng)
		if err != nil {
			t.Fatalf("NewLargeThresholdSigner party %d: %v", i, err)
		}
		signers[i] = ts
	}
	tsR1 := make([]*LargeRound1Message, threshold)
	for i, ts := range signers {
		m, err := ts.Round1(msg)
		if err != nil {
			t.Fatalf("Sign Round1 party %d: %v", i, err)
		}
		tsR1[i] = m
	}
	tsR2 := make([]*LargeRound2Message, threshold)
	for i, ts := range signers {
		m, ev, err := ts.Round2(tsR1)
		if err != nil {
			t.Fatalf("Sign Round2 party %d: %v (ev=%+v)", i, err, ev)
		}
		tsR2[i] = m
	}

	allShares := make([]*LargeKeyShare, n)
	for i := 0; i < n; i++ {
		allShares[i] = outs[i].SecretShare
	}

	sig, err := LargeCombine(params, groupPK, msg, precompileCtx, false, sid, attempt, quorum, threshold, tsR1, tsR2, allShares)
	if err != nil {
		t.Fatalf("LargeCombine with precompileCtx: %v", err)
	}
	if len(sig.Bytes) != params.SignatureSize {
		t.Fatalf("signature size %d, want %d", len(sig.Bytes), params.SignatureSize)
	}

	// (a) Raw FIPS 204 verify.
	var pkP65 mldsa65.PublicKey
	var pkBuf [mldsa65.PublicKeySize]byte
	copy(pkBuf[:], groupPK.Bytes)
	pkP65.Unpack(&pkBuf)
	if !mldsa65.Verify(&pkP65, msg, precompileCtx, sig.Bytes) {
		t.Fatalf("FIPS 204 mldsa65.Verify rejected LargeCombine signature under precompile ctx — Class N1 manifesto FALSE for GF(q) path")
	}

	// (b) Package wrapper VerifyCtx.
	if err := VerifyCtx(params, groupPK, msg, precompileCtx, sig); err != nil {
		t.Fatalf("pulsar.VerifyCtx rejected LargeCombine signature under precompile ctx: %v", err)
	}

	// Negative control: empty ctx must NOT accept this signature.
	if mldsa65.Verify(&pkP65, msg, nil, sig.Bytes) {
		t.Fatalf("FIPS 204 verify accepted precompile-ctx LargeCombine sig under empty ctx — ctx not propagated")
	}
	if err := Verify(params, groupPK, msg, sig); err == nil {
		t.Fatalf("pulsar.Verify (empty ctx) accepted precompile-ctx LargeCombine sig — ctx not propagated")
	}
}
