// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_ctx_test.go — closure of PULSAR-V04-CTX. Pins:
//
//	1. μ derivation byte-differs across distinct ctx values.
//	2. OrchestrateV03Sign(msg) == OrchestrateV03SignCtx(nil, msg) — the
//	   backwards-compatibility invariant for existing chain certs and
//	   KATs that were minted before ctx-bound threshold sign existed.
//	3. ctx > 255 bytes is rejected at the API boundary with ErrCtxTooLarge
//	   (alias of FIPS 204's ErrCtxTooLong from sign.go).
//	4. Output signature verifies under cloudflare/circl's stock FIPS 204
//	   ML-DSA VerifyCtx — Class N1 byte-equality contract for the ctx-
//	   bound path.
//
// These tests intentionally use stageAlgebraicCtx (a thin sibling of
// stageAlgebraic) so the orchestration path under test is the FULL
// quorum-driven Round1 → Round2W → Round2Sign → AlgebraicAggregateCtx
// loop, NOT a single-party shortcut. The v0.4 deliverable spec
// (BLOCKERS.md PULSAR-V04-CTX) requires this.

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/sha3"
)

// stageAlgebraicCtx is the ctx-aware sibling of stageAlgebraic. Returns
// (sig, pub, setup, shares, identity, r1, r2, err) so the tests below
// can examine intermediate state where useful.
//
// SHARES THE FIXTURE SEED with stageAlgebraic: same master seed (and
// same dealer-rng tag inside the v0.3 family) so empty-ctx output is
// byte-identical to the historical OrchestrateV03Sign path. The
// dealer-RNG tag is forced to the v0.3 byte-shape; the IDENTITY
// fixture is also seeded identically so the per-pair session keys
// match across the two paths.
func stageAlgebraicCtx(t testing.TB, n, threshold int, ctx, msg []byte, sid [16]byte, attempt uint32) (
	*Signature,
	*PublicKey,
	*AlgebraicSetup,
	[]*AlgebraicKeyShare,
	*identityFixture,
	[]*AlgebraicRound1Message,
	[]*AlgebraicRound2Message,
	error,
) {
	t.Helper()
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(n)
	// Identity-fixture seed identical to stageAlgebraic: byte{n, threshold,
	// attempt, 0x03}. This gives byte-identical pairwise session keys so
	// the MACs / commits match across the two paths.
	ident := newIdentityFixture(t, committee, []byte{byte(n), byte(threshold), byte(attempt), 0x03})

	var seed [SeedSize]byte
	// MUST match stageAlgebraic's seed verbatim for empty-ctx
	// backwards-compat byte-equality.
	copy(seed[:], "pulsar-v03-test-master-seed-32!!")
	// Dealer-RNG tag identical to stageAlgebraic so the s_1/s_2/t_0
	// Shamir share polynomials match byte-for-byte.
	dealerRng := deterministicReader([]byte{0x03, 0xDD, byte(n), byte(threshold)})
	setup, shares, err := DealAlgebraicV03Shares(params, committee, threshold, seed, dealerRng)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	for i := range seed {
		seed[i] = 0
	}

	quorum := make([]NodeID, threshold)
	quorumShares := make([]*AlgebraicKeyShare, threshold)
	for i := 0; i < threshold; i++ {
		quorum[i] = shares[i].NodeID
		quorumShares[i] = shares[i]
	}

	allSessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, err := V03QuorumEvalPoints(quorum, shares)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}

	signers := make([]*AlgebraicThresholdSigner, threshold)
	for i := 0; i < threshold; i++ {
		// Per-party RNG seed identical to stageAlgebraic byte-for-byte
		// (final byte 0x03, not 0x04) so empty-ctx output matches the
		// historical v0.3 path bit-for-bit.
		s, err := NewAlgebraicThresholdSignerCtx(params, setup, sid, attempt, quorum, quorumShares[i],
			allSessionKeys[quorum[i]], ctx, msg,
			deterministicReader([]byte{0xFE, byte(i), byte(attempt), 0x03}))
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		if err := s.SetQuorumEvalPoints(evalPoints); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		signers[i] = s
	}

	r1 := make([]*AlgebraicRound1Message, threshold)
	for i, s := range signers {
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("Round1 party %d: %v", i, err)
		}
		r1[i] = m
	}

	r2W := make([]*AlgebraicRound2Message, threshold)
	for i, s := range signers {
		m, _, err := s.Round2W(r1)
		if err != nil {
			t.Fatalf("Round2W party %d: %v", i, err)
		}
		r2W[i] = m
	}

	peerWByParty := make([]map[NodeID]polyVec, threshold)
	K, _, _ := modeShape(ModeP65)
	for i := 0; i < threshold; i++ {
		peerW := make(map[NodeID]polyVec, threshold-1)
		for j := 0; j < threshold; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}

	r2 := make([]*AlgebraicRound2Message, threshold)
	for i, s := range signers {
		m, _, err := s.Round2Sign(r1, peerWByParty[i])
		if err != nil {
			t.Fatalf("Round2Sign party %d: %v", i, err)
		}
		r2[i] = m
	}

	sig, err := AlgebraicAggregateCtx(params, setup, ctx, msg, sid, attempt, quorum, evalPoints,
		threshold, r1, r2, allSessionKeys)
	return sig, setup.Pub, setup, shares, ident, r1, r2, err
}

// muOnly extracts μ for the supplied (tr, ctx, msg) without running
// the full sign loop — used to pin the FIPS 204 §5.4 step-2 encoding.
func muOnly(tr [64]byte, ctx, msg []byte) [64]byte {
	var mu [64]byte
	h := sha3.NewShake256()
	_, _ = h.Write(tr[:])
	_, _ = h.Write([]byte{0x00, byte(len(ctx))})
	_, _ = h.Write(ctx)
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])
	return mu
}

// TestOrchestrateV03SignCtx_Mu_Includes_Ctx pins that μ is sensitive to
// ctx — the prehash differs across distinct ctx values, so a chain cert
// minted under ctx_A cannot be replayed under ctx_B.
func TestOrchestrateV03SignCtx_Mu_Includes_Ctx(t *testing.T) {
	var tr [64]byte
	copy(tr[:], "tr-for-mu-ctx-test--64-bytes-padding-padding-padding-padding-aa")
	msg := []byte("FIPS 204 §5.4 step-2 ctx test")

	mu0 := muOnly(tr, nil, msg)
	mu1 := muOnly(tr, []byte("lux-evm-precompile-mldsa-v1"), msg)
	mu2 := muOnly(tr, []byte("lux-evm-precompile-mldsa-v2"), msg)

	if bytes.Equal(mu0[:], mu1[:]) {
		t.Fatal("μ does not depend on ctx — empty ctx matches non-empty ctx, FIPS 204 §5.4 broken")
	}
	if bytes.Equal(mu1[:], mu2[:]) {
		t.Fatal("μ does not depend on ctx contents — distinct ctx values produce identical μ")
	}

	// Cross-check against the production deriveMuCtx — this MUST match
	// muOnly byte-for-byte because they are mathematically identical
	// (and the production path is the load-bearing one).
	var muProd [64]byte
	deriveMuCtx(tr, []byte("lux-evm-precompile-mldsa-v1"), msg, muProd[:])
	if !bytes.Equal(muProd[:], mu1[:]) {
		t.Fatalf("deriveMuCtx output mismatches reference muOnly:\n  prod = %x\n  ref  = %x", muProd[:8], mu1[:8])
	}

	// Empty-ctx production path matches the nil path (the backwards-
	// compat invariant; consumed by TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign).
	var muEmpty [64]byte
	deriveMuCtx(tr, nil, msg, muEmpty[:])
	if !bytes.Equal(muEmpty[:], mu0[:]) {
		t.Fatalf("deriveMuCtx(nil) mismatches muOnly(nil): %x vs %x", muEmpty[:8], mu0[:8])
	}
	var muEmpty2 [64]byte
	deriveMuCtx(tr, []byte{}, msg, muEmpty2[:])
	if !bytes.Equal(muEmpty2[:], mu0[:]) {
		t.Fatalf("deriveMuCtx([]byte{}) mismatches muOnly(nil): %x vs %x", muEmpty2[:8], mu0[:8])
	}
}

// TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign is the BACKWARDS-COMPAT
// invariant for v0.4. Existing chain certs signed by v0.3 OrchestrateV03Sign
// MUST remain verifiable after the v0.4 ctx-bound aggregator is wired:
//
//	OrchestrateV03Sign(msg) == OrchestrateV03SignCtx(nil, msg)
//	OrchestrateV03Sign(msg) == OrchestrateV03SignCtx([]byte{}, msg)
//
// Held by structural construction (the empty-ctx case in deriveMuCtx
// writes 0x00 0x00 prefix, byte-identical to historical encoding) and
// pinned here by re-deriving a signature under both paths from the
// SAME deterministic RNG seeds.
func TestOrchestrateV03SignCtx_EmptyCtx_MatchesV03Sign(t *testing.T) {
	msg := []byte("v0.4 backwards-compat: empty ctx == historical v0.3")
	var sid [16]byte
	copy(sid[:], "v04-empty-ctx-01")

	params := MustParamsFor(ModeP65)

	// Stage WITHOUT ctx via stageAlgebraic (calls NewAlgebraicThresholdSigner
	// + AlgebraicAggregate, the historical v0.3 path).
	var (
		sigPlain *Signature
		pubPlain *PublicKey
		errPlain error
	)
	for attempt := uint32(0); attempt < 64; attempt++ {
		sigPlain, pubPlain, _, _, _, _, _, errPlain = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if errPlain == nil {
			break
		}
		if errPlain != ErrAlgebraicRestart {
			t.Fatalf("plain attempt %d unexpected: %v", attempt, errPlain)
		}
	}
	if errPlain != nil {
		t.Fatalf("plain path no convergence: %v", errPlain)
	}

	// Stage WITH nil ctx via stageAlgebraicCtx (calls
	// NewAlgebraicThresholdSignerCtx + AlgebraicAggregateCtx).
	var (
		sigNil *Signature
		pubNil *PublicKey
		errNil error
	)
	for attempt := uint32(0); attempt < 64; attempt++ {
		sigNil, pubNil, _, _, _, _, _, errNil = stageAlgebraicCtx(t, 5, 3, nil, msg, sid, attempt)
		if errNil == nil {
			break
		}
		if errNil != ErrAlgebraicRestart {
			t.Fatalf("nil-ctx attempt %d unexpected: %v", attempt, errNil)
		}
	}
	if errNil != nil {
		t.Fatalf("nil-ctx path no convergence: %v", errNil)
	}

	// Pub keys must match (same master seed → same group key).
	if !bytes.Equal(pubPlain.Bytes, pubNil.Bytes) {
		t.Fatal("pub key bytes differ between plain and nil-ctx paths — DKG byte-equality broken")
	}

	// THE BYTE-EQUALITY INVARIANT.
	//
	// Both paths use the SAME master seed, same dealer-RNG tag, same
	// identity-fixture seed, and same per-party RNG seeds. The empty-ctx
	// path therefore feeds EXACTLY the same μ derivation
	// (M' = 0x00 || 0x00 || M) as the historical OrchestrateV03Sign
	// loop. The result MUST be bit-identical wire bytes — anything else
	// signals a μ-encoding regression in deriveMuCtx OR a side-effect
	// in NewAlgebraicThresholdSignerCtx that NewAlgebraicThresholdSigner
	// did not have.
	if !bytes.Equal(sigPlain.Bytes, sigNil.Bytes) {
		t.Fatalf("BACKWARDS-COMPAT BROKEN: empty-ctx sig bytes diverge from historical v0.3:\n  plain  = %x...\n  nilCtx = %x...",
			sigPlain.Bytes[:16], sigNil.Bytes[:16])
	}

	// All four verifiers must accept.
	if err := Verify(params, pubPlain, msg, sigPlain); err != nil {
		t.Fatalf("plain sig fails FIPS 204 Verify: %v", err)
	}
	if err := Verify(params, pubNil, msg, sigNil); err != nil {
		t.Fatalf("nil-ctx sig fails FIPS 204 Verify: %v", err)
	}
	if err := VerifyCtx(params, pubNil, msg, nil, sigNil); err != nil {
		t.Fatalf("nil-ctx sig fails FIPS 204 VerifyCtx(nil): %v", err)
	}
	if err := VerifyCtx(params, pubNil, msg, []byte{}, sigNil); err != nil {
		t.Fatalf("nil-ctx sig fails FIPS 204 VerifyCtx([]byte{}): %v", err)
	}

	// Reproducibility under the SAME deterministic seeds: rerunning
	// stageAlgebraicCtx with empty []byte{} ctx (not nil) yields the
	// same bytes — exercises the len==0 short-circuit in deriveMuCtx.
	var sigEmptySlice *Signature
	var errEmptySlice error
	for attempt := uint32(0); attempt < 64; attempt++ {
		sigEmptySlice, _, _, _, _, _, _, errEmptySlice = stageAlgebraicCtx(t, 5, 3, []byte{}, msg, sid, attempt)
		if errEmptySlice == nil {
			break
		}
		if errEmptySlice != ErrAlgebraicRestart {
			t.Fatalf("empty-slice attempt %d unexpected: %v", attempt, errEmptySlice)
		}
	}
	if errEmptySlice != nil {
		t.Fatalf("empty-slice path no convergence: %v", errEmptySlice)
	}
	if !bytes.Equal(sigNil.Bytes, sigEmptySlice.Bytes) {
		t.Fatalf("nil ctx and []byte{} ctx produce different sig bytes:\n  nil = %x...\n  []  = %x...",
			sigNil.Bytes[:16], sigEmptySlice.Bytes[:16])
	}
}

// TestOrchestrateV03SignCtx_CtxTooLarge_Rejected pins the API-boundary
// guard. A 256-byte ctx (one byte over the FIPS 204 §5.4 limit) MUST be
// rejected with ErrCtxTooLarge — at the constructor, the aggregator,
// and the one-shot OrchestrateV03SignCtx entry point.
func TestOrchestrateV03SignCtx_CtxTooLarge_Rejected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xFA, 0xFA})

	var seed [SeedSize]byte
	copy(seed[:], "ctx-too-large-master-seed-32!!12")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, rand.Reader)
	if err != nil {
		t.Fatalf("DealAlgebraicV03Shares: %v", err)
	}
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	quorumShares := []*AlgebraicKeyShare{shares[0], shares[1], shares[2]}
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	var sid [16]byte
	copy(sid[:], "ctx-too-large01a")
	msg := []byte("hi")
	allSessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	// 256-byte ctx (one over the §5.4 limit).
	tooLarge := make([]byte, 256)
	for i := range tooLarge {
		tooLarge[i] = byte(i)
	}

	// (a) Constructor must refuse.
	_, err = NewAlgebraicThresholdSignerCtx(params, setup, sid, 0, quorum, shares[0],
		allSessionKeys[shares[0].NodeID], tooLarge, msg, nil)
	if err != ErrCtxTooLarge {
		t.Fatalf("NewAlgebraicThresholdSignerCtx 256-byte ctx: got %v want ErrCtxTooLarge", err)
	}

	// (b) Aggregator must refuse.
	_, err = AlgebraicAggregateCtx(params, setup, tooLarge, msg, sid, 0,
		quorum, evalPoints, 3, nil, nil, nil)
	if err != ErrCtxTooLarge {
		t.Fatalf("AlgebraicAggregateCtx 256-byte ctx: got %v want ErrCtxTooLarge", err)
	}

	// (c) Orchestrator must refuse.
	_, err = OrchestrateV03SignCtx(params, setup, tooLarge, msg, sid,
		quorum, quorumShares, evalPoints, allSessionKeys, params.MaxRestart, nil)
	if err != ErrCtxTooLarge {
		t.Fatalf("OrchestrateV03SignCtx 256-byte ctx: got %v want ErrCtxTooLarge", err)
	}

	// 255 bytes is the MAX legal length — must NOT trip the gate.
	// (We won't run the full sign loop here; just verify the constructor
	// accepts the length and proceeds past the validation check.)
	maxLegal := make([]byte, 255)
	for i := range maxLegal {
		maxLegal[i] = byte(i)
	}
	signer, err := NewAlgebraicThresholdSignerCtx(params, setup, sid, 0, quorum, shares[0],
		allSessionKeys[shares[0].NodeID], maxLegal, msg, nil)
	if err != nil {
		t.Fatalf("NewAlgebraicThresholdSignerCtx 255-byte ctx: unexpected %v", err)
	}
	if !bytes.Equal(signer.Ctx, maxLegal) {
		t.Fatal("signer.Ctx not stored verbatim for 255-byte ctx")
	}
}

// TestOrchestrateV03SignCtx_VerifyMatchesFIPS204 is the Class N1
// byte-equality contract for the ctx-bound path: the threshold output
// verifies under cloudflare/circl's stock FIPS 204 mldsa65.Verify with
// the SAME ctx, and is REJECTED with a DIFFERENT ctx (ctx-binding is
// real).
//
// We verify against circl directly (not just our pulsar.VerifyCtx
// wrapper) because the test pins independent verifier compatibility:
// any FIPS 204 implementation holding the group public key bytes
// accepts the result. This is the load-bearing claim that distinguishes
// pulsar v0.4 from "private custom threshold output".
func TestOrchestrateV03SignCtx_VerifyMatchesFIPS204(t *testing.T) {
	ctx := []byte("lux-evm-precompile-mldsa-v1")
	msg := []byte("v0.4 ctx-bound threshold sign — Class N1 contract")
	var sid [16]byte
	copy(sid[:], "v04-fips204-circl")

	var (
		sig *Signature
		pub *PublicKey
		err error
	)
	for attempt := uint32(0); attempt < 64; attempt++ {
		sig, pub, _, _, _, _, _, err = stageAlgebraicCtx(t, 5, 3, ctx, msg, sid, attempt)
		if err == nil {
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatalf("no convergence within 64 attempts: %v", err)
	}

	params := MustParamsFor(ModeP65)
	if len(sig.Bytes) != params.SignatureSize {
		t.Fatalf("sig.Bytes length %d != FIPS 204 SignatureSize %d", len(sig.Bytes), params.SignatureSize)
	}

	// (1) pulsar's own VerifyCtx accepts (msg, ctx) and rejects (msg, ctx').
	if err := VerifyCtx(params, pub, msg, ctx, sig); err != nil {
		t.Fatalf("pulsar VerifyCtx accepts correct ctx: %v", err)
	}
	if err := VerifyCtx(params, pub, msg, []byte("different-ctx"), sig); err == nil {
		t.Fatal("pulsar VerifyCtx accepted WRONG ctx — ctx binding broken")
	}
	if err := VerifyCtx(params, pub, msg, nil, sig); err == nil {
		t.Fatal("pulsar VerifyCtx accepted EMPTY ctx for signature signed under non-empty ctx — ctx binding broken")
	}

	// (2) cloudflare/circl's stock FIPS 204 mldsa65.Verify accepts the
	// same sig under the same (pub, msg, ctx). This is the INDEPENDENT
	// verifier check — Class N1 byte-equality is real if any FIPS 204
	// verifier accepts the bytes.
	var circlPk mldsa65.PublicKey
	var pkBuf [mldsa65.PublicKeySize]byte
	if len(pub.Bytes) != mldsa65.PublicKeySize {
		t.Fatalf("pub.Bytes length %d != circl PublicKeySize %d", len(pub.Bytes), mldsa65.PublicKeySize)
	}
	copy(pkBuf[:], pub.Bytes)
	circlPk.Unpack(&pkBuf)
	if !mldsa65.Verify(&circlPk, msg, ctx, sig.Bytes) {
		t.Fatal("circl FIPS 204 mldsa65.Verify rejected v0.4 ctx-bound threshold signature — N1 contract broken")
	}
	if mldsa65.Verify(&circlPk, msg, []byte("different-ctx"), sig.Bytes) {
		t.Fatal("circl FIPS 204 mldsa65.Verify accepted WRONG ctx — ctx binding broken")
	}
	if mldsa65.Verify(&circlPk, msg, nil, sig.Bytes) {
		t.Fatal("circl FIPS 204 mldsa65.Verify accepted EMPTY ctx for non-empty-ctx sig — ctx binding broken")
	}

	// (3) The same Round-1/Round-2 transcript bytes under a DIFFERENT
	// ctx at the aggregator MUST NOT yield a valid signature. This pins
	// signer/aggregator ctx parity at the algebraic level.
	for attempt := uint32(0); attempt < 64; attempt++ {
		sigA, pubA, _, _, _, r1, r2, errA := stageAlgebraicCtx(t, 5, 3, ctx, msg, sid, attempt)
		if errA == ErrAlgebraicRestart {
			continue
		}
		if errA != nil {
			t.Fatalf("stageA: %v", errA)
		}
		// Re-aggregate the SAME r1/r2 under a DIFFERENT ctx.
		quorum := []NodeID{r1[0].NodeID, r1[1].NodeID, r1[2].NodeID}
		var setupA *AlgebraicSetup
		// Reconstruct via re-stage to get setup+evalPoints (cheap).
		_, _, setupA, sharesA, _, _, _, _ := stageAlgebraicCtx(t, 5, 3, ctx, msg, sid, attempt)
		evalPoints, _ := V03QuorumEvalPoints(quorum, sharesA)
		identA := newIdentityFixture(t, makeCommittee(5), []byte{5, 3, byte(attempt), 0x04})
		sessionKeysA := identA.quorumSessionKeys(t, quorum, sid, msg)
		sigB, errB := AlgebraicAggregateCtx(params, setupA, []byte("different-ctx-at-agg"), msg, sid, attempt,
			quorum, evalPoints, 3, r1, r2, sessionKeysA)
		// EITHER the re-aggregate trips norms (restart) OR it produces
		// a sig that fails Verify under either ctx — both outcomes mean
		// the aggregator's ctx is bound to its output.
		switch {
		case errB == ErrAlgebraicRestart:
			// OK — aggregator-side ctx mismatch broke the σ derivation
			// enough to trip the rejection check.
		case errB == nil:
			// Should not verify under EITHER ctx.
			if mldsa65.Verify(&circlPk, msg, ctx, sigB.Bytes) {
				t.Fatal("ctx-mismatch agg sig verified under original ctx — signer/aggregator ctx parity not enforced")
			}
			if mldsa65.Verify(&circlPk, msg, []byte("different-ctx-at-agg"), sigB.Bytes) {
				t.Fatal("ctx-mismatch agg sig verified under aggregator ctx — signer/aggregator ctx parity not enforced (signer-side μ leak)")
			}
		default:
			// Anything else — MAC failures etc — pin no false positives.
			t.Logf("agg-side ctx mismatch produced %v (non-restart, non-success) — acceptable", errB)
		}
		_ = sigA
		_ = pubA
		break
	}
}
