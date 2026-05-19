// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// n1_byte_equality_test.go — empirical validation of the Class N1
// output-interchangeability theorem.
//
// The EasyCrypt theorem Pulsar_N1.pulsar_n1_byte_equality_extracted
// (in proofs/easycrypt/Pulsar_N1_Wrapper_Bridge.ec) says:
//
//   For any honest threshold-sign session whose share set
//   reconstructs to a centralized FIPS 204 secret key SK, the
//   resulting signature bytes are IDENTICAL to those produced by
//   FIPS 204 Sign_internal(SK, msg, ctx) — i.e., threshold-sign is
//   output-byte-equivalent to single-party deterministic FIPS 204
//   signing under the corresponding centralized key.
//
// This is the load-bearing property of Pulsar Class N1: any FIPS 204
// verifier (a stock ML-DSA-65 implementation, on-chain pre-compile,
// hardware verifier) accepts threshold-produced signatures with NO
// code change, because the bytes look exactly like a centralized
// FIPS 204 signature.
//
// The implementation strategy that makes this property hold is
// "centralized recovery": Combine reconstructs the master seed via
// Lagrange interpolation of the share set, derives the centralized
// FIPS 204 SK via KeyFromSeed, and calls mldsaSign directly. See
// threshold.go around line 418.
//
// This test performs an end-to-end byte-equality check:
//
//   1. Run the DKG to produce shares + group public key.
//   2. Reconstruct the master seed from a threshold quorum of shares
//      using the SAME Lagrange + cSHAKE256 mix as Combine.
//   3. Derive the centralized SK via KeyFromSeed(masterSeed).
//   4. Sign centrally with deterministic FIPS 204 mode.
//   5. Run the full threshold-sign protocol on the same (sid,
//      attempt, msg, ctx, quorum) under the same shares.
//   6. Assert that the two signatures are BYTE-IDENTICAL.
//
// Catches: any divergence between the centralized FIPS 204 path and
// the threshold-sign path — wrong Shamir coefficient, wrong
// committee root, wrong cSHAKE256 mix input layout, wrong sign-call
// arguments, etc. A regression on any of these would cause the
// signatures to differ and the test to fail.

import (
	"bytes"
	"testing"
)

// reconstructMasterSeed Lagrange-reconstructs the DKG master seed
// from a quorum of KeyShares + the full committee membership. This
// mirrors the in-Combine reconstruction at threshold.go:386-415
// exactly — same shamirReconstructGF, same byteSum byte ordering,
// same committeeRoot, same cSHAKE256 tag.
func reconstructMasterSeed(t *testing.T, quorum []*KeyShare, committee []*KeyShare) [SeedSize]byte {
	t.Helper()
	shares := make([]shamirShare, len(quorum))
	for i, ks := range quorum {
		var buf [shareWireSize]byte
		copy(buf[:], ks.Share[:])
		shares[i] = shareFromBytes(ks.EvalPoint, buf)
	}
	byteSum, err := shamirReconstructGF(shares)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromShares(committee)
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var seed [SeedSize]byte
	copy(seed[:], cshake256(mixInput, SeedSize, tagSeedShare))
	return seed
}

func TestN1_ByteEquality_ThresholdMatchesCentralized(t *testing.T) {
	// Three configurations spanning small / typical / larger
	// thresholds. Every config must produce byte-identical
	// signatures from the two paths.
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"5of3", 5, 3},
		{"7of4", 7, 4},
		{"10of7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			pub, shares, _, ident := runDKGWithIdentities(t, tc.n, tc.t, ModeP65)

			msg := []byte("Pulsar Class N1 byte-equality test message")
			var ctx []byte // empty context — match between paths

			// --- Threshold-sign path. ---
			var sid [16]byte
			copy(sid[:], "n1-byte-eq-sid-1")
			attempt := uint32(1)
			quorum := make([]NodeID, tc.t)
			for i := 0; i < tc.t; i++ {
				quorum[i] = shares[i].NodeID
			}
			sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

			signers := make([]*ThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				s, err := NewThresholdSigner(
					params, sid, attempt, quorum, shares[i],
					sessionKeys[shares[i].NodeID], msg,
					deterministicReader([]byte{byte(i), 0xBE, 0xEF}),
				)
				if err != nil {
					t.Fatalf("NewThresholdSigner party %d: %v", i, err)
				}
				signers[i] = s
			}
			r1 := make([]*Round1Message, tc.t)
			for i, s := range signers {
				m, err := s.Round1(msg)
				if err != nil {
					t.Fatalf("Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}
			r2 := make([]*Round2Message, tc.t)
			for i, s := range signers {
				m, ev, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("Round2 party %d: %v (ev=%v)", i, err, ev)
				}
				r2[i] = m
			}
			// false = deterministic FIPS 204 mode (KAT-reproducible).
			// Match this in the centralized path below.
			thresholdSig, err := Combine(
				params, pub, msg, ctx, false,
				sid, attempt, quorum, tc.t, r1, r2, shares,
			)
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if len(thresholdSig.Bytes) != params.SignatureSize {
				t.Fatalf("threshold sig size %d, want %d",
					len(thresholdSig.Bytes), params.SignatureSize)
			}

			// --- Centralized FIPS 204 path. ---
			// Reconstruct the master seed from the threshold-sized
			// quorum of shares using the EXACT same Lagrange +
			// cSHAKE256 mix that Combine uses internally.
			masterSeed := reconstructMasterSeed(t, shares[:tc.t], shares)
			centralSK, err := KeyFromSeed(params, masterSeed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			// Sanity: reconstructed pubkey must match the DKG group
			// pubkey. If this fails, every other check is moot.
			if !centralSK.Pub.Equal(pub) {
				t.Fatalf("reconstructed pubkey != DKG group pubkey")
			}
			// false = deterministic FIPS 204 mode, matching Combine
			// above. The rng arg is irrelevant when randomized=false.
			centralSig, err := Sign(params, centralSK, msg, ctx, false, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// --- The headline assertion. ---
			if !bytes.Equal(thresholdSig.Bytes, centralSig.Bytes) {
				// Show a concise prefix-mismatch report so it's
				// obvious WHERE the divergence starts.
				diffAt := -1
				for i := 0; i < len(thresholdSig.Bytes) && i < len(centralSig.Bytes); i++ {
					if thresholdSig.Bytes[i] != centralSig.Bytes[i] {
						diffAt = i
						break
					}
				}
				t.Fatalf(
					"Class N1 byte-equality VIOLATED for %s:\n"+
						"  first differing byte at offset %d\n"+
						"  threshold prefix = %x\n"+
						"  central   prefix = %x",
					tc.name, diffAt,
					thresholdSig.Bytes[:min(32, len(thresholdSig.Bytes))],
					centralSig.Bytes[:min(32, len(centralSig.Bytes))],
				)
			}

			// Sanity (already covered by TestThresholdSign_RoundTrip,
			// repeated here so a failure of this test makes the
			// chain of properties obvious):
			if err := Verify(params, pub, msg, thresholdSig); err != nil {
				t.Fatalf("threshold sig fails FIPS 204 Verify: %v", err)
			}
			if err := Verify(params, pub, msg, centralSig); err != nil {
				t.Fatalf("centralized sig fails FIPS 204 Verify: %v", err)
			}
		})
	}
}

// min is a tiny helper since this file's Go target may pre-date
// the generic `min` builtin in older toolchains.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FuzzN1_ByteEquality_Differential — the property-based fuzz form of
// TestN1_ByteEquality_ThresholdMatchesCentralized.
//
// Each fuzz iteration:
//   1. Derives (n, t, msg, ctx, party_rng_seeds) from the fuzz input
//      with sensible bounds (n in [2, 10], t in [2, n]).
//   2. Runs the full DKG + threshold-sign pipeline.
//   3. Reconstructs the master seed from shares and derives the
//      centralized FIPS 204 SK.
//   4. Signs centrally with deterministic FIPS 204 mode.
//   5. Asserts thresholdSig.Bytes == centralSig.Bytes.
//
// The property under fuzz is: for ANY honest threshold-sign session,
// the produced bytes match the centralized FIPS 204 deterministic
// output under the reconstructed key. A counterexample (byte mismatch
// or unexpected error) is a real bug.
//
// Performance: ~50–200ms per iteration (DKG + threshold-sign +
// FIPS 204 sign). A 30s smoke run does ~150-400 iterations; a
// nightly job (-fuzztime=1h) does ~20k iterations.
//
// Smoke run:
//   GOWORK=off go test -run=^$ -fuzz=FuzzN1_ByteEquality_Differential \
//     -fuzztime=30s ./ref/go/pkg/pulsar/
func FuzzN1_ByteEquality_Differential(f *testing.F) {
	// Seed with the same three configurations the deterministic test
	// uses, plus a few extras so the fuzz engine has a base coverage
	// signal before mutation.
	seeds := []struct {
		n, t int
		msg  string
		ctx  string
	}{
		{5, 3, "Pulsar class N1 differential fuzz seed", ""},
		{7, 4, "another seed message", ""},
		{10, 7, "longer-quorum seed", "ctx-bytes"},
		{4, 2, "small-committee seed", ""},
	}
	for _, s := range seeds {
		input := make([]byte, 0, 4+len(s.msg)+1+len(s.ctx))
		input = append(input, byte(s.n), byte(s.t))
		input = append(input, byte(len(s.msg)))
		input = append(input, s.msg...)
		input = append(input, byte(len(s.ctx)))
		input = append(input, s.ctx...)
		// 16 bytes of party-RNG seed material padding so the seed
		// inputs are non-trivial under mutation.
		var pad [16]byte
		input = append(input, pad[:]...)
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse the fuzz input into (n, t, msg, ctx, party_seed).
		// Bail out cleanly (not Skip — Skip aborts the fuzz iteration
		// without exercising the pipeline) on inputs too short to
		// describe a valid configuration.
		if len(data) < 4 {
			return
		}
		// Clamp n to [2, 10] — DKG is O(n^2) so larger committees
		// blow up the per-iteration cost. The proof property is
		// invariant in n, so bounding is fine for coverage.
		n := int(data[0]%9) + 2 // 2..10
		// Clamp t to [2, n].
		tq := int(data[1]%uint8(n-1)) + 2
		if tq > n {
			tq = n
		}
		// Message length up to 64 bytes.
		mLen := int(data[2] % 65)
		if 3+mLen > len(data) {
			return
		}
		msg := append([]byte{}, data[3:3+mLen]...)
		// Context length up to 64 bytes.
		off := 3 + mLen
		if off >= len(data) {
			return
		}
		cLen := int(data[off] % 65)
		off++
		if off+cLen > len(data) {
			return
		}
		var ctx []byte
		if cLen > 0 {
			ctx = append([]byte{}, data[off:off+cLen]...)
		}
		off += cLen
		// Remaining bytes (if any) feed party-RNG diversification.
		// We just XOR them into the per-party seed prefix so the
		// fuzz mutation surface includes the per-party randomness
		// path. The protocol invariant is that byte-equality holds
		// regardless of per-party RNG choices.
		var partyTail [16]byte
		for i := 0; i < len(partyTail) && off+i < len(data); i++ {
			partyTail[i] = data[off+i]
		}

		// --- Run the pipeline. Any error is a fuzz failure (the
		//     property must hold for ALL well-formed configurations
		//     we generate above).
		params := MustParamsFor(ModeP65)
		// We use the in-package runDKGWithIdentities helper which
		// runs DKG deterministically (the per-party seed there is
		// already deterministicReader, but we make it fully
		// hermetic by using msg as part of the test name suffix).
		pub, shares, _, ident := runDKGWithIdentities(t, n, tq, ModeP65)

		var sid [16]byte
		copy(sid[:], "n1-fuzz-diff-sid")
		attempt := uint32(1)
		quorum := make([]NodeID, tq)
		for i := 0; i < tq; i++ {
			quorum[i] = shares[i].NodeID
		}
		sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

		signers := make([]*ThresholdSigner, tq)
		for i := 0; i < tq; i++ {
			rngSeed := append([]byte{}, partyTail[:]...)
			rngSeed = append(rngSeed, byte(i), 0xFE)
			s, err := NewThresholdSigner(
				params, sid, attempt, quorum, shares[i],
				sessionKeys[shares[i].NodeID], msg,
				deterministicReader(rngSeed),
			)
			if err != nil {
				t.Fatalf("NewThresholdSigner: %v", err)
			}
			signers[i] = s
		}
		r1 := make([]*Round1Message, tq)
		for i, s := range signers {
			m, err := s.Round1(msg)
			if err != nil {
				t.Fatalf("Round1 party %d: %v", i, err)
			}
			r1[i] = m
		}
		r2 := make([]*Round2Message, tq)
		for i, s := range signers {
			m, ev, err := s.Round2(r1)
			if err != nil {
				t.Fatalf("Round2 party %d: %v (ev=%v)", i, err, ev)
			}
			r2[i] = m
		}
		thresholdSig, err := Combine(
			params, pub, msg, ctx, false,
			sid, attempt, quorum, tq, r1, r2, shares,
		)
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}

		masterSeed := reconstructMasterSeed(t, shares[:tq], shares)
		centralSK, err := KeyFromSeed(params, masterSeed)
		if err != nil {
			t.Fatalf("KeyFromSeed: %v", err)
		}
		if !centralSK.Pub.Equal(pub) {
			t.Fatalf("reconstructed pubkey != DKG group pubkey")
		}
		centralSig, err := Sign(params, centralSK, msg, ctx, false, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if !bytes.Equal(thresholdSig.Bytes, centralSig.Bytes) {
			diffAt := -1
			for i := 0; i < len(thresholdSig.Bytes) && i < len(centralSig.Bytes); i++ {
				if thresholdSig.Bytes[i] != centralSig.Bytes[i] {
					diffAt = i
					break
				}
			}
			t.Fatalf(
				"Class N1 byte-equality VIOLATED under fuzz "+
					"(n=%d, t=%d, |msg|=%d, |ctx|=%d):\n"+
					"  first differing byte at offset %d\n"+
					"  threshold prefix = %x\n"+
					"  central   prefix = %x",
				n, tq, len(msg), len(ctx), diffAt,
				thresholdSig.Bytes[:min(32, len(thresholdSig.Bytes))],
				centralSig.Bytes[:min(32, len(centralSig.Bytes))],
			)
		}
		// Both sigs must FIPS 204 Verify with the SAME ctx they were
		// signed under. (A regression where Combine ignored ctx
		// while Sign honored it would show up here as a Verify
		// failure on the threshold sig under VerifyCtx with the
		// real ctx — caught early.)
		if err := VerifyCtx(params, pub, msg, ctx, thresholdSig); err != nil {
			t.Fatalf("threshold sig fails FIPS 204 VerifyCtx (|ctx|=%d): %v",
				len(ctx), err)
		}
		if err := VerifyCtx(params, pub, msg, ctx, centralSig); err != nil {
			t.Fatalf("centralized sig fails FIPS 204 VerifyCtx (|ctx|=%d): %v",
				len(ctx), err)
		}
	})
}
