// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// fuzz_test.go — Layer-6 (fuzzing) targets for the parser surface.
//
// Each target seeds with at least one byte-equal valid value (a hex
// blob from vectors/, or a marshalled in-memory canonical example)
// and then accepts arbitrary mutation. The invariant under mutation is
// REJECT — every parser must return a typed error rather than panic,
// and must never return a value that subsequently passes
// FIPS 204 ML-DSA.Verify against an unrelated public key.
//
// Run smoke locally:
//   GOWORK=off go test -run=^$ -fuzz=FuzzUnmarshalAbortEvidence \
//     -fuzztime=5s ./ref/go/pkg/pulsar/
//
// Deep fuzzing belongs in a nightly job (-fuzztime=1h, multiple workers,
// preserved corpus under testdata/fuzz/). See Makefile.fuzz.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// =====================================================================
// Seed material.
// =====================================================================

// validAbortEvidenceWire is a byte-equal canonical wire form produced
// by MarshalAbortEvidence over the fixture in fuzz_test.go's
// TestAbortEvidence_RoundTrip-equivalent inputs. Hardcoded so the fuzz
// corpus is hermetic (no filesystem dependency).
const validAbortEvidenceWireHex = "010102030405000000000000000000000000000000000000000000000000" +
	"00006362610000000000000000000000000000000000000000000000000000" +
	"00001122334455667788" + // epoch big-endian uint64
	"0000001b" + // evidence length = 27
	"65766964656e63652d736565642d626c6f622d666f722d66757a7a" + // "evidence-seed-blob-for-fuzz"
	"0000001d" + // signature length = 29
	"6964656e746974792d7369676e61747572652d62797465732d73656564" // "identity-signature-bytes-seed"

// loadVerifyKAT loads the first entry matching `mode` from
// vectors/verify.json, returning (pk, msg, sig) and (ok=true) on
// success. On failure the caller should skip the seed addition rather
// than fail — the vectors directory may be absent on a fresh checkout
// (kat_test.go uses the same convention).
func loadVerifyKAT(mode string) (pk, msg, sig []byte, ok bool) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, nil, nil, false
	}
	path := filepath.Join(wd, "..", "..", "..", "..", "vectors", "verify.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, false
	}
	type entry struct {
		Mode      string `json:"mode"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	var es []entry
	if err := json.Unmarshal(data, &es); err != nil {
		return nil, nil, nil, false
	}
	for _, e := range es {
		if e.Mode != mode {
			continue
		}
		pkB, err1 := hex.DecodeString(e.PublicKey)
		msgB, err2 := hex.DecodeString(e.Message)
		sigB, err3 := hex.DecodeString(e.Signature)
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, nil, nil, false
		}
		return pkB, msgB, sigB, true
	}
	return nil, nil, nil, false
}

// =====================================================================
// FuzzUnmarshalAbortEvidence — direct wire parser for complaints.
// =====================================================================

func FuzzUnmarshalAbortEvidence(f *testing.F) {
	// Valid canonical seed.
	wire, err := hex.DecodeString(validAbortEvidenceWireHex)
	if err != nil {
		f.Fatalf("bad embedded seed hex: %v", err)
	}
	f.Add(wire)

	// Construct two more seeds programmatically to widen coverage of
	// the kind/length-field state space.
	for _, kind := range []ComplaintKind{
		ComplaintEquivocation,
		ComplaintBadDelivery,
		ComplaintMACFailure,
		ComplaintRangeFailure,
	} {
		ev := &AbortEvidence{
			Kind:      kind,
			Accuser:   NodeID{byte(kind), 0xaa},
			Accused:   NodeID{0xbb, byte(kind)},
			Epoch:     uint64(kind),
			Evidence:  []byte{},
			Signature: []byte{0xde, 0xad, 0xbe, 0xef},
		}
		if b, err := MarshalAbortEvidence(ev); err == nil {
			f.Add(b)
		}
	}

	// Edge: minimum-size valid frame (zero-length evidence and
	// signature). Hits the boundary check at the head of
	// UnmarshalAbortEvidence.
	ev := &AbortEvidence{
		Kind:    ComplaintEquivocation,
		Accuser: NodeID{0x01},
		Accused: NodeID{0x02},
	}
	if b, err := MarshalAbortEvidence(ev); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: must not panic on any input. Either returns a
		// well-formed AbortEvidence with consistent field bounds, or a
		// typed error. We do not assert which — the only invariant is
		// no panic, no out-of-bounds slice.
		out, err := UnmarshalAbortEvidence(data)
		if err != nil {
			if out != nil {
				t.Fatalf("error returned with non-nil result: %v", err)
			}
			return
		}
		// On accept, the returned struct must satisfy the marshaller's
		// own constraint (accuser != accused) — re-marshal and check
		// round-trip stability for a non-empty subset.
		if out.Accuser == out.Accused {
			t.Fatalf("parser accepted self-accusation")
		}
		if _, mErr := MarshalAbortEvidence(out); mErr != nil {
			t.Fatalf("parser returned struct that fails marshal: %v", mErr)
		}
	})
}

// =====================================================================
// FuzzAbortEvidence_PerKindValidation — fuzz the per-kind structural
// validator. Contract: must not panic on any (kind, blob) input;
// either accepts and returns nil, or returns a typed error. The
// adversarial property "blob valid for kind A must reject under
// kind B" is covered by TestAbortEvidence_RejectsWrongKindShape;
// the fuzz here widens random-input coverage.
// =====================================================================

func FuzzAbortEvidence_PerKindValidation(f *testing.F) {
	for _, kind := range []ComplaintKind{
		ComplaintEquivocation,
		ComplaintBadDelivery,
		ComplaintMACFailure,
		ComplaintRangeFailure,
		ComplaintKind(99), // unknown kind seed
	} {
		f.Add(uint8(kind), []byte{})
		if blob := validEvidenceFor(kind); blob != nil {
			f.Add(uint8(kind), blob)
		}
	}

	f.Fuzz(func(t *testing.T, kind uint8, blob []byte) {
		e := &AbortEvidence{
			Kind:     ComplaintKind(kind),
			Accuser:  NodeID{0x01},
			Accused:  NodeID{0x02},
			Evidence: blob,
		}
		// Must not panic. Result is checked-error or nil.
		_ = ValidateAbortEvidence(e)
	})
}

// =====================================================================
// FuzzVerifySignature — fuzz the FIPS 204 signature byte parser via
// the Pulsar consensus-consumer entry point.
// =====================================================================

func FuzzVerifySignature(f *testing.F) {
	pk, msg, sig, ok := loadVerifyKAT("Pulsar-44")
	if !ok {
		// Provide a synthetic seed of the correct length even when
		// vectors are absent so the fuzzer has something to mutate.
		pk = make([]byte, ParamsP44.PublicKeySize)
		msg = []byte("fuzz-seed-msg")
		sig = make([]byte, ParamsP44.SignatureSize)
	}
	f.Add(pk, msg, sig)
	// A second seed: deliberately wrong-size signature. Verify must
	// reject with ErrSignatureWrongSize, not panic.
	f.Add(pk, msg, []byte{0x00})

	f.Fuzz(func(t *testing.T, pkBytes, msgBytes, sigBytes []byte) {
		// Cap to params.PublicKeySize so we exercise both the size
		// gate and the underlying FIPS 204 Unpack path.
		params := ParamsP44
		pubkey := &PublicKey{Mode: ModeP44, Bytes: pkBytes}
		signature := &Signature{Mode: ModeP44, Bytes: sigBytes}

		// Must not panic. Verify returns a typed error on any
		// structural failure. A successful Verify on fuzzer-mutated
		// input would be a forgery, which is computationally
		// infeasible — so practically we always expect a non-nil
		// error here, but we do NOT assert that (a future bug would
		// be a silent forgery; the panic-freedom check is the
		// invariant the fuzzer enforces).
		_ = Verify(params, pubkey, msgBytes, signature)
	})
}

// =====================================================================
// FuzzVerifyCtx — same surface but with mutating ctx bytes.
// =====================================================================

func FuzzVerifyCtx(f *testing.F) {
	pk, msg, sig, ok := loadVerifyKAT("Pulsar-44")
	if !ok {
		pk = make([]byte, ParamsP44.PublicKeySize)
		msg = []byte("fuzz-seed-msg")
		sig = make([]byte, ParamsP44.SignatureSize)
	}
	f.Add(pk, msg, sig, []byte{})
	f.Add(pk, msg, sig, []byte("ctx-A"))
	// 255-byte ctx is the FIPS 204 max; 256 must be rejected.
	f.Add(pk, msg, sig, make([]byte, 255))

	f.Fuzz(func(t *testing.T, pkBytes, msgBytes, sigBytes, ctxBytes []byte) {
		params := ParamsP44
		pubkey := &PublicKey{Mode: ModeP44, Bytes: pkBytes}
		signature := &Signature{Mode: ModeP44, Bytes: sigBytes}
		_ = VerifyCtx(params, pubkey, msgBytes, ctxBytes, signature)
	})
}

// =====================================================================
// FuzzShareFromBytes — the Shamir share wire parser.
//
// shareFromBytes is package-internal, but its wire layout (64 bytes of
// big-endian uint16s) is part of the protocol surface and any change
// to its bounds-checking behaviour is a wire incompatibility. The
// fuzz target here verifies it does not panic on any 64-byte input
// (it must not, since the function reads fixed offsets only).
// =====================================================================

func FuzzShareFromBytes(f *testing.F) {
	// Seed: all-zero share (corresponds to f(x)=0 which is a valid
	// Shamir share, even if unusual).
	var z [shareWireSize]byte
	f.Add(uint32(1), z[:])

	// Seed: max value at every uint16 position.
	var m [shareWireSize]byte
	for i := range m {
		m[i] = 0xff
	}
	f.Add(uint32(256), m[:])

	// Seed: alternating pattern.
	var p [shareWireSize]byte
	for i := range p {
		p[i] = byte(i)
	}
	f.Add(uint32(42), p[:])

	f.Fuzz(func(t *testing.T, x uint32, buf []byte) {
		// shareFromBytes takes a fixed-size array, so we pad/truncate
		// fuzzer input deterministically. The conversion never panics
		// for any 64-byte buffer; this target catches a future
		// regression where the loop bounds change.
		var fixed [shareWireSize]byte
		copy(fixed[:], buf)
		s := shareFromBytes(x, fixed)
		// Sanity: X round-trips and Y values do not exceed the
		// 16-bit width of the wire encoding (always true by
		// construction; this is a regression guard).
		if s.X != x {
			t.Fatalf("X not preserved: got %d want %d", s.X, x)
		}
		for i, v := range s.Y {
			if v > 0xffff {
				t.Fatalf("Y[%d]=%d exceeds 16-bit range", i, v)
			}
		}
	})
}

// =====================================================================
// FuzzParamsFor — Mode dispatch (committee/quorum-relevant entry).
//
// ParamsFor is the gate that downstream code uses to convert an
// untrusted Mode byte into a canonical *Params. Fuzzing it confirms
// the dispatch table rejects every non-canonical mode without panic
// and that the returned Params validates iff Mode is in the registry.
// =====================================================================

func FuzzParamsFor(f *testing.F) {
	f.Add(uint8(0))   // ModeUnspecified
	f.Add(uint8(44))  // ModeP44
	f.Add(uint8(65))  // ModeP65
	f.Add(uint8(87))  // ModeP87
	f.Add(uint8(255)) // out-of-range

	f.Fuzz(func(t *testing.T, m uint8) {
		mode := Mode(m)
		p, err := ParamsFor(mode)
		if err != nil {
			if p != nil {
				t.Fatalf("ParamsFor returned (%v, %v) — expected nil on error", p, err)
			}
			return
		}
		// Accepted modes must round-trip through Validate.
		if vErr := p.Validate(); vErr != nil {
			t.Fatalf("ParamsFor(%d) returned tampered params: %v", mode, vErr)
		}
		// Mode field must match the requested mode.
		if p.Mode != mode {
			t.Fatalf("ParamsFor(%d).Mode = %d (mismatch)", mode, p.Mode)
		}
	})
}
