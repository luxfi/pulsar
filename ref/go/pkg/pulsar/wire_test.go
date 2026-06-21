// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestPulsar_Wire_SigRoundtrip checks the Signature wire codec
// round-trips byte-equal for every mode and that the parsed Mode +
// Bytes match the input exactly. A second marshal MUST produce the
// same bytes as the first (strict canonical encoding).
func TestPulsar_Wire_SigRoundtrip(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			body := make([]byte, params.SignatureSize)
			if _, err := rand.Read(body); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			sig := &Signature{Mode: mode, Bytes: append([]byte{}, body...)}

			wire1, err := sig.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := len(wire1); got != wireFixedSigHeader+params.SignatureSize {
				t.Fatalf("wire length %d != header(%d) + payload(%d)",
					got, wireFixedSigHeader, params.SignatureSize)
			}

			var parsed Signature
			if err := parsed.UnmarshalBinary(wire1); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if parsed.Mode != mode {
				t.Fatalf("parsed.Mode = %v want %v", parsed.Mode, mode)
			}
			if !bytes.Equal(parsed.Bytes, body) {
				t.Fatalf("parsed.Bytes diverged from input")
			}

			wire2, err := parsed.MarshalBinary()
			if err != nil {
				t.Fatalf("re-MarshalBinary: %v", err)
			}
			if !bytes.Equal(wire1, wire2) {
				t.Fatalf("re-marshal not byte-equal: %d vs %d", len(wire1), len(wire2))
			}
		})
	}
}

// TestPulsar_Wire_GroupKeyRoundtrip mirrors TestPulsar_Wire_SigRoundtrip
// for PublicKey (the group public key on the wire).
func TestPulsar_Wire_GroupKeyRoundtrip(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			body := make([]byte, params.PublicKeySize)
			if _, err := rand.Read(body); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			pk := &PublicKey{Mode: mode, Bytes: append([]byte{}, body...)}

			wire1, err := pk.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if got := len(wire1); got != wireFixedGroupKeyHeader+params.PublicKeySize {
				t.Fatalf("wire length %d != header(%d) + payload(%d)",
					got, wireFixedGroupKeyHeader, params.PublicKeySize)
			}

			var parsed PublicKey
			if err := parsed.UnmarshalBinary(wire1); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if parsed.Mode != mode {
				t.Fatalf("parsed.Mode = %v want %v", parsed.Mode, mode)
			}
			if !bytes.Equal(parsed.Bytes, body) {
				t.Fatalf("parsed.Bytes diverged from input")
			}

			wire2, err := parsed.MarshalBinary()
			if err != nil {
				t.Fatalf("re-MarshalBinary: %v", err)
			}
			if !bytes.Equal(wire1, wire2) {
				t.Fatalf("re-marshal not byte-equal: %d vs %d", len(wire1), len(wire2))
			}
		})
	}
}

// TestPulsar_Wire_FIPS204Verifiable is the headline cryptographic
// claim of the wire codec: a Pulsar Signature, after MarshalBinary +
// payload-extraction, verifies under cloudflare/circl's FIPS 204
// mldsa{44,65,87}.Verify with NO Pulsar code path involved on the
// verifier side.
//
// This is the Class N1 manifesto in test form: the threshold
// orchestration layer can hand wire bytes to a relying party that
// has never heard of Pulsar, and that party — with only a FIPS 204
// ML-DSA verifier and the documented PULS / PULG frame — verifies
// the signature.
//
// For every mode we run the single-party deterministic Sign path
// (the production threshold path emits a bit-identical signature,
// proved by TestN1_ByteEquality_ThresholdMatchesCentralized; the
// relevant property here is that the WIRE FORMAT preserves the FIPS
// 204 bytes verbatim, which is mode-agnostic and orthogonal to
// whether the signer was single-party or threshold).
func TestPulsar_Wire_FIPS204Verifiable(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			var seed [SeedSize]byte
			copy(seed[:], "pulsar-wire-test-deterministic!!")
			seed[0] ^= byte(mode) // distinct seed per mode

			sk, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			msg := []byte("pulsar wire codec — FIPS 204 byte-identity claim")
			// Deterministic signing so the test is repeatable.
			sig, err := Sign(params, sk, msg, nil, false, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// 1. Sanity: pulsar's own Verify accepts it.
			if err := Verify(params, sk.Pub, msg, sig); err != nil {
				t.Fatalf("baseline Verify failed before wire: %v", err)
			}

			// 2. Frame both via the wire codec.
			gkWire, err := sk.Pub.MarshalBinary()
			if err != nil {
				t.Fatalf("Pub.MarshalBinary: %v", err)
			}
			sigWire, err := sig.MarshalBinary()
			if err != nil {
				t.Fatalf("sig.MarshalBinary: %v", err)
			}

			// 3. Extract the FIPS 204 payload from each frame by skipping
			//    the magic(4) + version(2) + mode(1) + len(4) header. NO
			//    pulsar package code touches the payload — this is exactly
			//    what an external relying party with a FIPS 204 verifier
			//    would do.
			fipsPK := extractFIPSPayload(t, gkWire, wireMagicPulsarGroupKey)
			fipsSig := extractFIPSPayload(t, sigWire, wireMagicPulsarSig)

			// 4. Verify under cloudflare/circl directly. No pulsar code
			//    path is hit on the verify side.
			if !verifyDirectCirc(mode, fipsPK, msg, fipsSig) {
				t.Fatalf("cloudflare/circl FIPS 204 Verify rejected the unwrapped Pulsar bytes — wire codec broke byte-identity")
			}

			// 5. Stateless VerifyBytes path used by thresholdd accepts
			//    the same bytes.
			if !VerifyBytes(gkWire, msg, sigWire) {
				t.Fatalf("VerifyBytes rejected a valid signature")
			}

			// 6. Tamper resistance: flip a byte in the sig payload —
			//    direct circl verify MUST reject, and VerifyBytes must
			//    reject.
			tamperedSig := append([]byte{}, sigWire...)
			tamperedSig[len(tamperedSig)-1] ^= 0x01
			if VerifyBytes(gkWire, msg, tamperedSig) {
				t.Fatalf("VerifyBytes accepted a tampered signature")
			}
			tamperedFips := append([]byte{}, fipsSig...)
			tamperedFips[len(tamperedFips)-1] ^= 0x01
			if verifyDirectCirc(mode, fipsPK, msg, tamperedFips) {
				t.Fatalf("circl FIPS 204 Verify accepted a tampered signature")
			}
		})
	}
}

// extractFIPSPayload strips the wire header from a PULS or PULG
// frame and returns the FIPS 204 payload bytes. Asserts the magic
// matches the expected one. Test-only — production wire callers go
// through (Signature|PublicKey).UnmarshalBinary.
func extractFIPSPayload(t *testing.T, wire []byte, wantMagic uint32) []byte {
	t.Helper()
	if len(wire) < wireFixedSigHeader {
		t.Fatalf("wire frame too short: %d", len(wire))
	}
	gotMagic := binary.BigEndian.Uint32(wire[0:4])
	if gotMagic != wantMagic {
		t.Fatalf("magic mismatch: got 0x%08x want 0x%08x", gotMagic, wantMagic)
	}
	version := binary.BigEndian.Uint16(wire[4:6])
	if version != wireVersionV1 {
		t.Fatalf("version mismatch: got %d want %d", version, wireVersionV1)
	}
	declared := binary.BigEndian.Uint32(wire[7:11])
	if int(declared) != len(wire)-wireFixedSigHeader {
		t.Fatalf("declared length %d != payload length %d",
			declared, len(wire)-wireFixedSigHeader)
	}
	return wire[wireFixedSigHeader:]
}

// verifyDirectCirc bypasses every Pulsar code path and calls
// cloudflare/circl's FIPS 204 Verify directly. This proves the
// wire codec's body bytes are valid FIPS 204 bytes.
func verifyDirectCirc(mode Mode, pkBytes, msg, sigBytes []byte) bool {
	switch mode {
	case ModeP44:
		if len(pkBytes) != mldsa44.PublicKeySize || len(sigBytes) != mldsa44.SignatureSize {
			return false
		}
		var pk mldsa44.PublicKey
		var pkBuf [mldsa44.PublicKeySize]byte
		copy(pkBuf[:], pkBytes)
		pk.Unpack(&pkBuf)
		return mldsa44.Verify(&pk, msg, nil, sigBytes)
	case ModeP65:
		if len(pkBytes) != mldsa65.PublicKeySize || len(sigBytes) != mldsa65.SignatureSize {
			return false
		}
		var pk mldsa65.PublicKey
		var pkBuf [mldsa65.PublicKeySize]byte
		copy(pkBuf[:], pkBytes)
		pk.Unpack(&pkBuf)
		return mldsa65.Verify(&pk, msg, nil, sigBytes)
	case ModeP87:
		if len(pkBytes) != mldsa87.PublicKeySize || len(sigBytes) != mldsa87.SignatureSize {
			return false
		}
		var pk mldsa87.PublicKey
		var pkBuf [mldsa87.PublicKeySize]byte
		copy(pkBuf[:], pkBytes)
		pk.Unpack(&pkBuf)
		return mldsa87.Verify(&pk, msg, nil, sigBytes)
	default:
		return false
	}
}

// TestPulsar_Wire_RejectMalformed exercises every negative path the
// signature parser must catch. Each malformed input must surface a
// typed error from the wire package; no panic, no oversized
// allocation, no payload buffer for invalid magic/version/mode/length.
func TestPulsar_Wire_RejectMalformed(t *testing.T) {
	validSig := func(t *testing.T) []byte {
		t.Helper()
		mode := ModeP65
		params := MustParamsFor(mode)
		body := make([]byte, params.SignatureSize)
		s := &Signature{Mode: mode, Bytes: body}
		w, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("setup MarshalBinary: %v", err)
		}
		return w
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []byte
		want  error
	}{
		{
			name:  "empty",
			build: func(t *testing.T) []byte { return nil },
			want:  ErrWireFrameTooShort,
		},
		{
			name: "header-only",
			build: func(t *testing.T) []byte {
				return make([]byte, wireFixedSigHeader-1)
			},
			want: ErrWireFrameTooShort,
		},
		{
			name: "wrong-magic",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				w[0] = 0xDE
				w[1] = 0xAD
				w[2] = 0xBE
				w[3] = 0xEF
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "group-key-magic-into-sig",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Replace PULS with PULG.
				binary.BigEndian.PutUint32(w[0:4], wireMagicPulsarGroupKey)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "wrong-version",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				binary.BigEndian.PutUint16(w[4:6], 0xFFFF)
				return w
			},
			want: ErrWireVersionMismatch,
		},
		{
			name: "unknown-mode",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				w[6] = 0xAA // not 44, 65, or 87
				return w
			},
			want: ErrWireModeUnknown,
		},
		{
			name: "length-mismatch-mode-65",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Declared length 999 for ModeP65 — not the canonical 3309.
				binary.BigEndian.PutUint32(w[7:11], 999)
				return w
			},
			want: ErrWireLengthMismatch,
		},
		{
			name: "length-oversized-vs-buffer",
			build: func(t *testing.T) []byte {
				// Manually craft: PULS, v1, mode=44, declared=4 GiB.
				w := make([]byte, wireFixedSigHeader)
				binary.BigEndian.PutUint32(w[0:4], wireMagicPulsarSig)
				binary.BigEndian.PutUint16(w[4:6], wireVersionV1)
				w[6] = byte(ModeP44)
				binary.BigEndian.PutUint32(w[7:11], 0xFFFFFFFF)
				return w
			},
			// 4 GiB is not equal to FIPS 204 mldsa44 size; the length
			// mismatch fires before the buffer-bounds check.
			want: ErrWireLengthMismatch,
		},
		{
			name: "trailing-bytes",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				return append(w, 0x00, 0x00, 0x00)
			},
			want: ErrWireTrailingBytes,
		},
		{
			name: "truncated-payload",
			build: func(t *testing.T) []byte {
				w := validSig(t)
				// Drop the trailing 3 bytes of the payload. The declared
				// length still matches the canonical FIPS 204 size so
				// length-against-mode check passes; the bounded-reader
				// check fires because declared > remaining buffer.
				return w[:len(w)-3]
			},
			want: ErrWireFrameRejected,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var sig Signature
			err := sig.UnmarshalBinary(tc.build(t))
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestPulsar_Wire_GroupKeyRejectMalformed mirrors the signature
// rejection suite for GroupKey. Crucially, a SIGNATURE frame fed
// into the GroupKey parser must be rejected at the magic check —
// domain separation between PULS and PULG must be effective.
func TestPulsar_Wire_GroupKeyRejectMalformed(t *testing.T) {
	validGk := func(t *testing.T) []byte {
		t.Helper()
		mode := ModeP65
		params := MustParamsFor(mode)
		body := make([]byte, params.PublicKeySize)
		p := &PublicKey{Mode: mode, Bytes: body}
		w, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("setup MarshalBinary: %v", err)
		}
		return w
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []byte
		want  error
	}{
		{
			name:  "empty",
			build: func(t *testing.T) []byte { return nil },
			want:  ErrWireFrameTooShort,
		},
		{
			name: "sig-magic-into-groupkey",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint32(w[0:4], wireMagicPulsarSig)
				return w
			},
			want: ErrWireMagicMismatch,
		},
		{
			name: "wrong-version",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint16(w[4:6], 0xFFFF)
				return w
			},
			want: ErrWireVersionMismatch,
		},
		{
			name: "unknown-mode",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				w[6] = 0xAA
				return w
			},
			want: ErrWireModeUnknown,
		},
		{
			name: "length-mismatch",
			build: func(t *testing.T) []byte {
				w := validGk(t)
				binary.BigEndian.PutUint32(w[7:11], 7)
				return w
			},
			want: ErrWireLengthMismatch,
		},
		{
			name: "trailing-bytes",
			build: func(t *testing.T) []byte {
				return append(validGk(t), 0x00)
			},
			want: ErrWireTrailingBytes,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var gk PublicKey
			err := gk.UnmarshalBinary(tc.build(t))
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestPulsar_Wire_VerifyBytes_RejectsCrossSlot exercises the
// dispatcher's contract that wire bytes cannot be swapped between
// slots: a GroupKey-magic frame fed into the signature slot of
// VerifyBytes must produce false. Same for a Signature-magic frame
// fed into the GroupKey slot.
func TestPulsar_Wire_VerifyBytes_RejectsCrossSlot(t *testing.T) {
	mode := ModeP65
	params := MustParamsFor(mode)
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-wire-cross-slot-test-32!!")
	sk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	msg := []byte("cross-slot rejection")
	sig, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	gkWire, err := sk.Pub.MarshalBinary()
	if err != nil {
		t.Fatalf("gk MarshalBinary: %v", err)
	}
	sigWire, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("sig MarshalBinary: %v", err)
	}

	if !VerifyBytes(gkWire, msg, sigWire) {
		t.Fatalf("baseline VerifyBytes failed")
	}
	// Swap: gkWire in the signature slot. Must reject.
	if VerifyBytes(gkWire, msg, gkWire) {
		t.Fatalf("VerifyBytes accepted GroupKey-magic bytes in signature slot")
	}
	// Swap: sigWire in the group-key slot. Must reject.
	if VerifyBytes(sigWire, msg, sigWire) {
		t.Fatalf("VerifyBytes accepted Signature-magic bytes in group-key slot")
	}
	// nil bytes — must reject without panic.
	if VerifyBytes(nil, msg, sigWire) {
		t.Fatalf("VerifyBytes accepted nil group-key bytes")
	}
	if VerifyBytes(gkWire, msg, nil) {
		t.Fatalf("VerifyBytes accepted nil signature bytes")
	}
	// Wrong message — must reject.
	if VerifyBytes(gkWire, []byte("different message"), sigWire) {
		t.Fatalf("VerifyBytes accepted a wrong message")
	}
}

// TestPulsar_Wire_ModeMismatch_Rejected ensures the dispatcher's
// VerifyBytes returns false when the parsed GroupKey and Signature
// declare different modes — a relying party must never witness a
// ModeP65 signature verifying under a ModeP44 group key.
func TestPulsar_Wire_ModeMismatch_Rejected(t *testing.T) {
	// Build a valid sig (ModeP65) and a valid gk (ModeP44).
	skP65, err := KeyFromSeed(MustParamsFor(ModeP65), [SeedSize]byte{1})
	if err != nil {
		t.Fatalf("KeyFromSeed P65: %v", err)
	}
	skP44, err := KeyFromSeed(MustParamsFor(ModeP44), [SeedSize]byte{2})
	if err != nil {
		t.Fatalf("KeyFromSeed P44: %v", err)
	}
	msg := []byte("mode mismatch test")
	sigP65, err := Sign(MustParamsFor(ModeP65), skP65, msg, nil, false, nil)
	if err != nil {
		t.Fatalf("Sign P65: %v", err)
	}
	gkP44Wire, err := skP44.Pub.MarshalBinary()
	if err != nil {
		t.Fatalf("gk P44 MarshalBinary: %v", err)
	}
	sigP65Wire, err := sigP65.MarshalBinary()
	if err != nil {
		t.Fatalf("sig P65 MarshalBinary: %v", err)
	}
	if VerifyBytes(gkP44Wire, msg, sigP65Wire) {
		t.Fatalf("VerifyBytes accepted cross-mode (gk=P44, sig=P65)")
	}
}

// TestPulsar_Wire_MarshalSafetyChecks ensures Marshal refuses
// inputs that would emit malformed frames: nil receiver, unknown
// mode, length-vs-mode mismatch.
func TestPulsar_Wire_MarshalSafetyChecks(t *testing.T) {
	t.Run("nil-signature", func(t *testing.T) {
		var s *Signature
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("nil Signature.MarshalBinary did not return error")
		}
	})
	t.Run("nil-publickey", func(t *testing.T) {
		var p *PublicKey
		if _, err := p.MarshalBinary(); err == nil {
			t.Fatal("nil PublicKey.MarshalBinary did not return error")
		}
	})
	t.Run("sig-unknown-mode", func(t *testing.T) {
		s := &Signature{Mode: Mode(0xAA), Bytes: make([]byte, 3309)}
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("unknown-mode Signature.MarshalBinary did not return error")
		}
	})
	t.Run("sig-wrong-length", func(t *testing.T) {
		s := &Signature{Mode: ModeP65, Bytes: make([]byte, 999)}
		if _, err := s.MarshalBinary(); err == nil {
			t.Fatal("wrong-length Signature.MarshalBinary did not return error")
		}
	})
	t.Run("gk-wrong-length", func(t *testing.T) {
		p := &PublicKey{Mode: ModeP65, Bytes: make([]byte, 99)}
		if _, err := p.MarshalBinary(); err == nil {
			t.Fatal("wrong-length PublicKey.MarshalBinary did not return error")
		}
	})
}
