// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// verify.go — the canonical consensus-consumer entry point.
//
// This file is the Class N1 manifesto in code: Verify literally
// dispatches to mldsa{44,65,87}.Verify from cloudflare/circl, which
// is the FIPS 204 §6.3 verifier verbatim. No Pulsar-specific
// logic; no threshold-specific extension fields; no envelope. A
// signature produced by ThresholdSign (threshold.go) flows through
// the SAME Verify code path as a single-party Sign output.
//
// Per pulsar.tex §4.3 and spec/nist-mptc-category.tex, this is the
// load-bearing property of the entire Pulsar family: anything that
// changes Verify breaks Class N1 output interchangeability.

import (
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Verification errors. Returning a typed error rather than a panic
// is mandated by pulsar.tex §6.1 (DD-007: no panic in the verify
// path) and CONTRIBUTING.md.
var (
	// ErrInvalidSignature is returned when the signature does not
	// verify under FIPS 204 ML-DSA.Verify(pk, message, signature).
	ErrInvalidSignature = errors.New("pulsarm: signature verification failed")

	// ErrSignatureWrongSize is returned when the signature byte
	// length does not match the expected FIPS 204 signature size for
	// the params.Mode.
	ErrSignatureWrongSize = errors.New("pulsarm: signature wrong size")

	// ErrPublicKeyWrongSize is returned when the public-key byte
	// length does not match the expected FIPS 204 public-key size.
	ErrPublicKeyWrongSize = errors.New("pulsarm: public-key wrong size")

	// ErrNilSignature is returned when sig is nil.
	ErrNilSignature = errors.New("pulsarm: nil signature")

	// ErrNilPublicKey is returned when groupPubkey is nil.
	ErrNilPublicKey = errors.New("pulsarm: nil public key")
)

// Verify is the canonical consensus-consumer entry point for
// Pulsar signature verification.
//
// Returns nil if the signature is valid under FIPS 204 ML-DSA.Verify;
// a typed error otherwise. Never panics: caller code in the consensus
// path can call Verify in a hot loop without a recover() shroud.
//
// All validation runs in constant time over the signature and
// public-key bytes (the underlying circl Verify is constant-time
// per FIPS 204 §6.3 and cloudflare/circl's documented contract).
//
// ctx is the FIPS 204 context string (≤255 bytes); pass nil for the
// empty context. Match this to whatever was passed at Sign time.
//
// Class N1 manifesto: this function MUST remain a thin dispatch over
// the FIPS 204 verifier. Adding logic here breaks output
// interchangeability with single-party FIPS 204 — the whole point
// of the Pulsar.M variant.
func Verify(params *Params, groupPubkey *PublicKey, message []byte, sig *Signature) error {
	return VerifyCtx(params, groupPubkey, message, nil, sig)
}

// VerifyCtx is the context-aware variant of Verify. The FIPS 204
// context string ctx (≤255 bytes) is included in the verification
// transcript per FIPS 204 §6.3; pass nil for the empty context.
func VerifyCtx(params *Params, groupPubkey *PublicKey, message, ctx []byte, sig *Signature) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if groupPubkey == nil {
		return ErrNilPublicKey
	}
	if sig == nil {
		return ErrNilSignature
	}
	if groupPubkey.Mode != params.Mode {
		return ErrModeMismatch
	}
	if sig.Mode != params.Mode {
		return ErrModeMismatch
	}
	if len(groupPubkey.Bytes) != params.PublicKeySize {
		return ErrPublicKeyWrongSize
	}
	if len(sig.Bytes) != params.SignatureSize {
		return ErrSignatureWrongSize
	}
	if len(ctx) > 255 {
		return ErrCtxTooLong
	}

	ok := mldsaVerify(params.Mode, groupPubkey.Bytes, message, ctx, sig.Bytes)
	if !ok {
		return ErrInvalidSignature
	}
	return nil
}

// mldsaVerify dispatches to the correct circl ML-DSA parameter set.
// This is the only place outside keygen/sign that touches the
// FIPS 204 implementation; centralising it makes the Class N1
// dispatch table auditable as a single function.
func mldsaVerify(mode Mode, packedPk, message, ctx, sig []byte) bool {
	switch mode {
	case ModeP44:
		var pk mldsa44.PublicKey
		var pkBuf [mldsa44.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa44.Verify(&pk, message, ctx, sig)
	case ModeP65:
		var pk mldsa65.PublicKey
		var pkBuf [mldsa65.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa65.Verify(&pk, message, ctx, sig)
	case ModeP87:
		var pk mldsa87.PublicKey
		var pkBuf [mldsa87.PublicKeySize]byte
		copy(pkBuf[:], packedPk)
		pk.Unpack(&pkBuf)
		return mldsa87.Verify(&pk, message, ctx, sig)
	default:
		return false
	}
}
