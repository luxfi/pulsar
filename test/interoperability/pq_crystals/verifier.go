// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pq_crystals is a cgo binding to the pq-crystals/dilithium
// reference FIPS 204 verifier — the construction reference for
// ML-DSA. It exists for the sole purpose of CROSS-VALIDATING the
// signatures Pulsar produces against an INDEPENDENT FIPS 204
// verifier that is not cloudflare/circl (the other independent
// verifier already wired in at test/interoperability/n1_class_test.go).
//
// The cgo binding is verify-only. Keygen and sign live in the
// underlying static archive, but the Go surface deliberately does
// not expose them — the "independent verifier" discipline requires
// this binding to be incapable of producing signatures of its own.
// It can only accept or reject a byte string offered to it.
//
// Build requirements:
//
//   - CGO_ENABLED=1
//   - A working C compiler (any of cc / clang / gcc)
//   - Run fetch.sh first to clone pq-crystals at the pinned
//     commit and build libpqcrystals_dilithium.a in this directory
//
// If CGO_ENABLED=0 or the archive is missing, the package fails
// to build; callers under the high-assurance gate must arrange for
// fetch.sh to have run before invoking go test on this package.
//
// The build tag `pulsar_pqcrystals` is required to enable this
// binding. Tests under this directory carry the same build tag.
// This keeps the default Pulsar build (which does not have the
// archive) green; the cross-validation gate sets the tag explicitly.

//go:build pulsar_pqcrystals

package pq_crystals

/*
#cgo CFLAGS: -I${SRCDIR}

// macOS and Linux have different conventions for resolving the
// archive path. We pass the archive by absolute path via SRCDIR
// so both platforms resolve identically. The archive lives in
// the same directory as this Go file; fetch.sh puts it there.
#cgo LDFLAGS: ${SRCDIR}/libpqcrystals_dilithium.a

#include "pq_crystals_verify.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// ErrPqCrystalsReject is returned when the pq-crystals reference
// verifier rejects the (pk, msg, sig, ctx) tuple.
var ErrPqCrystalsReject = errors.New("pq-crystals/dilithium reference verifier rejected the signature")

// VerifyMLDSA44 runs the pq-crystals DILITHIUM_MODE=2 reference
// verifier on (pk, msg, sig) with ML-DSA context string ctx.
//
// FIPS 204 ML-DSA-44 sizes: pk = 1312 bytes, sig = 2420 bytes.
// Returns nil iff the signature verifies; otherwise wraps the
// reference verifier's non-zero return.
func VerifyMLDSA44(pk, msg, sig, ctx []byte) error {
	return doVerify(44, pk, msg, sig, ctx)
}

// VerifyMLDSA65 runs the pq-crystals DILITHIUM_MODE=3 reference
// verifier. ML-DSA-65 sizes: pk = 1952, sig = 3309.
func VerifyMLDSA65(pk, msg, sig, ctx []byte) error {
	return doVerify(65, pk, msg, sig, ctx)
}

// VerifyMLDSA87 runs the pq-crystals DILITHIUM_MODE=5 reference
// verifier. ML-DSA-87 sizes: pk = 2592, sig = 4627.
func VerifyMLDSA87(pk, msg, sig, ctx []byte) error {
	return doVerify(87, pk, msg, sig, ctx)
}

// doVerify dispatches to the parameter-set-specific entry point.
// The size precondition is enforced both here (defensive) and in
// the C wrapper (authoritative); we want a clear Go-side error
// if the caller has handed us malformed input rather than a cryptic
// negative return code from the upstream verifier.
func doVerify(mode int, pk, msg, sig, ctx []byte) error {
	var wantPK, wantSig int
	switch mode {
	case 44:
		wantPK = C.LUX_PULSAR_MLDSA44_PK_BYTES
		wantSig = C.LUX_PULSAR_MLDSA44_SIG_BYTES
	case 65:
		wantPK = C.LUX_PULSAR_MLDSA65_PK_BYTES
		wantSig = C.LUX_PULSAR_MLDSA65_SIG_BYTES
	case 87:
		wantPK = C.LUX_PULSAR_MLDSA87_PK_BYTES
		wantSig = C.LUX_PULSAR_MLDSA87_SIG_BYTES
	default:
		return fmt.Errorf("unknown ML-DSA mode %d", mode)
	}

	if len(pk) != wantPK {
		return fmt.Errorf("ML-DSA-%d pk: expected %d bytes, got %d", mode, wantPK, len(pk))
	}
	if len(sig) != wantSig {
		return fmt.Errorf("ML-DSA-%d sig: expected %d bytes, got %d", mode, wantSig, len(sig))
	}

	// Empty slices map to nil C pointers; cgo will accept this
	// and pq-crystals correctly handles ctxlen=0 (per FIPS 204
	// §5.4.1, ctx is optional and may be a zero-length string).
	pkPtr := cBytesPtr(pk)
	msgPtr := cBytesPtr(msg)
	sigPtr := cBytesPtr(sig)
	ctxPtr := cBytesPtr(ctx)

	var rc C.int
	switch mode {
	case 44:
		rc = C.lux_pulsar_pqc_verify_mldsa44(
			pkPtr,
			sigPtr, C.size_t(len(sig)),
			msgPtr, C.size_t(len(msg)),
			ctxPtr, C.size_t(len(ctx)),
		)
	case 65:
		rc = C.lux_pulsar_pqc_verify_mldsa65(
			pkPtr,
			sigPtr, C.size_t(len(sig)),
			msgPtr, C.size_t(len(msg)),
			ctxPtr, C.size_t(len(ctx)),
		)
	case 87:
		rc = C.lux_pulsar_pqc_verify_mldsa87(
			pkPtr,
			sigPtr, C.size_t(len(sig)),
			msgPtr, C.size_t(len(msg)),
			ctxPtr, C.size_t(len(ctx)),
		)
	}

	if rc != 0 {
		return fmt.Errorf("%w (rc=%d, mode=ML-DSA-%d)", ErrPqCrystalsReject, int(rc), mode)
	}
	return nil
}

// cBytesPtr returns a *C.uint8_t pointer to the first byte of the
// slice, or nil if the slice is empty. cgo will not invent a
// non-nil pointer for an empty slice; we encode that explicitly
// so the upstream verifier sees a true NULL for a missing
// context string, matching the FIPS 204 §5.4.1 "no context"
// case (ctxlen = 0).
func cBytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
