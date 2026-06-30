// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build pulsar_verify_ct

// verify_ct.go — cgo bridge exposing pulsar.Verify to the C dudect
// harness in dudect_verify.c.
//
// HONEST CT-population framing (NOT a FIPS 204 citation).
//
// FIPS 204 itself does not carve out a "valid signatures only" CT
// requirement for Verify — §6.3 is the Verify algorithm spec, not a
// CT requirement section. The reason we test the valid-signature
// population here is OPERATIONAL, not standards-cited:
//
//   * Verify holds no long-term secret state. An attacker observing
//     the rejection-path timing of garbage bytes does not learn any
//     confidential value — the attacker SUPPLIED the garbage.
//   * The class of inputs over which Verify is interesting to
//     constant-time-test is the class of inputs an attacker would
//     submit to extract information about a SECRET in the verifier.
//     Verify has no secret, so the empirically meaningful CT
//     property is "signatures with identical structural validity
//     should not be timing-distinguishable" — i.e., the valid-sig
//     class.
//   * circl's ML-DSA Verify (the dispatch target of pulsar.Verify)
//     is documented as constant-time over the valid-signature
//     pipeline. Our test exercises that pipeline.
//
// The dudect harness BOTH classes are VALID signatures on the same
// (pk, message); they differ only in the per-signing randomness
// (signing is randomised per FIPS 204 §3.5.2), so the byte strings
// vary but the verify pipeline executes the same code path. Any
// timing difference dudect detects between class-A and class-B
// samples is a real signature-content-dependent timing in Verify.
//
// The bridge precomputes a pool of K_VALID valid signatures at
// startup. prepare_inputs (in dudect_verify.c) copies pool[0] for
// every class-A sample (Welch's t-test requires identical class-A
// inputs) and pool[rand % K_VALID] for class-B.
//
// Earlier versions of this harness used zero-bytes (class A) vs
// random-bytes (class B). Both were invalid sigs but on different
// rejection paths (z-range pass vs fail), so dudect detected a
// rejection-path timing difference that is not the CT property
// pulsar.Verify is claimed to satisfy (see "valid-signature class"
// framing above). See ct/dudect/README.md "Verify CT population".
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_verify.dylib ./verify_ct.go
//
// On Linux the output extension is .so; the Makefile selects the right
// one for the host platform.

package main

// Force-include the ARM compat shim on AArch64 hosts so that
// dudect/src/dudect.h's unconditional <emmintrin.h>/<x86intrin.h>
// includes resolve via the shim's blocking #defines. Matches the
// Makefile behavior so `go build` and `make` agree on arm64.

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/pulsar/pkg/pulsar"
)

// Long-lived fixture. The dudect main loop calls
// pulsar_verify_ct_setup() once at startup, then calls
// pulsar_verify_ct() in a tight measurement loop.
const kValidPool = 64

var (
	fixtureParams *pulsar.Params
	fixturePub    *pulsar.PublicKey
	fixtureMsg    []byte
	fixtureSig    *pulsar.Signature
	// validPool holds kValidPool valid signatures over the same
	// (pk, message), differing only in per-signing randomness.
	// The C harness selects from this pool to populate the dudect
	// class A (pool[0]) and class B (pool[rand]) input buffers.
	validPool [kValidPool]*pulsar.Signature
)

// Initialise the long-lived fixture. Returns 0 on success, non-zero
// on failure. Must be called once before pulsar_verify_ct.
//
// We use ModeP65 (the Lux consensus production target, see
// params.go). The fixture pk/signature are freshly generated under
// crypto/rand so the dudect run is not deterministic across launches
// — that's intentional: the timing property must hold for ANY valid
// (pk, msg, sig) triple, not a single hardcoded test vector.
//
//export pulsar_verify_ct_setup
func pulsar_verify_ct_setup() C.int {
	params := pulsar.MustParamsFor(pulsar.ModeP65)
	sk, err := pulsar.GenerateKey(params, rand.Reader)
	if err != nil {
		return 1
	}
	msg := []byte("dudect constant-time smoke message: Pulsar Verify class N1")
	sig, err := pulsar.Sign(params, sk, msg, nil, true, rand.Reader)
	if err != nil {
		return 2
	}
	// Sanity round-trip: any failure here means the fixture itself
	// is broken before dudect starts measuring.
	if err := pulsar.Verify(params, sk.Pub, msg, sig); err != nil {
		return 3
	}
	fixtureParams = params
	fixturePub = sk.Pub
	fixtureMsg = msg
	fixtureSig = sig
	// Generate kValidPool independent valid signatures on the same
	// (pk, msg). Each draws fresh randomness from crypto/rand.
	for i := 0; i < kValidPool; i++ {
		s, err := pulsar.Sign(params, sk, msg, nil, true, rand.Reader)
		if err != nil {
			return 4
		}
		if err := pulsar.Verify(params, sk.Pub, msg, s); err != nil {
			return 5
		}
		validPool[i] = s
	}
	return 0
}

// Returns the FIPS 204 signature size for the configured mode. The
// C harness uses this to size its per-sample scratch buffer to the
// exact wire width Verify expects.
//
//export pulsar_verify_ct_sig_size
func pulsar_verify_ct_sig_size() C.size_t {
	if fixtureParams == nil {
		return 0
	}
	return C.size_t(fixtureParams.SignatureSize)
}

// Returns the number of valid signatures in the per-startup pool.
// The C harness draws class-B samples from pool[0..pool_size).
//
//export pulsar_verify_ct_pool_size
func pulsar_verify_ct_pool_size() C.size_t {
	return C.size_t(kValidPool)
}

// Copies validPool[idx].Bytes into the caller-supplied dst buffer
// (sig_size bytes). idx MUST be in [0, kValidPool); the C harness
// enforces this via pulsar_verify_ct_pool_size. Returns 0 on
// success, non-zero on bounds violation.
//
// dst is owned by the caller; this is a one-way copy. The copy
// itself is constant-time over idx since we always write exactly
// sig_size bytes; the timing of the copy is irrelevant because
// dudect measures cycles around pulsar_verify_ct, not around this
// setup-time data movement.
//
//export pulsar_verify_ct_copy_pool
func pulsar_verify_ct_copy_pool(idx C.size_t, dst *C.uint8_t) C.int {
	i := int(idx)
	if i < 0 || i >= kValidPool || fixtureParams == nil || validPool[i] == nil {
		return 1
	}
	n := fixtureParams.SignatureSize
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), n)
	copy(dstSlice, validPool[i].Bytes)
	return 0
}

// One dudect measurement sample.
//
// data points to sig_size bytes of caller-controlled signature bytes
// (one dudect "class" picks fixed bytes, the other picks random
// bytes; that classification happens in the C harness). The bridge
// constructs a *Signature wrapping those bytes and calls
// pulsar.Verify; the return value is ignored (Verify returns an
// error for class-B random bytes; that's expected and irrelevant —
// we measure cycles, not result).
//
// The function MUST be branchless on data — any data-dependent
// branch we introduce here pollutes the measurement before Verify
// even starts. We only copy data into a fresh slice and dispatch.
//
//export pulsar_verify_ct
func pulsar_verify_ct(data *C.uint8_t) {
	if fixtureParams == nil {
		return
	}
	n := fixtureParams.SignatureSize
	sigBytes := unsafe.Slice((*byte)(unsafe.Pointer(data)), n)
	sig := &pulsar.Signature{
		Mode:  fixtureParams.Mode,
		Bytes: append([]byte{}, sigBytes...),
	}
	// Return value deliberately unused. dudect measures the elapsed
	// cycles regardless of pass/fail. We must not branch on the
	// return value, or the C harness would see a control-flow
	// difference that is OUR fault, not Verify's.
	_ = pulsar.Verify(fixtureParams, fixturePub, fixtureMsg, sig)
}

// main is required for `go build -buildmode=c-shared`.
func main() {}
