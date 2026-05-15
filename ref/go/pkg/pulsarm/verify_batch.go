// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// verify_batch.go -- parallel CPU batch verifier.
//
// Pulsar signatures are FIPS 204 ML-DSA byte-equal (the Class N1
// manifesto in pulsar.tex §4.3). The single-shot Verify path is the
// only place this package touches the FIPS 204 verifier; this file
// composes it across N (groupPubkey, message, signature) tuples in
// parallel.
//
// This file deliberately has NO CGO / native-accel dep: it stays
// portable so any consumer can verify a batch on any platform. The
// GPU fast-path (accel.LatticeOps.DilithiumVerifyBatch) lives at the
// engine layer (consensus/engine/gpu_batch_pipeline.go) where the
// accel session is owned and the host has the native libs installed.
// Engine consumers should prefer the accel path for batches >=
// luxfi/accel.BLSBatchVerifyThreshold; everything below that
// threshold goes through this CPU implementation.

import (
	"errors"
	"runtime"
	"sync"
)

// ErrBatchSizeMismatch is returned when groupPubkeys, messages, and
// sigs do not all have the same length.
var ErrBatchSizeMismatch = errors.New("pulsarm: batch slices length mismatch")

// VerifyBatch verifies N (groupPubkey, message, signature) tuples in
// parallel. results[i] is nil if the i-th signature is valid; on
// failure it carries the same typed error Verify(params, gp_i, msg_i,
// sig_i) would return.
//
// The slices MUST have equal length; mismatches return
// ErrBatchSizeMismatch with a nil results slice.
//
// Empty input (len == 0) returns (nil, nil).
//
// Parallelism is bounded by GOMAXPROCS. The implementation is allocation-
// free in the dispatch loop; the only per-tuple allocation is whatever
// the underlying FIPS 204 Verify does (a copy of the packed public key
// into a fixed-size buffer, identical to the single-shot path).
//
// VerifyBatch is the canonical entry point for any consumer that
// needs to verify > 1 Pulsar signature. Use Verify only when N == 1.
func VerifyBatch(params *Params, groupPubkeys []*PublicKey, messages [][]byte, sigs []*Signature) ([]error, error) {
	n := len(sigs)
	if n != len(groupPubkeys) || n != len(messages) {
		return nil, ErrBatchSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}
	return VerifyBatchCtx(params, groupPubkeys, messages, nil, sigs)
}

// VerifyBatchCtx is the context-aware variant of VerifyBatch. The
// FIPS 204 context string ctx applies to every signature in the
// batch; per-signature contexts require N separate Verify calls.
func VerifyBatchCtx(params *Params, groupPubkeys []*PublicKey, messages [][]byte, ctx []byte, sigs []*Signature) ([]error, error) {
	n := len(sigs)
	if n != len(groupPubkeys) || n != len(messages) {
		return nil, ErrBatchSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}

	results := make([]error, n)

	// Per-tuple validation is cheap; verify is dominated by the FIPS 204
	// signature check. Use a worker pool capped at GOMAXPROCS so we
	// don't oversaturate when called from a context that already has
	// its own concurrency.
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}

	jobs := make(chan int, n)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = VerifyCtx(params, groupPubkeys[i], messages[i], ctx, sigs[i])
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

// VerifyBatchAll is a convenience predicate: true iff every signature
// in the batch verifies. Equivalent to checking that every entry of
// VerifyBatch's results slice is nil. Returns (false, err) only on
// the structural ErrBatchSizeMismatch.
func VerifyBatchAll(params *Params, groupPubkeys []*PublicKey, messages [][]byte, sigs []*Signature) (bool, error) {
	results, err := VerifyBatch(params, groupPubkeys, messages, sigs)
	if err != nil {
		return false, err
	}
	for _, r := range results {
		if r != nil {
			return false, nil
		}
	}
	return true, nil
}
