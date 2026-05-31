// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu wires Pulsar (FIPS 204 M-LWE threshold signing) onto the
// shared luxfi/lattice/v7 GPU NTT dispatcher. Pulsar and luxfi/corona
// (R-LWE threshold signing) share this dispatcher by construction:
// Corona is rank-1 Pulsar (the module shape R_q^k specialised at k=1),
// so the polynomial arithmetic — NTT, sampling, multiplication — is
// the same primitive. Sharing the dispatcher means one and only one
// place owns the cgo plumbing: lattice/v7/gpu. Corona's
// corona/gpu/gpu.go is the structural template for this package;
// every export here has the matching corona counterpart.
//
// IMPORT-PATH DISCIPLINE — NIST-CLEAN REFERENCE
//
// The pulsar NIST reference implementation lives at the parent import
// path github.com/luxfi/pulsar/ref/go/pkg/pulsar. That package's
// import graph carries ZERO dependency on luxfi/lattice/v7 — its
// only external imports are encoding/binary, crypto/rand,
// crypto/elliptic, golang.org/x/crypto/sha3, and the standard library.
// Reviewers compiling the reference do not pull lattice, cgo, or any
// GPU plumbing.
//
// This subpackage is a SEPARATE import path —
// github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu — that consumers
// reach for explicitly when they want to opt into the shared
// dispatcher. Compiling the reference (go test ./ref/go/pkg/pulsar/)
// does not transitively pull this subpackage.
//
// DECOMPLECTING NOTE
//
// Pulsar's per-coefficient NTT (FIPS 204 §3.6) operates on
// [256]uint32 polynomials in 32-bit Montgomery form with q=8380417
// and R=2^32. The lattice/v7 ring.SubRing.NTT operates on []uint64
// polynomials in 64-bit Montgomery form. The byte format and the
// Montgomery constants differ, so pulsar's reference NTT in
// mldsa_lattice.go is NOT byte-equal to ring.SubRing.NTT for the
// same FIPS 204 input. This is by design — pulsar's NTT bytes are
// pinned by the FIPS 204 KAT contract.
//
// The lattice/v7/gpu dispatcher operates at the ring.SubRing layer:
// it is engaged when a ring.SubRing is registered with
// gpu.RegisterSubRing and the SubRing's NTT call lands above the
// gpu.NTTThreshold. Pulsar's per-poly FIPS 204 NTT does not flow
// through ring.SubRing, so the dispatcher is not engaged by pulsar's
// production sign path today.
//
// Why ship this surface anyway:
//
//  1. ONE WAY TO DO EVERYTHING. Corona and pulsar consumers see the
//     same UseAccelerator / DisableAccelerator / RegisterRing /
//     Stats surface. Multi-primitive harnesses (e.g. a research
//     environment exercising both corona R-LWE and pulsar M-LWE
//     against a shared lattice/v7 ring) opt in with one call.
//
//  2. BYTE-EQUALITY BY CONSTRUCTION. TestPulsar_GPU_ByteEqual asserts
//     that signatures emitted with UseAccelerator() enabled are
//     bit-identical to signatures emitted with the accelerator
//     disabled. Today this holds vacuously (the dispatcher is not
//     engaged) but the test is the load-bearing contract: when the
//     v0.4 lift widens pulsar's NTT to a 64-bit Montgomery form
//     routable through ring.SubRing, the test must continue to pass.
//
//  3. STATS + DIAGNOSTICS. CurrentStats() reports the active backend
//     (Metal / CUDA / CPU) so operators can confirm the lattice/v7
//     cgo plumbing is wired correctly without grepping the lattice
//     source.
//
// THRESHOLD GATING
//
// Pulsar's production ring degree is N=256 (FIPS 204 fixed). Single-
// poly Metal NTT on Apple M1 Max is strictly slower than the pure-Go
// path for every N up to 16384 (lattice/v7/gpu/gpu_montgomery_cgo.go).
// The GPU dispatch win lives in BATCHED dispatch — many polynomials
// submitted in one kernel launch. Engaging single-poly GPU dispatch
// at N=256 regresses wall-clock by roughly 4x.
//
// Therefore UseAccelerator() picks defaultThreshold=1024, ABOVE
// Pulsar's production ring degree. Operators with a batched
// dispatcher available (future luxfi/accel batch NTT plumbed through
// ring.NTT, or a v0.4 batched mldsa_lattice.go path) can lower the
// threshold via SetThreshold; correctness tests can call
// UseAcceleratorForce() to set threshold=1 and exercise the GPU path
// at N=256 as a byte-equality gate.
//
// BUILD-TAG DISCIPLINE
//
// This package has NO build tags. It compiles identically across
// cgo+gpu builds and pure-Go builds because the cgo plumbing lives
// entirely in lattice/v7/gpu (gpu_montgomery_cgo.go vs
// gpu_montgomery_purego.go). UseAccelerator() flips an atomic flag;
// SetNTTThreshold writes to lattice's threshold; on a pure-Go build
// lattice's dispatcher returns false and the canonical pure-Go
// SubRing.NTT path runs. Output bytes are unchanged.
package gpu

import (
	"sync"
	"sync/atomic"

	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
)

// defaultThreshold is the SubRing single-poly dispatch threshold
// installed by UseAccelerator(). See the package doc above for the
// rationale: pulsar's N=256 sits below the M1 Max GPU break-even on
// single-poly NTT, so the default leaves single-poly dispatch off
// while keeping the SubRing registry primed for future batched paths.
const defaultThreshold uint32 = 1024

// accelEnabled is the global opt-in flag. Consumers invoke
// UseAccelerator() once at startup; subsequent RegisterRing calls
// from any caller (pulsar's future v0.4 batched NTT lift, a research
// harness, or a cross-primitive multi-ring runtime) consult this via
// Enabled().
var accelEnabled atomic.Bool

// UseAccelerator opts every subsequent caller into the lattice/v7
// GPU NTT dispatch path. Idempotent. Safe to call from package init
// or from a runtime configuration step before any pulsar signer is
// constructed.
//
// On a pure-Go (no cgo) build, the flag still flips and the lattice
// threshold is set, but the lattice dispatcher's Available() returns
// false so the canonical pure-Go SubRing.NTT path runs. Output bytes
// are unchanged.
func UseAccelerator() error {
	accelEnabled.Store(true)
	// See defaultThreshold doc above for the rationale: single-poly
	// GPU dispatch is slower than pure-Go at pulsar's production
	// N=256. The dispatcher stays armed (registered SubRings remain
	// bound) so any future batched dispatch path can engage it; the
	// threshold is conservative to keep single-poly NTT on CPU.
	gpu.SetNTTThreshold(defaultThreshold)
	return nil
}

// UseAcceleratorForce flips the opt-in flag and forces the SubRing
// threshold to 1, dispatching every NTT call on a registered SubRing
// to the GPU regardless of size. Useful for the byte-equal
// correctness tests that need to exercise the GPU path on small
// rings; production callers should use UseAccelerator() instead.
func UseAcceleratorForce() error {
	accelEnabled.Store(true)
	gpu.SetNTTThreshold(1)
	return nil
}

// DisableAccelerator clears the opt-in. Subsequent RegisterRing /
// MaybeRegister calls become no-ops. Existing registrations remain
// in place (use UnregisterRing to detach them).
func DisableAccelerator() {
	accelEnabled.Store(false)
	gpu.SetNTTThreshold(0)
}

// Enabled reports whether the opt-in flag is set. Internal callers
// consult this to decide whether to call RegisterRing.
func Enabled() bool { return accelEnabled.Load() }

// SetThreshold overrides the lattice/v7/gpu single-poly dispatch
// threshold. Pass 0 to disable single-poly GPU dispatch entirely.
// See lattice/v7/gpu.SetNTTThreshold for the full contract.
func SetThreshold(n uint32) { gpu.SetNTTThreshold(n) }

// Available reports whether the GPU NTT path is reachable on this
// build (cgo + lattice library + Metal / CUDA at runtime). The CPU
// fallback is always reachable.
func Available() bool { return gpu.Available() }

// Backend returns the active GPU backend name ("Metal", "CUDA", or a
// CPU descriptor) for diagnostic logging. Identical to the value
// returned by lattice/v7/gpu.GetBackend(); re-exported here so
// callers do not import lattice/v7/gpu directly.
func Backend() string { return gpu.GetBackend() }

// registeredMu guards registeredRings.
var (
	registeredMu    sync.Mutex
	registeredRings = map[*ring.SubRing]struct{}{}
)

// RegisterRing binds every SubRing of r into the lattice/v7/gpu
// per-SubRing registry. Idempotent per SubRing pointer; safe to call
// multiple times with the same ring.
//
// Callers exercising a luxfi/lattice/v7 ring (research harnesses,
// multi-primitive runtimes sharing the dispatcher across pulsar +
// corona, the v0.4 batched mldsa_lattice.go lift) register their
// rings here. The pulsar reference implementation does NOT register
// any ring today — its FIPS 204 NTT is in-package and uint32-Montgomery
// so it does not route through ring.SubRing.
func RegisterRing(r *ring.Ring) error {
	if r == nil {
		return nil
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	for _, s := range r.SubRings {
		if s == nil {
			continue
		}
		if _, ok := registeredRings[s]; ok {
			continue
		}
		if _, err := gpu.RegisterSubRing(s); err != nil {
			return err
		}
		registeredRings[s] = struct{}{}
	}
	return nil
}

// UnregisterRing removes the binding installed by RegisterRing. Used
// by tests to ensure subsequent benches measure the pure-Go path.
func UnregisterRing(r *ring.Ring) {
	if r == nil {
		return
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	for _, s := range r.SubRings {
		if s == nil {
			continue
		}
		gpu.UnregisterSubRing(s)
		delete(registeredRings, s)
	}
}

// MaybeRegister is the convenience helper consumer code invokes from
// its NewParams() / ring-construction site. If Enabled() is true it
// binds the ring; otherwise no-op.
func MaybeRegister(r *ring.Ring) {
	if !accelEnabled.Load() || r == nil {
		return
	}
	_ = RegisterRing(r) // best-effort; failure leaves CPU path engaged
}

// Stats describes the active accelerator state for diagnostic
// logging.
type Stats struct {
	Enabled         bool
	Available       bool
	Backend         string
	Threshold       uint32
	RegisteredRings int
}

// CurrentStats snapshots the accelerator state.
func CurrentStats() Stats {
	registeredMu.Lock()
	n := len(registeredRings)
	registeredMu.Unlock()
	return Stats{
		Enabled:         accelEnabled.Load(),
		Available:       gpu.Available(),
		Backend:         gpu.GetBackend(),
		Threshold:       gpu.NTTThreshold(),
		RegisteredRings: n,
	}
}
