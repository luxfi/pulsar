// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu_test

// gpu_test.go — surface tests for the pulsar gpu subpackage.
//
// Mirrors corona/gpu/gpu_test.go: idempotency of UseAccelerator, the
// flag-clear semantics of DisableAccelerator, RegisterRing /
// UnregisterRing round-trip on a synthetic lattice/v7 ring, the
// MaybeRegister no-op-when-disabled behaviour, and stats shape.
//
// The byte-equality contract — TestPulsar_GPU_ByteEqual — lives in the
// pulsar package (ref/go/pkg/pulsar/threshold_v03_gpu_byte_eq_test.go)
// because driving a full v0.3 algebraic threshold ceremony requires
// the package-private polyVec / unpackPolyVec helpers that
// Round2Sign's peer-W map consumes. The pulsar package's TEST import
// graph is allowed to reference gpu (and thus lattice/v7) — the
// non-test reference compile (go build ./ref/go/pkg/pulsar) does NOT
// pull lattice/v7.

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"

	"github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu"
)

// TestUseAcceleratorIdempotent — opting in twice is harmless and leaves
// the flag set.
func TestUseAcceleratorIdempotent(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAccelerator(); err != nil {
		t.Fatalf("UseAccelerator first call: %v", err)
	}
	if !gpu.Enabled() {
		t.Fatal("Enabled() false after first UseAccelerator")
	}
	if err := gpu.UseAccelerator(); err != nil {
		t.Fatalf("UseAccelerator second call: %v", err)
	}
	if !gpu.Enabled() {
		t.Fatal("Enabled() false after second UseAccelerator")
	}
}

// TestDisableAcceleratorClearsFlag — DisableAccelerator returns the
// global to its baseline state.
func TestDisableAcceleratorClearsFlag(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	gpu.DisableAccelerator()
	if gpu.Enabled() {
		t.Fatal("Enabled() true after DisableAccelerator")
	}
}

// TestRegisterRingIdempotent — calling RegisterRing twice with the same
// ring does not double-register SubRings.
func TestRegisterRingIdempotent(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gpu.UnregisterRing(r) })

	if err := gpu.RegisterRing(r); err != nil {
		// On non-GPU builds (no cgo / no Metal / no CUDA) lattice/v7/gpu
		// RegisterSubRing returns "GPU unavailable". The rest of the
		// surface is exercised by the other tests; skip this idempotency
		// check rather than failing.
		t.Skipf("GPU registration unavailable on this build: %v", err)
	}
	beforeStats := gpu.CurrentStats()
	if err := gpu.RegisterRing(r); err != nil {
		t.Fatalf("RegisterRing second: %v", err)
	}
	afterStats := gpu.CurrentStats()
	if beforeStats.RegisteredRings != afterStats.RegisteredRings {
		t.Fatalf("idempotency broken: %d -> %d", beforeStats.RegisteredRings, afterStats.RegisteredRings)
	}
}

// TestMaybeRegisterNoopWhenDisabled — when the accelerator is off,
// MaybeRegister leaves the SubRing registry untouched.
func TestMaybeRegisterNoopWhenDisabled(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	gpu.DisableAccelerator()

	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	before := gpu.CurrentStats()
	gpu.MaybeRegister(r)
	after := gpu.CurrentStats()
	if before.RegisteredRings != after.RegisteredRings {
		t.Fatalf("MaybeRegister mutated registry while disabled: %d -> %d",
			before.RegisteredRings, after.RegisteredRings)
	}
}

// TestUnregisterRing — unbinding restores the pre-register state.
func TestUnregisterRing(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	before := gpu.CurrentStats()
	if err := gpu.RegisterRing(r); err != nil {
		t.Skipf("GPU registration unavailable on this build: %v", err)
	}
	gpu.UnregisterRing(r)
	after := gpu.CurrentStats()
	if before.RegisteredRings != after.RegisteredRings {
		t.Fatalf("registry not restored: %d -> %d", before.RegisteredRings, after.RegisteredRings)
	}
}

// TestStatsShape — sanity check that CurrentStats returns a populated
// struct. Backend string is informational; we only assert it is set
// (lattice/v7/gpu always provides one even in the pure-Go build).
func TestStatsShape(t *testing.T) {
	s := gpu.CurrentStats()
	if s.Backend == "" {
		t.Fatal("Backend is empty")
	}
}

// TestSetThreshold — direct write to lattice/v7/gpu threshold via the
// wrapper. Surface-only; no semantic side effect beyond stats round-trip.
func TestSetThreshold(t *testing.T) {
	t.Cleanup(func() {
		gpu.SetThreshold(0)
	})
	gpu.SetThreshold(2048)
	if got := gpu.CurrentStats().Threshold; got != 2048 {
		t.Fatalf("Threshold not honored: got %d want 2048", got)
	}
	gpu.SetThreshold(0)
	if got := gpu.CurrentStats().Threshold; got != 0 {
		t.Fatalf("Threshold not cleared: got %d want 0", got)
	}
}

// TestUseAcceleratorForce — the threshold=1 mode dispatches every
// registered SubRing NTT to the GPU. Used by the byte-equal test in
// the pulsar package to exercise the dispatcher at small N.
func TestUseAcceleratorForce(t *testing.T) {
	t.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAcceleratorForce(); err != nil {
		t.Fatalf("UseAcceleratorForce: %v", err)
	}
	if !gpu.Enabled() {
		t.Fatal("Enabled() false after UseAcceleratorForce")
	}
	if got := gpu.CurrentStats().Threshold; got != 1 {
		t.Fatalf("forced threshold not 1: got %d", got)
	}
}
