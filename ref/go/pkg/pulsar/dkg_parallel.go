// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// dkgGPUEnabled is the runtime toggle for the goroutine fan-out path of
// the Pulsar DKG hot loop. Default off; tests opt in via SetDKGGPUForTest.
// Real GPU NTT for the underlying ring math lives in luxfi/lattice/v7/gpu
// and is reached via the consensus engine accel pipeline.
func init() { dkgGPUEnabled = false }
