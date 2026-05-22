// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_debug_shake.go — tiny shake helper for the debug test
// file. Lives outside the *_test.go suffix because shakeWriter needs
// to be visible to the debug test.

import "golang.org/x/crypto/sha3"

type shakeWriter interface {
	Write(p []byte) (int, error)
	Read(p []byte) (int, error)
}

func newShake256Impl() shakeWriter {
	return sha3.NewShake256()
}
