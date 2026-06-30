package pulsar

import "errors"

// Security-explicit error names (kept blunt on purpose).
var (
	ErrNonceTranscriptRevealsLowBitsW = errors.New("pulsar: nonce transcript reveals LowBits(w)")
	ErrForbiddenHintMaterial          = errors.New("pulsar: forbidden hint-secret material in production wire")
)
