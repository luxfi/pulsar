package pulsar

import "errors"

// Tree aggregation for ~1000-validator committees. Tree nodes carry only
// z-sums, bitmaps, and proof roots — never hint material, w, or residual.

var (
	ErrDuplicateSigner = errors.New("pulsar: duplicate signer in tree aggregate")
	ErrWrongSessionAgg = errors.New("pulsar: aggregate session/nonce mismatch")
)

func bitmapsOverlap(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i]&b[i] != 0 {
			return true
		}
	}
	return false
}

func bitmapUnion(a, b []byte) []byte {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		var x, y byte
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		out[i] = x | y
	}
	return out
}

// MergeAggregates merges child Aggregates: identical session+nonce, DISJOINT
// bitmaps (no duplicate signer), z summed mod q.
func MergeAggregates(children []Aggregate, l int) (Aggregate, error) {
	if len(children) == 0 {
		return Aggregate{}, nil
	}
	sid, nid := children[0].SessionID, children[0].NonceID
	z := make(polyVec, l)
	var bitmap []byte
	for _, ch := range children {
		if ch.SessionID != sid || ch.NonceID != nid {
			return Aggregate{}, ErrWrongSessionAgg
		}
		if bitmapsOverlap(bitmap, ch.SignerBitmap) {
			return Aggregate{}, ErrDuplicateSigner
		}
		bitmap = bitmapUnion(bitmap, ch.SignerBitmap)
		sumZ(z, unpackPolyVec(ch.ZSum, l), l)
	}
	return Aggregate{SessionID: sid, NonceID: nid, SignerBitmap: bitmap, ZSum: packPolyVec(z)}, nil
}
