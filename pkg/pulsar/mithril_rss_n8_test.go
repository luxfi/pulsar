package pulsar

import (
	"crypto/rand"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestMithrilRSS_LargeN_StockCircl proves the dealerless RSS key signs under stock
// circl mldsa65.Verify at committee sizes ADMITTED by dkg v0.3.2's per-(N,T) bound
// beyond the old N≤6 cap. The T==N cases (n=8,t=8; n=16,t=16) use the algorithmic
// base-case partition and work now; T<N at N>6 (n=8,t=7) needs the general
// Algorithm-6 partition (canonicalSharing currently table-limited to N≤6) — that
// gap is tracked separately.
func TestMithrilRSS_LargeN_StockCircl(t *testing.T) {
	for _, c := range []struct{ tt, n int }{{8, 8}, {16, 16}} {
		seeds := make([][]byte, c.n)
		for i := range seeds {
			seeds[i] = make([]byte, 32)
			rand.Read(seeds[i])
		}
		mk, err := MithrilRSSKeygen(ModeP65, c.tt, c.n, seeds)
		if err != nil {
			t.Fatalf("(t=%d,n=%d) keygen: %v", c.tt, c.n, err)
		}
		active := make([]int, c.tt)
		for i := range active {
			active[i] = i
		}
		msg := []byte("owner-large-committee")
		sig, err := mk.Sign(active, msg, nil, rand.Reader, 8000)
		if err != nil {
			t.Fatalf("(t=%d,n=%d) sign: %v", c.tt, c.n, err)
		}
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(mk.Pub()); err != nil {
			t.Fatalf("pk unmarshal: %v", err)
		}
		if !mldsa65.Verify(&pk, msg, nil, sig.Bytes) {
			t.Fatalf("(t=%d,n=%d) stock circl REJECTED the dealerless RSS signature", c.tt, c.n)
		}
		t.Logf("(t=%d,n=%d) dealerless RSS key (N>6, T==N) → stock circl mldsa65.Verify PASS", c.tt, c.n)
	}
}
