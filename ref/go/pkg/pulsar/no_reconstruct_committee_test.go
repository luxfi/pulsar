// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// no_reconstruct_committee_test.go — the two HARD GATES for the
// no-reconstruct committee threshold-sign fix (fix/no-reconstruct-committee).
//
// GATE 1 (standard-verifier): a committee threshold signature produced by the
// no-reconstruct path (DistributedBCCSigner / AggregateBCC) verifies under the
// INDEPENDENT, unmodified cloudflare/circl mldsa65.Verify — the group public
// key is re-derived and checked by circl alone. Bytes/acceptance preserved.
//
// GATE 2 (no-reconstruct INVARIANT): the committee sign-combine NEVER
// materialises the secret. Proven STRUCTURALLY (the production build contains
// no KeyFromSeed call in any sign-combine file; the reconstruct-at-sign combiner
// LargeCombine has been DELETED from the package entirely —
// ci_build_invariant_test.go guards that it never returns) AND BEHAVIOURALLY
// (the combiner's inputs — Partial, AggregateBCC's parameters — carry no share,
// sk, seed, or nonce; a sub-threshold coalition cannot sign).
//
// CLAIM DISCIPLINE. What these gates establish: "no-reconstruct committee
// threshold signing whose output verifies under the standard ML-DSA verifier."
// They do NOT establish FIPS-204 KeyGen-distribution equivalence (a separate
// hiding/simulation argument) and NOT FIPS validation.

import (
	"crypto/rand"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ─────────────────────────────────────────────────────────────────────────
// GATE 1 — the committee no-reconstruct signature verifies under circl alone.
// ─────────────────────────────────────────────────────────────────────────

// TestCommittee_NoReconstruct_VerifiesUnderCircl runs a real (t,n)=(4,7)
// committee no-reconstruct ceremony (each validator a SEPARATE signer holding
// ONE s1-share; combiner sees only z-partials) and checks the aggregated
// signature with cloudflare/circl's stock mldsa65.Verify — the independent
// reference verifier — by re-deriving the public key into a circl PublicKey
// and calling Verify directly. A tampered message must be rejected.
func TestCommittee_NoReconstruct_VerifiesUnderCircl(t *testing.T) {
	const n, threshold = 7, 4
	f := newBCCFixture(t, ModeP65, n, threshold)

	var sid [32]byte
	copy(sid[:], []byte("no-reconstruct-committee-gate-1"))
	msg := []byte("committee finality: no-reconstruct threshold ML-DSA-65")

	sig, nodes, err := runBCCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("committee no-reconstruct ceremony: %v", err)
	}

	// Custody: every node held exactly one share; the combiner is one node.
	seen := make(map[NodeID]bool, len(nodes))
	for i, nd := range nodes {
		if got := nd.ShareCount(); got != 1 {
			t.Fatalf("node %d ShareCount=%d, want 1 (single-share custody violated)", i, got)
		}
		if seen[nd.NodeID()] {
			t.Fatalf("node %d co-locates a NodeID with another node", i)
		}
		seen[nd.NodeID()] = true
	}

	// INDEPENDENT verifier: re-derive the group pk into a circl PublicKey and
	// verify with stock circl mldsa65.Verify (ctx = empty, matching the bare
	// ceremony). This is the same call path the EVM precompile's reference
	// verifier uses — no pulsar code in the loop.
	if len(sig.Bytes) != f.params.SignatureSize {
		t.Fatalf("signature size %d, want %d", len(sig.Bytes), f.params.SignatureSize)
	}
	var pk mldsa65.PublicKey
	var pkBuf [mldsa65.PublicKeySize]byte
	if len(f.setup.Pub.Bytes) != mldsa65.PublicKeySize {
		t.Fatalf("group pk size %d, want %d", len(f.setup.Pub.Bytes), mldsa65.PublicKeySize)
	}
	copy(pkBuf[:], f.setup.Pub.Bytes)
	pk.Unpack(&pkBuf)

	if !mldsa65.Verify(&pk, msg, nil, sig.Bytes) {
		t.Fatalf("GATE 1 FAILED: circl mldsa65.Verify REJECTED the no-reconstruct committee signature")
	}

	// Negative control: a one-bit message tamper must be rejected by circl.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if mldsa65.Verify(&pk, bad, nil, sig.Bytes) {
		t.Fatalf("GATE 1 FAILED: circl accepted a tampered message — binding broken")
	}
	t.Logf("GATE 1 PASS: circl mldsa65.Verify accepts the (t,n)=(%d,%d) no-reconstruct committee signature; tamper rejected", threshold, n)
}

// ─────────────────────────────────────────────────────────────────────────
// GATE 2 (structural) — no KeyFromSeed in the production sign-combine path,
// and the reconstruct combiner is not in the production build at all.
// ─────────────────────────────────────────────────────────────────────────

// keyFromSeedCall matches a CALL to KeyFromSeed (the seed→sk reconstruct
// primitive) while NOT matching circl's NewKeyFromSeed or the bare word in
// prose: it requires a non-identifier byte immediately before "KeyFromSeed(".
var keyFromSeedCall = regexp.MustCompile(`(^|[^A-Za-z0-9_])KeyFromSeed\(`)

// keyFromSeedCallAllowlist is the ONLY set of production files permitted to
// call KeyFromSeed. Both are KEYGEN, never sign-combine:
//   - keygen.go: defines KeyFromSeed and the single-key GenerateKey wrapper.
//   - dkg.go: the small-committee DKG derives the GROUP PUBLIC KEY once at
//     keygen by forming sk (a flagged keygen-side residual — NOT signing).
var keyFromSeedCallAllowlist = map[string]bool{
	"keygen.go": true,
	"dkg.go":    true,
}

func TestCommittee_NoReconstruct_Invariant_NoKeyFromSeedInProductionBuild(t *testing.T) {
	// Enumerate the package's PRODUCTION (default-build, non-test) Go files —
	// the exact set a production binary links.
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("enumerate default-build package files: %v", err)
	}

	// (a) No production file may CALL KeyFromSeed (the seed→sk reconstruct
	//     primitive) except the keygen allowlist. The reconstruct-at-sign combiner
	//     LargeCombine was DELETED from the package; ci_build_invariant_test.go is
	//     the structural guard that it (and the trusted dealer) never reappear.
	offenders := 0
	for _, f := range pkg.GoFiles {
		src, err := os.ReadFile(filepath.Join(pkg.Dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(src)
		if keyFromSeedCall.MatchString(text) && !keyFromSeedCallAllowlist[f] {
			t.Errorf("GATE 2 FAILED: %s calls KeyFromSeed (seed→sk reconstruct) but is not an allowlisted keygen file", f)
			offenders++
		}
	}
	if offenders > 0 {
		t.Fatalf("GATE 2 FAILED: %d production file(s) reconstruct the secret key", offenders)
	}

	// (b) The load-bearing combiner file itself must be free of every
	//     reconstruct vector: no KeyFromSeed, no key-material expansion, no
	//     master-seed assembly, no GF(q) SEED reconstruction.
	combine, err := os.ReadFile(filepath.Join(pkg.Dir, "distributed_bcc.go"))
	if err != nil {
		t.Fatalf("read distributed_bcc.go: %v", err)
	}
	for _, banned := range []string{"KeyFromSeed(", "deriveKeyMaterial(", "masterSeed", "shamirReconstructGFQ"} {
		if strings.Contains(string(combine), banned) {
			t.Fatalf("GATE 2 FAILED: distributed_bcc.go (AggregateBCC sign-combine) contains reconstruct vector %q", banned)
		}
	}

	t.Logf("GATE 2 (structural) PASS: %d production files scanned; KeyFromSeed only in %v; AggregateBCC reconstruct-free",
		len(pkg.GoFiles), keysOf(keyFromSeedCallAllowlist))
}

// ─────────────────────────────────────────────────────────────────────────
// GATE 2 (behavioural) — the combiner is handed only z-partials and public
// material; nothing it receives can reconstruct the secret.
// ─────────────────────────────────────────────────────────────────────────

func TestCommittee_NoReconstruct_Invariant_CombinerSeesNoSecret(t *testing.T) {
	// (a) Partial is the ONLY per-signer artifact the combiner ingests. It must
	//     carry no secret: no s1-share, no nonce-share, no seed, no sk. ZShare
	//     is the MASKED response z_i = λ_i·y_i + c·λ_i·s1_i (the same quantity a
	//     normal ML-DSA signature reveals), not a secret.
	bannedFieldName := []string{"S1", "S1Share", "Seed", "Sk", "Secret", "YShare", "NonceShare", "Master", "PrivateKey", "Lambda"}
	bannedTypeSubstr := []string{"AlgShare", "PrivateKey", "mldsaKeyMaterial", "polyVec", "poly"}
	pt := reflect.TypeOf(Partial{})
	for i := 0; i < pt.NumField(); i++ {
		fld := pt.Field(i)
		for _, b := range bannedFieldName {
			if fld.Name == b {
				t.Fatalf("GATE 2 FAILED: Partial.%s — the combiner's input carries a secret-bearing field", fld.Name)
			}
		}
		ts := fld.Type.String()
		for _, b := range bannedTypeSubstr {
			if strings.Contains(ts, b) {
				t.Fatalf("GATE 2 FAILED: Partial.%s has secret-bearing type %s", fld.Name, ts)
			}
		}
	}

	// (b) AggregateBCC is the free-function no-reconstruct boundary. Its
	//     parameter list must carry NO share / sk / key-material type — only
	//     public setup, public challenge/commitment, ids, and []Partial.
	at := reflect.TypeOf(AggregateBCC)
	for i := 0; i < at.NumIn(); i++ {
		ts := at.In(i).String()
		for _, b := range []string{"AlgShare", "PrivateKey", "mldsaKeyMaterial"} {
			if strings.Contains(ts, b) {
				t.Fatalf("GATE 2 FAILED: AggregateBCC parameter %d is secret-bearing type %s", i, ts)
			}
		}
	}

	// (c) Behavioural threshold bound: a combiner handed t-1 valid partials
	//     cannot produce a signature (it never has enough to reconstruct, and
	//     by design it could not reconstruct even with t). End-to-end.
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("gate2-subquorum"))
	msg := []byte("a sub-threshold coalition must not sign")

	quorum, evalPoints, qshares := f.quorum(threshold)
	var nonceID [32]byte
	nonceID[0] = 0x9c
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("nonce deal: %v", err)
	}
	nodes := make([]*DistributedBCCSigner, threshold)
	partials := make([]Partial, 0, threshold)
	var aggR1 SignRound1
	for i := 0; i < threshold; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		// Trusted in-memory bus: opt OUT of origin-auth explicitly (a bare nil
		// verifier is refused FAIL-CLOSED). The no-reconstruct / threshold bound
		// under test is orthogonal to origin authentication.
		nd.SetIdentity(nil, UnauthenticatedAggregation)
		nodes[i] = nd
		if err := nd.SetNonceShare(nonceID, deal.YShares[quorum[i]]); err != nil {
			t.Fatalf("set nonce share %d: %v", i, err)
		}
		r1, err := nd.Round1(sid, nonceID, deal.Cert)
		if err != nil {
			t.Fatalf("round1 %d: %v", i, err)
		}
		if nd.IsAggregator() {
			aggR1 = r1
		}
		p, err := nd.Round2(r1, PartialInput{})
		if err != nil {
			t.Fatalf("round2 %d: %v", i, err)
		}
		partials = append(partials, p)
	}
	var agg *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			agg = nd
		}
	}
	if _, _, err := agg.Finalize(aggR1, partials[:threshold-1]); err == nil {
		t.Fatalf("GATE 2 FAILED: combiner produced a signature from t-1 partials")
	}
	t.Logf("GATE 2 (behavioural) PASS: Partial + AggregateBCC carry no secret; t-1 partials cannot sign")
}

// keysOf returns the sorted-ish key list of a string-set (for log output).
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
