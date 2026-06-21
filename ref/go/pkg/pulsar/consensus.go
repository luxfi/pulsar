package pulsar

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Production BCC/CEF threshold ML-DSA wire + aggregation layer. NONE of
// these types or functions carry or compute c*s2, c*t0, r0,
// LowBits(residual), or full w (PULSAR-V13-HINT-LEAK / PULSAR-V13-W-LEAK).

// ---- Wire types (no hint-secret fields, no full w) ----

// NonceCert is a boundary-cleared nonce certificate. It carries only
// w1 = HighBits(w) (public, used in the challenge), a hiding commitment to w,
// and a validator-run NonceMPC clearance certificate (NonceTranscriptRoot +
// ClearanceQC) — NEVER full w, w_i shares, LowBits(w), boundary distances, or
// hint-secret material (PULSAR-V13-W-LEAK). The production clearance backend
// is the quorum-certified validator transcript; ClearanceProof is retained
// only for an optional pluggable ZK backend.
type NonceCert struct {
	NonceID           [32]byte
	PKEpoch           uint64
	CommitteeID       [32]byte
	SignerSetRoot     [32]byte
	W1                []byte // packed HighBits(w) — public
	WCommitment       []byte // hiding commitment to w
	Margin            uint32
	RegionRoot        [32]byte
	CommitRoot        [32]byte
	NonceTranscriptRoot [32]byte    // root of the validator NonceMPC transcript
	ClearanceQC       QuorumCert  // quorum of validators that verified the transcript
	ClearanceProof    []byte      // optional pluggable ZK backend (unused for the NonceMPC path)
	Consumed          bool
}

// Partial is a proof-carrying z-share. No CS2/CT0/r0/LowBits/hint fields.
type Partial struct {
	PartyID   uint32
	NonceID   [32]byte
	SessionID [32]byte
	ZShare    []byte // packed z_i
	Proof     []byte // partial-correctness proof (PROTOTYPE)
	MAC       []byte
}

// ConsensusCert is the two-certificate consensus artifact: the ML-DSA
// signature proves the joint key signed; the bitmap + transcript root prove
// which validators participated (BLS-like accountability).
type ConsensusCert struct {
	Epoch          uint64
	Height         uint64
	Round          uint64
	BlockHash      [32]byte
	JointPKID      [32]byte
	SignerBitmap   []byte
	TranscriptRoot [32]byte
	Signature      Signature
}

// ---- Canonical, non-grindable nonce selection ----

// CanonicalNonceIndex deterministically selects a nonce from the pool so a
// coordinator cannot grind w1 (hence the challenge) by choosing among many
// boundary-clear certs after seeing the message. Every signer MUST recompute
// and reject a non-canonical nonce for the session.
func CanonicalNonceIndex(sessionID, noncePoolRoot [32]byte, poolSize uint64) uint64 {
	if poolSize == 0 {
		return 0
	}
	h := sha3.NewShake256()
	_, _ = h.Write(sessionID[:])
	_, _ = h.Write(noncePoolRoot[:])
	_, _ = h.Write([]byte("PULSAR-BCC-CEF-v1-nonce"))
	var buf [8]byte
	_, _ = h.Read(buf[:])
	return binary.BigEndian.Uint64(buf[:]) % poolSize
}

// ---- Tree aggregation of z-shares (z-sum only) ----

func sumZ(into polyVec, sh polyVec, l int) {
	for i := 0; i < l && i < len(sh); i++ {
		into[i].add(&into[i], &sh[i])
		into[i].normalize()
	}
}

// FlatAggregateZ sums all z-shares (reference, mod q).
func FlatAggregateZ(shares []polyVec, l int) polyVec {
	acc := make(polyVec, l)
	for _, sh := range shares {
		sumZ(acc, sh, l)
	}
	return acc
}

// TreeAggregateZ aggregates pairwise so ~1000-signer consensus can fan-in
// without a single coordinator collecting all partials. Equals
// FlatAggregateZ (mod-q addition is associative). Tree nodes carry only
// z-sums (+ bitmaps + proof roots) — never c*s2/c*t0/r0/hint shares.
func TreeAggregateZ(shares []polyVec, l int) polyVec {
	switch len(shares) {
	case 0:
		return make(polyVec, l)
	case 1:
		out := make(polyVec, l)
		for i := 0; i < l && i < len(shares[0]); i++ {
			out[i] = shares[0][i]
			out[i].normalize()
		}
		return out
	default:
		mid := len(shares) / 2
		acc := TreeAggregateZ(shares[:mid], l)
		sumZ(acc, TreeAggregateZ(shares[mid:], l), l)
		return acc
	}
}

// ---- Coarse, privacy-preserving abort classes ----

// AbortClass is intentionally coarse: a rejected attempt must NOT reveal
// which honest signer or which coefficient caused a norm/hint/boundary
// failure (that would leak secret-dependent predicates). Only the class is
// published; internal detail stays local.
type AbortClass uint8

const (
	AbortNone AbortClass = iota
	AbortRetry
	AbortBadPartialProof
	AbortBadCommitment
	AbortReplay
)

func (a AbortClass) String() string {
	switch a {
	case AbortRetry:
		return "ABORT_RETRY"
	case AbortBadPartialProof:
		return "ABORT_BAD_PARTIAL_PROOF"
	case AbortBadCommitment:
		return "ABORT_BAD_COMMITMENT"
	case AbortReplay:
		return "ABORT_REPLAY"
	default:
		return "ABORT_NONE"
	}
}

// ---- Two-certificate consensus verification ----

var (
	ErrQuorumNotMet      = errors.New("pulsar: consensus cert bitmap weight below quorum")
	ErrSignerOutOfSet    = errors.New("pulsar: consensus cert bitmap selects a non-validator")
	ErrNonCanonicalNonce = errors.New("pulsar: non-canonical nonce for session")
)

func bitmapWeight(bm []byte) int {
	w := 0
	for _, b := range bm {
		for b != 0 {
			w += int(b & 1)
			b >>= 1
		}
	}
	return w
}

// VerifyStructure checks consensus-layer accountability: bitmap weight meets
// quorum and every set bit indexes a validator. The ML-DSA signature itself
// is verified separately by an unmodified FIPS 204 verifier.
func (c *ConsensusCert) VerifyStructure(quorum, validatorSetSize int) error {
	if bitmapWeight(c.SignerBitmap) < quorum {
		return ErrQuorumNotMet
	}
	for i := 0; i < len(c.SignerBitmap)*8; i++ {
		if c.SignerBitmap[i/8]&(1<<(uint(i)%8)) != 0 && i >= validatorSetSize {
			return ErrSignerOutOfSet
		}
	}
	return nil
}

// ---- Reflection guard: production wire types carry no hint-secret fields ----

func productionWireTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(NonceCert{}),
		reflect.TypeOf(Partial{}),
		reflect.TypeOf(ConsensusCert{}),
		reflect.TypeOf(QuorumCert{}),
		reflect.TypeOf(NonceVote{}),
		reflect.TypeOf(Aggregate{}),
	}
}

var forbiddenWireFieldFragments = []string{
	"CS2", "CT0", "Cs2", "Ct0", "D2Masked", "D0Masked",
	"R0Share", "LowBits", "HintShare", "HintInput", "MaskedCorrection",
	"Residual",
}

func typeHasForbiddenField(t reflect.Type) (string, bool) {
	if t.Kind() != reflect.Struct {
		return "", false
	}
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		for _, frag := range forbiddenWireFieldFragments {
			if strings.Contains(name, frag) {
				return name, true
			}
		}
	}
	return "", false
}
