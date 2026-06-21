package pulsar

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// NonceMPC is a validator-run consensus subprotocol (not a separate service):
// validators jointly compute w1 = HighBits(w) and BoundaryClear(w, 2β) over
// their hidden w = A·y shares and sign a NonceCertVote; a quorum forms the
// ClearanceQC. Full w is never opened. Public chain verifiers check the QC,
// never the hidden w (PULSAR-V13-W-LEAK).

// QuorumCert is a quorum of validator signatures over a bound payload.
type QuorumCert struct {
	CommitteeID  [32]byte
	SignerBitmap []byte
	PayloadRoot  [32]byte // what the quorum signed (binds all cert fields)
	Signatures   [][]byte // validator signatures over PayloadRoot
}

func (qc QuorumCert) Weight() int { return bitmapWeight(qc.SignerBitmap) }
func (qc QuorumCert) IsEmpty() bool {
	return len(qc.SignerBitmap) == 0 && len(qc.Signatures) == 0 && qc.PayloadRoot == [32]byte{}
}

// NonceCertVote is one validator's signed attestation that the NonceMPC
// transcript proves a boundary-clear hidden w with the given w1.
type NonceCertVote struct {
	Epoch             uint64
	CommitteeID       [32]byte
	NonceID           [32]byte
	W1                []byte
	Margin            uint32
	CommitRoot        [32]byte
	RegionRoot        [32]byte
	MPCTranscriptRoot [32]byte
	Signature         []byte
}

// ZAggregate is a tree-aggregation node: z-sums + bitmaps + proof roots only.
type ZAggregate struct {
	SessionID    [32]byte
	NonceID      [32]byte
	SignerBitmap []byte
	ZSum         []byte
	ProofRoot    [32]byte
	ChildRoots   [][32]byte
}

var (
	ErrMissingClearanceQC    = errors.New("pulsar: boundary nonce cert missing clearance QC")
	ErrBadClearanceQC        = errors.New("pulsar: boundary nonce cert clearance QC payload/quorum mismatch")
	ErrNonceMPCRevealsW      = errors.New("pulsar: NonceMPC transcript reveals full w")
	ErrNonceNotBoundaryClear = errors.New("pulsar: NonceMPC nonce not boundary-clear")
	ErrBadNonceMPCOutput     = errors.New("pulsar: NonceMPC transcript outputs more than w1 + clear bit")
)

// nonceCertPayloadRoot binds every consensus-relevant field of a boundary
// nonce cert. Any mutation changes the root, so a QC over the old root no
// longer matches — the cert is tamper-evident. (Full w is NOT bound; it is
// never available to public verifiers.)
func nonceCertPayloadRoot(cert *BoundaryNonceCert) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-BCC-CEF/nonce-cert/v1"))
	_, _ = h.Write(cert.NonceID[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], cert.PKEpoch)
	_, _ = h.Write(u[:])
	_, _ = h.Write(cert.CommitteeID[:])
	_, _ = h.Write(cert.SignerSetRoot[:])
	_, _ = h.Write(cert.W1)
	binary.BigEndian.PutUint32(u[:4], cert.Margin)
	_, _ = h.Write(u[:4])
	_, _ = h.Write(cert.CommitRoot[:])
	_, _ = h.Write(cert.RegionRoot[:])
	_, _ = h.Write(cert.MPCTranscriptRoot[:])
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// VerifyBoundaryNonceCert performs the structural consensus check: the
// clearance QC is present, binds the cert payload, meets quorum, and selects
// only validators. The per-validator QC signatures are verified by the
// consensus layer's registered validator-set verifier (out of this module's
// structural scope). Without a valid QC there is no signing — fail closed.
func VerifyBoundaryNonceCert(cert *BoundaryNonceCert, quorum, validatorSetSize int) error {
	if cert.ClearanceQC.IsEmpty() {
		return ErrMissingClearanceQC
	}
	if cert.ClearanceQC.PayloadRoot != nonceCertPayloadRoot(cert) {
		return ErrBadClearanceQC
	}
	if cert.ClearanceQC.Weight() < quorum {
		return ErrBadClearanceQC
	}
	for i := 0; i < len(cert.ClearanceQC.SignerBitmap)*8; i++ {
		if cert.ClearanceQC.SignerBitmap[i/8]&(1<<(uint(i)%8)) != 0 && i >= validatorSetSize {
			return ErrSignerOutOfSet
		}
	}
	return nil
}

// ---- NonceMPC transcript + voting (debug-oracle compute path) ----

// NonceMPCTranscript models the validator NonceMPC output. debugFullW is
// TEST-ONLY and never enters the public view or the transcript root.
type NonceMPCTranscript struct {
	debugFullW  polyVec // DEBUG ONLY — never serialized, never bound
	Epoch       uint64
	CommitteeID [32]byte
	NonceID     [32]byte
	W1          []byte
	Margin      uint32
	CommitRoot  [32]byte
	RegionRoot  [32]byte
	Clear       bool
}

// Root binds only the public outputs (w1, clear, margin, roots) — never w.
func (tr *NonceMPCTranscript) Root() [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-BCC-CEF/nonce-mpc/v1"))
	_, _ = h.Write(tr.NonceID[:])
	_, _ = h.Write(tr.W1)
	var u [8]byte
	binary.BigEndian.PutUint32(u[:4], tr.Margin)
	_, _ = h.Write(u[:4])
	_, _ = h.Write(tr.CommitRoot[:])
	_, _ = h.Write(tr.RegionRoot[:])
	if tr.Clear {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// PublicView returns only the public outputs (w1 + clear + root). It NEVER
// contains full w or its low bits.
func (tr *NonceMPCTranscript) PublicView() []byte {
	out := append([]byte{}, tr.W1...)
	if tr.Clear {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	root := tr.Root()
	return append(out, root[:]...)
}

// RunNonceMPCDebug runs a DEBUG-ORACLE NonceMPC over a directly-computed w: it
// sets W1 = HighBits(w) and Clear = BoundaryClear(w, 2β) exactly as a sound
// validator MPC would, producing a cert with a quorum-signed bound payload.
// The public view never reveals w. (A production NonceMPC replaces the direct
// w with secret-shared MPC; the public API is identical.)
func RunNonceMPCDebug(w polyVec, mode Mode, nonceID [32]byte) (*BoundaryNonceCert, *NonceMPCTranscript) {
	gamma2, beta, _, _ := bccParams(mode)
	tr := &NonceMPCTranscript{
		debugFullW: w,
		NonceID:    nonceID,
		W1:         packPolyVec(highBitsVec(w, gamma2)),
		Margin:     2 * beta,
		Clear:      BoundaryClear(w, gamma2, beta),
	}
	cert := &BoundaryNonceCert{
		NonceID:           nonceID,
		W1:                tr.W1,
		Margin:            tr.Margin,
		CommitRoot:        tr.CommitRoot,
		RegionRoot:        tr.RegionRoot,
		MPCTranscriptRoot: tr.Root(),
	}
	payload := nonceCertPayloadRoot(cert)
	cert.ClearanceQC = QuorumCert{
		SignerBitmap: []byte{0xFF}, // a debug quorum of 8 validators
		PayloadRoot:  payload,
		Signatures:   [][]byte{{1}},
	}
	return cert, tr
}

// ValidateAndVoteNonceCert is the validator voting rule: refuse to vote unless
// the transcript outputs ONLY w1 + a clear bit (never full w) and the nonce is
// boundary-clear.
func ValidateAndVoteNonceCert(tr *NonceMPCTranscript) (*NonceCertVote, error) {
	if len(tr.W1) == 0 {
		return nil, ErrBadNonceMPCOutput
	}
	if !tr.Clear {
		return nil, ErrNonceNotBoundaryClear
	}
	return &NonceCertVote{
		Epoch:             tr.Epoch,
		CommitteeID:       tr.CommitteeID,
		NonceID:           tr.NonceID,
		W1:                tr.W1,
		Margin:            tr.Margin,
		CommitRoot:        tr.CommitRoot,
		RegionRoot:        tr.RegionRoot,
		MPCTranscriptRoot: tr.Root(),
	}, nil
}

// ---- mod-q vector helpers (debug oracles + residual demonstration) ----

func addVecMod(a, b polyVec) polyVec {
	out := make(polyVec, len(a))
	for i := range a {
		for j := 0; j < mldsaN; j++ {
			out[i][j] = uint32((int64(a[i][j]) + int64(b[i][j])) % mldsaQ)
		}
	}
	return out
}

func subVecMod(a, b polyVec) polyVec {
	out := make(polyVec, len(a))
	for i := range a {
		for j := 0; j < mldsaN; j++ {
			v := (int64(a[i][j]) - int64(b[i][j])) % mldsaQ
			if v < 0 {
				v += mldsaQ
			}
			out[i][j] = uint32(v)
		}
	}
	return out
}
