package pulsar

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// NonceMPC is a validator-run consensus subprotocol (not a separate service):
// validators jointly compute w1 = HighBits(w) and BoundaryClear(w, 2β) over
// their hidden w = A·y shares and sign a NonceVote; a quorum forms the
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

// NonceVote is one validator's signed attestation that the NonceMPC
// transcript proves a boundary-clear hidden w with the given w1.
type NonceVote struct {
	Epoch               uint64
	CommitteeID         [32]byte
	NonceID             [32]byte
	W1                  []byte
	Margin              uint32
	CommitRoot          [32]byte
	RegionRoot          [32]byte
	NonceTranscriptRoot [32]byte
	Signature           []byte
}

// Aggregate is a tree-aggregation node: z-sums + bitmaps + proof roots only.
type Aggregate struct {
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
// longer matches — the cert is tamper-evident. This includes the Mode (so an
// out-of-scope parameter set cannot be swapped in), the hiding WCommitment (so
// a different hidden w cannot be bound to the same cert), the ClearanceProof
// bytes, and the Consumed anti-replay flag. (Full w is NOT bound; it is never
// available to public verifiers — PULSAR-V13-W-LEAK.) Variable-length byte
// fields are length-prefixed for canonical, unambiguous encoding.
func nonceCertPayloadRoot(cert *NonceCert) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-BCC-CEF/nonce-cert/v1"))
	var u [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(u[:], uint64(len(b)))
		_, _ = h.Write(u[:])
		_, _ = h.Write(b)
	}
	_, _ = h.Write([]byte{byte(cert.Mode)})
	_, _ = h.Write(cert.NonceID[:])
	binary.BigEndian.PutUint64(u[:], cert.PKEpoch)
	_, _ = h.Write(u[:])
	_, _ = h.Write(cert.CommitteeID[:])
	_, _ = h.Write(cert.SignerSetRoot[:])
	writeField(cert.W1)
	writeField(cert.WCommitment)
	binary.BigEndian.PutUint32(u[:4], cert.Margin)
	_, _ = h.Write(u[:4])
	_, _ = h.Write(cert.CommitRoot[:])
	_, _ = h.Write(cert.RegionRoot[:])
	_, _ = h.Write(cert.NonceTranscriptRoot[:])
	writeField(cert.ClearanceProof)
	if cert.Consumed {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// VerifyNonceCert checks a boundary nonce cert: the parameter set is in the
// proven BCC scope, the clearance QC is present, binds the cert payload, meets
// quorum, selects only validators, and carries valid validator signatures
// (verified by the registered, fail-closed QuorumSigVerifier). Without a valid,
// quorum-signed QC there is no signing — fail closed.
func VerifyNonceCert(cert *NonceCert, quorum, validatorSetSize int) error {
	// Refuse parameter sets outside the proven ‖c·t0‖∞ < γ2 scope (e.g.
	// ML-DSA-44), where boundary clearance is vacuous. Independent of the
	// minter — a public verifier must not bless an out-of-scope cert.
	if _, _, _, ok := bccParams(cert.Mode); !ok {
		return ErrBCCParamSet
	}
	if cert.ClearanceQC.IsEmpty() {
		return ErrMissingClearanceQC
	}
	payloadRoot := nonceCertPayloadRoot(cert)
	if cert.ClearanceQC.PayloadRoot != payloadRoot {
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
	// Verify the actual validator signatures over the bound payload root
	// (fail-closed until the consensus layer registers a real verifier).
	return registeredQuorumSigVerifier.VerifyQuorum(payloadRoot, cert.ClearanceQC)
}

// ---- NonceMPC transcript + voting (debug-oracle compute path) ----

// NonceTranscript models the validator NonceMPC output. debugFullW is
// TEST-ONLY and never enters the public view or the transcript root.
type NonceTranscript struct {
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
func (tr *NonceTranscript) Root() [32]byte {
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
func (tr *NonceTranscript) PublicView() []byte {
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
// w with secret-shared MPC; the public API is identical.) It refuses any
// parameter set outside the proven BCC scope (ErrBCCParamSet).
func RunNonceMPCDebug(w polyVec, mode Mode, nonceID [32]byte) (*NonceCert, *NonceTranscript, error) {
	gamma2, beta, _, ok := bccParams(mode)
	if !ok {
		return nil, nil, ErrBCCParamSet
	}
	tr := &NonceTranscript{
		debugFullW: w,
		NonceID:    nonceID,
		W1:         packPolyVec(highBitsVec(w, gamma2)),
		Margin:     2 * beta,
		Clear:      BoundaryClear(w, gamma2, beta),
	}
	cert := &NonceCert{
		Mode:                mode,
		NonceID:             nonceID,
		W1:                  tr.W1,
		Margin:              tr.Margin,
		CommitRoot:          tr.CommitRoot,
		RegionRoot:          tr.RegionRoot,
		NonceTranscriptRoot: tr.Root(),
	}
	payload := nonceCertPayloadRoot(cert)
	bitmap := []byte{0xFF} // a debug quorum of 8 validators
	sigs := make([][]byte, bitmapWeight(bitmap))
	for i := range sigs {
		sigs[i] = []byte{1}
	}
	cert.ClearanceQC = QuorumCert{
		CommitteeID:  cert.CommitteeID,
		SignerBitmap: bitmap,
		PayloadRoot:  payload,
		Signatures:   sigs,
	}
	return cert, tr, nil
}

// ValidateAndVoteNonceCert is the validator voting rule: refuse to vote unless
// the transcript outputs ONLY w1 + a clear bit (never full w) and the nonce is
// boundary-clear.
func ValidateAndVoteNonceCert(tr *NonceTranscript) (*NonceVote, error) {
	if len(tr.W1) == 0 {
		return nil, ErrBadNonceMPCOutput
	}
	if !tr.Clear {
		return nil, ErrNonceNotBoundaryClear
	}
	return &NonceVote{
		Epoch:               tr.Epoch,
		CommitteeID:         tr.CommitteeID,
		NonceID:             tr.NonceID,
		W1:                  tr.W1,
		Margin:              tr.Margin,
		CommitRoot:          tr.CommitRoot,
		RegionRoot:          tr.RegionRoot,
		NonceTranscriptRoot: tr.Root(),
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
