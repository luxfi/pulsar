// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// distributed_bcc.go — the concrete, no-reconstruct, single-share
// threshold ML-DSA signer for the current (post-v0.3) Pulsar model.
//
// THE PROBLEM THIS CLOSES (PULSAR-V12-PARALLEL-PQ, forward path item 1):
//
//	The public KeyShare (types.go) is a GF(257) byte-share of the 32-byte
//	ML-DSA SEED. ML-DSA's s1/s2 are a NON-LINEAR SHAKE expansion of the
//	seed, so seed-shares admit ONLY Lagrange reconstruct-then-sign
//	(Combine / LargeCombine — the H-1 footgun that materialises the master
//	key in the aggregator). The new RoundSigner / Partial / FlatAggregateZ
//	model carried the interface and the z-sum aggregation primitive for a
//	no-reconstruct signer, but NO concrete poly-vector share type or
//	concrete RoundSigner implementor existed on the current line (the v0.3
//	AlgebraicKeyShare stack was removed in b185533).
//
// THE FIX (this file):
//
//	AlgShare is a poly-vector Shamir share of the EXPANDED signing-key
//	component s1 (length L) over GF(q), at the party's evaluation point.
//	Because s1 enters the BCC/CEF response z = y + c·s1 LINEARLY, the
//	per-party partial
//
//	    z_i = λ_i·y_i + c·λ_i·s1_i        (over R_q^L)
//
//	aggregates Lagrange-linearly to z = ȳ + c·s1 WITHOUT ever forming s1
//	(let alone the seed): Σ_i z_i = (Σ_i λ_i·y_i) + c·(Σ_i λ_i·s1_i) =
//	ȳ + c·s1. The hint is recovered from the PUBLIC w' = A·z − c·t1·2^d
//	via FindHint exactly as the single-key BCC signer (bcc_sign.go) does,
//	so the aggregator never holds s1, s2, t0, r0, or full w. Each node
//	holds EXACTLY ONE AlgShare; the designated aggregator (quorum[0])
//	combines collected z-partials — its Finalize signature takes
//	[]Partial, NEVER a share, sk, or seed.
//
// WHY ONLY s1 (not s1,s2,t0). The BCC/CEF path is precisely the
// construction that touches NEITHER s2 NOR t0 when signing: the hint
// comes from public data (FindHint over w'), so c·s2 and c·t0 are never
// computed (PULSAR-V13-HINT-LEAK). Sharing s2/t0 would (a) be unused dead
// secret material and (b) reopen the very leak vector the V13 line closed
// (DKGPublicOutput carries no t0; TestNoT0* enforce it). The codebase's
// own invariant states it: "Online signing needs only s1_i, y_i (held
// locally) and public t1" (dkg_wellformed.go). AlgShare follows that
// invariant: s1 only.
//
// SAME KERNEL, DECOMPLECTED CUSTODY. The arithmetic of each round is
// byte-identical to what the single-key bcc_sign.go computes on the joint
// (ȳ, s1); this file only distributes the custody boundary so no process
// holds ≥ t shares. The unforgeability / (t−1)-privacy argument is the
// standard threshold-of-a-linear-response reduction (FROST-shaped: masks
// summed, secret shares Lagrange-weighted), inheriting ML-DSA's EUF-CMA
// under Module-LWE/Module-SIS.
//
// WHAT THIS FILE IS NOT — the two fences that remain open:
//   - Part-1 KEYGEN here is a TRUSTED DEALER (DealAlgShares expands the
//     seed once, shares s1, wipes). It is no-RECONSTRUCT at SIGN time, not
//     dealerless at KEYGEN time. Dealerless ML-DSA DKG is the separate,
//     research-blocked Part-2 problem (see distributed_bcc_dkg.go).
//   - The joint nonce ȳ is established by DealNonceMPCDebug, a stand-in
//     for the validator NonceMPC. It reveals the joint commitment w to the
//     harness — exactly the leak production must avoid (PULSAR-V13-W-LEAK).
//     The leak-free distributed nonce (HighBits-over-shares without
//     revealing w) remains fail-closed behind the same exact-ℓ∞-range-proof
//     wall as rangeproof.go. The SIGNING decomposition below is independent
//     of how the nonce was established and is the load-bearing deliverable.

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

// Errors specific to the distributed BCC signer.
var (
	// ErrAlgNilShare is returned when a DistributedBCCSigner is constructed
	// without exactly one AlgShare.
	ErrAlgNilShare = errors.New("pulsar: distributed BCC signer requires exactly one AlgShare")

	// ErrAlgNoNonceShare is returned when Round1/Round2 run before a nonce
	// share has been delivered by the NonceMPC (SetNonceShare).
	ErrAlgNoNonceShare = errors.New("pulsar: distributed BCC signer has no nonce share (SetNonceShare first)")

	// ErrAlgNotAggregator is returned when Finalize is called on a node that
	// is not the designated aggregator (quorum[0]).
	ErrAlgNotAggregator = errors.New("pulsar: only the designated aggregator (quorum[0]) can Finalize")

	// ErrAlgSessionMismatch / ErrAlgNonceMismatch guard round binding.
	ErrAlgSessionMismatch = errors.New("pulsar: distributed BCC round session mismatch")
	ErrAlgNonceMismatch   = errors.New("pulsar: distributed BCC round nonce mismatch")

	// ErrAlgShareShape rejects a malformed share / setup.
	ErrAlgShareShape = errors.New("pulsar: AlgShare shape does not match the parameter set")

	// ErrAlgNonceExhausted is returned by DealNonceMPCDebug when it cannot
	// find a boundary-clear joint nonce within its attempt budget.
	ErrAlgNonceExhausted = errors.New("pulsar: nonce MPC exhausted its budget without a boundary-clear joint nonce")
)

// AlgShare is one validator's poly-vector Shamir share of the ML-DSA
// signing-key component s1, evaluated at the party's GF(q) Shamir point.
//
// CUSTODY: a DistributedBCCSigner holds exactly one *AlgShare (a single
// pointer, never a slice). There is no field, constructor, or method by
// which it comes to hold a second party's share. AlgShare carries s1 only
// — never s2, t0, the seed, or the full secret t — so it cannot be used to
// reconstruct the leaking MakeHint residual even in principle.
type AlgShare struct {
	NodeID    NodeID
	EvalPoint uint32  // Shamir x-coordinate in [1, q); distinct per party
	S1Share   polyVec // length L; Shamir share of s1 at EvalPoint, coeff-wise over GF(q)
	Mode      Mode
}

// AlgSetup is the public setup shared by the whole committee: the group
// ML-DSA public key, the matrix A (NTT domain), tr, and t1. NO master sk
// inside; identical for every party.
type AlgSetup struct {
	Mode Mode
	Pub  *PublicKey
	rho  [32]byte
	tr   [64]byte
	a    []polyVec // K×L public matrix, NTT domain (== circl pk.A)
	t1   polyVec   // K, high bits in [0, 2^10)

	// s1ShareCommit holds the per-party (keyed by GF(q) eval point) BDLOP
	// commitment to the dealt s1-share, for identifiable-abort binding of the
	// partial-z proof. nil today (the leak-free authoritative commitments are
	// the BDLOP residual — see share_commit.go); when populated by a DKG that
	// publishes Com_s_i, shareCommitmentsFor returns these and the extended
	// sigma enforces the dealt-share opening (flips valid-sigma wrong-z into an
	// attributable blame). Public, hiding (MLWE) — carries no secret.
	s1ShareCommit map[uint32][]byte
}

// DealAlgShares (the Part-1 TRUSTED-DEALER s1-share keygen) has been RIPPED
// OUT of the production surface. It expanded the seed and formed the master
// key for the duration of one call — a centralized-trust genesis. It now
// lives ONLY in the test/bootstrap file bootstrap_dealer_test.go (a
// `_test.go` file, so it is uncompilable into any production binary) where
// it seeds the no-reconstruct SIGNING tests. The production no-reconstruct
// SIGN path (DistributedBCCSigner / AggregateBCC, below) never forms s1,
// the seed, or sk. A genuinely DEALERLESS s1-share keygen is the
// research-blocked Part-2 problem — see naive_additive_seta_obstruction.go
// (DealerlessMLDSADKG, COMPUTED obstruction; Mithril short-replicated
// shares ia.cr/2026/013 is the adoption target).

// shamirSharePolyVecGFq shares each coefficient of secret (a length-L
// poly-vector, coefficients already normalized to [0,q)) with a fresh
// degree-(t−1) GF(q) polynomial whose constant term is that coefficient,
// and evaluates the sharing at each eval point. Returns shares[p] = the
// length-L poly-vector share for the party at evalPoints[p]. By Lagrange
// interpolation at X=0, Σ_p λ_p · shares[p] == secret.
func shamirSharePolyVecGFq(secret polyVec, evalPoints []uint32, threshold int, rng io.Reader) ([]polyVec, error) {
	if threshold < 1 {
		return nil, ErrInvalidThreshold
	}
	L := len(secret)
	n := len(evalPoints)
	out := make([]polyVec, n)
	for p := 0; p < n; p++ {
		out[p] = make(polyVec, L)
	}
	coeffs := make([]uint32, threshold-1) // reused per (l, j)
	for l := 0; l < L; l++ {
		for j := 0; j < mldsaN; j++ {
			for d := 0; d < threshold-1; d++ {
				v, err := randGFq(rng)
				if err != nil {
					return nil, err
				}
				coeffs[d] = v
			}
			a0 := secret[l][j] % mldsaQ
			for p := 0; p < n; p++ {
				// Horner from the top degree down to the constant a0.
				x := uint64(evalPoints[p])
				var acc uint64
				for d := threshold - 2; d >= 0; d-- {
					acc = (acc*x + uint64(coeffs[d])) % shamirPrimeQ
				}
				acc = (acc*x + uint64(a0)) % shamirPrimeQ
				out[p][l][j] = uint32(acc)
			}
		}
	}
	return out, nil
}

// randGFq draws one uniform GF(q) value in [0, q) by rejection from rng.
func randGFq(rng io.Reader) (uint32, error) {
	var buf [4]byte
	for {
		if _, err := io.ReadFull(rng, buf[:]); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFF // 23 bits
		if v < mldsaQ {
			return v, nil
		}
	}
}

// randCenteredGFq draws v uniform in the centered range [−R, R] and
// returns its [0, q) representative. Used to sample the small joint nonce.
func randCenteredGFq(rng io.Reader, R uint32) (uint32, error) {
	span := uint64(2*R + 1)
	var buf [8]byte
	for {
		if _, err := io.ReadFull(rng, buf[:]); err != nil {
			return 0, err
		}
		u := binary.LittleEndian.Uint64(buf[:])
		// Reject the small biased tail so the result is exactly uniform.
		limit := (^uint64(0) / span) * span
		if u >= limit {
			continue
		}
		v := int64(u%span) - int64(R)
		r := v % int64(mldsaQ)
		if r < 0 {
			r += mldsaQ
		}
		return uint32(r), nil
	}
}

// ----- NonceMPC stand-in (PULSAR-V13-W-LEAK gate; test/dev surface) -----

// NonceDeal is the output of the NonceMPC stand-in: the public NonceCert
// (w1 + clearance) plus the per-party Shamir shares of the small joint
// nonce ȳ. DebugW is the joint commitment; a real NonceMPC never reveals
// it (the no-leak oracle in the test asserts the production wire — the
// NonceCert — does not carry it).
type NonceDeal struct {
	Cert    NonceCert
	YShares map[NodeID]polyVec
	DebugW  polyVec // TEST/DEBUG ONLY — never on the production wire
}

// DealNonceMPCDebug models the validator NonceMPC: it samples a small joint
// nonce ȳ whose commitment w = A·ȳ is BOUNDARY-CLEAR, Shamir-shares ȳ over
// the quorum eval points, and emits the public NonceCert (w1 + a debug
// clearance QC) plus the per-party nonce shares.
//
// W-LEAK HONESTY. A real NonceMPC must produce w1 = HighBits(w) and the
// boundary-clear attestation over secret-shared w WITHOUT revealing w to
// any participant (else w' − w = c·t0 − c·s2 leaks the long-term key —
// PULSAR-V13-W-LEAK). This stand-in computes w directly and returns it in
// DebugW; it is the dealer-modelled NonceMPC for the SIGNING tests, NOT a
// production primitive. The leak-free distributed nonce (a secure
// HighBits-over-shares MPC, or an exact-ℓ∞ boundary-clearance ZK proof) is
// fail-closed behind the same wall as rangeproof.go.
//
// The joint nonce is sampled in the reduced centered range R = γ1 − 2β − 4
// so the aggregated response z = ȳ + c·s1 always clears ‖z‖∞ < γ1 − β;
// boundary clearance (~9% yield for ML-DSA-65) is the only resample gate.
func DealNonceMPCDebug(setup *AlgSetup, quorum []NodeID, evalPoints []uint32, threshold int, nonceID [32]byte, rng io.Reader) (*NonceDeal, error) {
	gamma2, beta, _, ok := bccParams(setup.Mode)
	if !ok {
		return nil, ErrBCCParamSet
	}
	if len(quorum) != len(evalPoints) {
		return nil, ErrAlgShareShape
	}
	_, L, _ := modeShape(setup.Mode)
	K := len(setup.a)
	_, _, gamma1Bits, _ := modeTauOmega(setup.Mode)
	gamma1 := uint32(1) << gamma1Bits
	R := gamma1 - 2*beta - 4

	const budget = 4096
	for attempt := 0; attempt < budget; attempt++ {
		// 1. Sample the small joint nonce ȳ ∈ R_q^L, ‖ȳ‖∞ ≤ R.
		yBar := make(polyVec, L)
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				v, err := randCenteredGFq(rng, R)
				if err != nil {
					return nil, err
				}
				yBar[l][j] = v
			}
		}
		// 2. w = A·ȳ (mirror bcc_sign step 2).
		yHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			yHat[l] = yBar[l]
			yHat[l].ntt()
		}
		w := make(polyVec, K)
		for k := 0; k < K; k++ {
			polyDotHat(&w[k], setup.a[k], yHat)
			w[k].reduceLe2Q()
			w[k].invNTT()
			w[k].normalize()
		}
		// 3. Offline boundary-clearance gate (message-independent, public).
		if !BoundaryClear(w, gamma2, beta) {
			continue
		}
		w1 := highBitsVec(w, gamma2)

		// 4. Shamir-share ȳ over the quorum eval points.
		perParty, err := shamirSharePolyVecGFq(yBar, evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		yShares := make(map[NodeID]polyVec, len(quorum))
		for i, id := range quorum {
			yShares[id] = perParty[i]
		}

		// 5. Public NonceCert (w1 + debug clearance QC). Models the validator-
		// attested NonceMPC: a quorum signs the bound payload. The test
		// registers a permissive QuorumSigVerifier (the validators attested);
		// production registers the real validator-set verifier.
		cert := NonceCert{
			Mode:    setup.Mode,
			NonceID: nonceID,
			W1:      packW1Vec(w1, gamma2, K),
			Margin:  2 * beta,
		}
		payload := nonceCertPayloadRoot(&cert)
		bitmap := []byte{0xFF}
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
		return &NonceDeal{Cert: cert, YShares: yShares, DebugW: w}, nil
	}
	return nil, ErrAlgNonceExhausted
}

// ----- the single-share distributed BCC round signer -----

// DistributedBCCSigner is one validator's local state machine for a
// no-reconstruct threshold ML-DSA signature on the BCC/CEF path. It holds
// exactly one *AlgShare; the per-nonce y-share is delivered out-of-band by
// the NonceMPC (SetNonceShare). It satisfies the RoundSigner interface.
type DistributedBCCSigner struct {
	params *Params
	setup  *AlgSetup
	share  *AlgShare // THE single key share — one pointer, never a slice

	quorum     []NodeID
	evalPoints []uint32
	partyIdx   uint32 // this node's position in the sorted quorum
	lambda     uint32 // this node's Lagrange coefficient at X=0
	sid        [32]byte
	ctx, msg   []byte
	rng        io.Reader

	// committeeID binds nonce reservations to THIS (group key, sorted quorum).
	committeeID [32]byte
	// shareID is the committee-independent identity of this validator's key-share
	// (shareIdentityKey). The nonce single-use ledger is resolved from the
	// process-global registry by this key (shareLedgerFor), so EVERY signer
	// instance over the same share shares ONE ledger — cross-instance nonce reuse
	// is refused by DEFAULT, with no per-instance empty-ledger fail-open path.
	shareID [32]byte
	// optional domain-binding context recorded with each reservation (audit /
	// domain separation). Zero by default; set via SetNonceBinding.
	epoch       uint64
	policy      [32]byte
	messageKind uint32

	// identity layer (RED MEDIUM, authenticated PartyID). idSigner signs THIS
	// node's z-partials with its long-term identity key (producer side); idVerify
	// authenticates OTHER nodes' partials when this node aggregates (verifier
	// side). Both nil by default: Round2 then emits an unsigned partial and
	// FinalizeWithBlame aggregates sigma-checked partials WITHOUT emitting blame
	// (no blame is ever produced off an unauthenticated PartyID). Wire both via
	// SetIdentity to enable authenticated blame + front-run-exclusion resistance.
	idSigner IdentitySigner
	idVerify AbortSignatureVerifier

	// per-nonce state.
	nonceID  [32]byte
	yShare   polyVec // this node's Shamir share of the joint nonce ȳ
	haveY    bool
	w1       polyVec // public HighBits(w), unpacked from the NonceCert
	w1Packed []byte  // packed HighBits(w) as carried on the cert — nonce material
	c        poly    // challenge = SampleInBall(H(μ, w1)); set by Round1
	cHat     poly    // c in NTT/Montgomery form
	haveC    bool
}

// compile-time witness: the concrete signer is a Quasar RoundSigner.
var _ RoundSigner = (*DistributedBCCSigner)(nil)

// NewDistributedBCCSigner constructs one validator's signer over exactly
// one AlgShare. quorum is the sorted, distinct signing committee containing
// share.NodeID; evalPoints are the GF(q) Shamir points parallel to quorum.
func NewDistributedBCCSigner(params *Params, setup *AlgSetup, share *AlgShare, quorum []NodeID, evalPoints []uint32, sid [32]byte, ctx, msg []byte, rng io.Reader) (*DistributedBCCSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgShareShape
	}
	if share == nil {
		return nil, ErrAlgNilShare
	}
	if _, _, _, ok := bccParams(params.Mode); !ok {
		return nil, ErrBCCParamSet
	}
	if share.Mode != params.Mode || setup.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	_, L, _ := modeShape(params.Mode)
	if len(share.S1Share) != L {
		return nil, ErrAlgShareShape
	}
	if len(quorum) == 0 || len(evalPoints) != len(quorum) {
		return nil, ErrAlgShareShape
	}
	if len(ctx) > 255 {
		return nil, ErrCtxTooLong
	}
	// Quorum sorted ascending, distinct; this node must be in it.
	myIdx := -1
	for i := 1; i < len(quorum); i++ {
		if !nodeIDLess(quorum[i-1], quorum[i]) {
			return nil, ErrCommitteeDuplicate
		}
	}
	for i, q := range quorum {
		if q == share.NodeID {
			myIdx = i
		}
	}
	if myIdx < 0 {
		return nil, ErrNotInQuorum
	}

	var ctxCopy []byte
	if len(ctx) > 0 {
		ctxCopy = append([]byte{}, ctx...)
	}
	return &DistributedBCCSigner{
		params:      params,
		setup:       setup,
		share:       share,
		quorum:      append([]NodeID{}, quorum...),
		evalPoints:  append([]uint32{}, evalPoints...),
		partyIdx:    uint32(myIdx),
		lambda:      LagrangeAtZeroQ(share.EvalPoint, evalPoints),
		sid:         sid,
		ctx:         ctxCopy,
		msg:         append([]byte{}, msg...),
		rng:         rng,
		committeeID: deriveCommitteeID(pkID(setup.Pub), quorum),
		shareID:     shareIdentityKey(share),
	}, nil
}

// SetNonceLedger installs a PERSISTENT nonce single-use ledger for THIS signer's
// key-share. It is the seam for crash-restart safety (a flagged residual): the
// in-process default is already safe by construction (every signer over a share
// resolves to ONE registry ledger keyed by share identity), so this is only
// needed to upgrade that share's ledger to durable storage. It writes the
// per-share registry slot — FIRST WRITER WINS — so ALL instances of the share
// (default-constructed, no call needed) pick it up; call it once at startup
// before any Round2 for the share. A nil ledger is ignored (the safe default is
// retained — never fail-open). Returns the signer for chaining.
func (d *DistributedBCCSigner) SetNonceLedger(l NonceLedger) *DistributedBCCSigner {
	setShareLedger(d.shareID, l)
	return d
}

// IdentitySigner is the PRODUCER side of the protocol-message identity layer
// (the verifier side is AbortSignatureVerifier — one identity layer, two faces).
// A validator signs the canonical to-be-signed bytes of a protocol message with
// its long-term identity key (Ed25519 / hybrid PQ / BLS — opaque here). It is
// the same key whose public half a verifier looks up in the validator set.
type IdentitySigner interface {
	// SignProtocolMessage returns the identity-key signature over tbs.
	SignProtocolMessage(tbs []byte) []byte
}

// SetIdentity wires this node's identity layer (RED MEDIUM, authenticated
// PartyID). signer signs THIS node's z-partials so the aggregator can bind each
// partial to its true producer; verifier authenticates OTHER nodes' partials
// when this node aggregates, so a forged partial stamped with a victim's PartyID
// is dropped (never blamed/excluded). Both must be set for authenticated blame;
// production wires the validator's identity key + the validator-set verifier
// here. Returns the signer for chaining.
func (d *DistributedBCCSigner) SetIdentity(signer IdentitySigner, verifier AbortSignatureVerifier) *DistributedBCCSigner {
	d.idSigner = signer
	d.idVerify = verifier
	return d
}

// SetNonceBinding sets the optional domain-binding context (epoch, policy,
// message-kind) recorded with each nonce reservation for audit / domain
// separation. The single-use guard is independent of this; the binding is the
// auditable "what was this nonce spent on" record. Returns the signer for
// chaining.
func (d *DistributedBCCSigner) SetNonceBinding(epoch uint64, policy [32]byte, messageKind uint32) *DistributedBCCSigner {
	d.epoch = epoch
	d.policy = policy
	d.messageKind = messageKind
	return d
}

// Profile reports the Quasar cert profile this signer serves.
func (d *DistributedBCCSigner) Profile() CertProfile { return ProfilePulsar }

// NodeID returns this validator's identity within the quorum.
func (d *DistributedBCCSigner) NodeID() NodeID { return d.share.NodeID }

// ShareCount is the runtime witness of the single-share custody invariant:
// it returns 1 for a constructed signer and 0 only for the zero value.
func (d *DistributedBCCSigner) ShareCount() int {
	if d.share == nil {
		return 0
	}
	return 1
}

// IsAggregator reports whether this node is the designated aggregator
// (quorum[0], the lowest-sorted member). The aggregator rotates with the
// committee; it is not a fixed leader and holds no extra secret.
func (d *DistributedBCCSigner) IsAggregator() bool { return d.share.NodeID == d.quorum[0] }

// SetNonceShare delivers this node's Shamir share of the joint nonce ȳ for
// the given nonce id. The NonceMPC produces these out-of-band (the hot path
// consumes a NonceCert plus its own y-share). Must be called before Round1.
func (d *DistributedBCCSigner) SetNonceShare(nonceID [32]byte, yShare polyVec) error {
	_, L, _ := modeShape(d.params.Mode)
	if len(yShare) != L {
		return ErrAlgShareShape
	}
	d.nonceID = nonceID
	d.yShare = append(polyVec(nil), yShare...)
	d.haveY = true
	return nil
}

// Round1 binds the canonical nonce cert to the session and derives the
// challenge c = SampleInBall(H(μ, w1)). The per-party y-share must already
// be set (SetNonceShare). Returns the SignRound1 binding consensus tracks.
func (d *DistributedBCCSigner) Round1(sessionID, nonceID [32]byte, cert NonceCert) (SignRound1, error) {
	if sessionID != d.sid {
		return SignRound1{}, ErrAlgSessionMismatch
	}
	if !d.haveY || nonceID != d.nonceID {
		return SignRound1{}, ErrAlgNoNonceShare
	}
	if cert.Mode != d.params.Mode {
		return SignRound1{}, ErrModeMismatch
	}
	if _, _, _, ok := bccParams(cert.Mode); !ok {
		return SignRound1{}, ErrBCCParamSet
	}
	K, _, _ := modeShape(d.params.Mode)
	gamma2, _, _, _ := bccParams(d.params.Mode)
	w1, err := unpackW1Vec(cert.W1, gamma2, K)
	if err != nil {
		return SignRound1{}, err
	}
	d.w1 = w1
	// Capture the canonical packed nonce commitment as the single-use material
	// (keyed on w1, not the nonceID label, so a relabeled nonce cannot bypass).
	d.w1Packed = append([]byte(nil), cert.W1...)

	// c̃ = H(μ, packW1(w1)); c = SampleInBall(c̃). Same deriveCTilde the
	// aggregator uses, so every party's c and the final signature's c̃ agree.
	cTilde := deriveCTilde(d.params.Mode, d.setup.tr, d.ctx, d.msg, d.w1, gamma2, K)
	var c poly
	polyDeriveUniformBall(&c, cTilde, d.params.Tau)
	d.c = c
	d.cHat = c
	d.cHat.ntt()
	d.haveC = true

	return SignRound1{SessionID: sessionID, NonceID: nonceID, NonceCert: cert}, nil
}

// Round2 emits this node's proof-carrying z-partial. The signer computes
// z_i = λ_i·y_i + c·λ_i·s1_i from ITS OWN (y_i, s1_i, λ_i, c) and produces
// the sound linear-sigma proof (partial_proof.go) binding it to (session,
// nonce, party, challenge, dkg-commit, nonce-commit). The PartialInput
// supplies only the public bindings; in.ZShare is recomputed authoritatively
// here (the signer, not the caller, holds the secret).
func (d *DistributedBCCSigner) Round2(r1 SignRound1, in PartialInput) (Partial, error) {
	if !d.haveC {
		return Partial{}, ErrAlgNoNonceShare
	}
	if r1.SessionID != d.sid {
		return Partial{}, ErrAlgSessionMismatch
	}
	if r1.NonceID != d.nonceID {
		return Partial{}, ErrAlgNonceMismatch
	}

	// NONCE SINGLE-USE GUARD (RED nonce-reuse, HIGH). Resolve THIS share's
	// process-shared single-use ledger by share identity (shareLedgerFor) — every
	// signer instance over the same share gets the SAME ledger by construction, so
	// the guard is enforced even across the per-message signer objects an
	// integrator necessarily creates (no per-instance empty-ledger fail-open).
	// Mint the nonce ticket and reserve its MATERIAL key BEFORE the secret is
	// touched. A second use of the same joint nonce — even relabeled under a fresh
	// nonceID or a different message — is refused FAIL-CLOSED (dedup keys on the
	// nonce commitment, not the ticket id), so the attacker can never obtain a
	// second z-partial on the same nonce and the (c_A − c_B)·s1 key-recovery
	// system can never be assembled. The reservation is never rolled back: if
	// proof generation below fails, the nonce stays burned (an aborted attempt
	// leaves no reusable nonce state). ReserveNonceTicket is the one and only
	// nonce-consume path.
	ledger := shareLedgerFor(d.shareID)
	if ledger == nil {
		return Partial{}, ErrNonceLedgerNil
	}
	ticket := NewNonceTicket(d.committeeID, d.w1Packed, NonceBinding{
		Epoch:       d.epoch,
		CommitteeID: d.committeeID,
		Policy:      d.policy,
		MessageKind: d.messageKind,
		Digest:      nonceBindingDigest(d.params.Mode, d.setup.tr, d.ctx, d.msg),
	})
	if err := ReserveNonceTicket(ledger, ticket); err != nil {
		return Partial{}, err
	}

	// z_i = partialLinearMap(λ_i, ĉ, y_i, s1_i) — byte-identical to the image
	// the proof certifies, so the partial and its proof are consistent.
	z := partialLinearMap(d.lambda, &d.cHat, d.yShare, d.share.S1Share)

	// Bind the AUTHORITATIVE per-party DKG/nonce commitments (not caller-
	// supplied bytes) so the prover and the verifier (AggregateBCC) bind the
	// SAME values — they both call shareCommitmentsFor, the single source of
	// truth. nil today (BDLOP residual, share_commit.go); the in.* commitment
	// fields are no longer trusted for the binding.
	dkgCommit, nonceCommit := shareCommitmentsFor(d.setup, d.nonceID, d.share.EvalPoint)
	st := &PartialStatement{
		Mode:            d.params.Mode,
		Lambda:          d.lambda,
		C:               d.c,
		Z:               z,
		SessionID:       d.sid,
		NonceID:         d.nonceID,
		PartyID:         d.partyIdx,
		DKGCommitment:   dkgCommit,
		NonceCommitment: nonceCommit,
	}
	proof, err := ProvePartial(st, &PartialWitness{Y: d.yShare, S1: d.share.S1Share}, d.rng)
	if err != nil {
		return Partial{}, err
	}
	p := Partial{
		PartyID:   d.partyIdx,
		NonceID:   d.nonceID,
		SessionID: d.sid,
		ZShare:    packPolyVec(z),
		Proof:     proof,
	}
	// AUTHENTICATE ORIGIN (RED MEDIUM). Sign the partial with this validator's
	// long-term identity key so the aggregator can bind it to its true producer
	// (Author == quorum[PartyID]) and refuse a forged partial stamped with this
	// slot. The signature binds the slot AND the content (partialAuthTBS), so it
	// is non-malleable. With no identity wired the partial is unsigned and the
	// aggregator will not emit blame off it (fail-closed on attribution).
	if d.idSigner != nil {
		p.Author = d.NodeID()
		p.AuthSig = d.idSigner.SignProtocolMessage(partialAuthTBS(p, d.epoch))
	}
	return p, nil
}

// Finalize is run by the designated aggregator (quorum[0]). It verifies
// every partial's sound z-proof, picks the canonical signer subset, sums
// the z-partials Lagrange-linearly, recovers the hint from PUBLIC data via
// FindHint, and emits a FIPS 204 ML-DSA signature plus the two-cert
// consensus artifact. It holds NO share, sk, or seed — its only secret-free
// inputs are the collected partials.
func (d *DistributedBCCSigner) Finalize(r1 SignRound1, partials []Partial) (Aggregate, ConsensusCert, error) {
	agg, cert, _, err := d.FinalizeWithBlame(r1, partials)
	return agg, cert, err
}

// FinalizeWithBlame is Finalize with IDENTIFIABLE ABORT: it additionally
// returns a signed-complaint-ready AbortEvidence for every attributable
// sign-time deviation (malformed / duplicate-PartyID / unknown-party /
// session-mismatch / invalid-proof). This node is the accuser; PartyIDs are
// mapped to NodeIDs via the signing quorum. The AbortEvidence.Signature is left
// empty for the caller's identity layer (TranscriptForComplaint gives the
// to-be-signed bytes). A VALID-sigma WRONG-z is NOT attributed here (BDLOP
// residual — share_commit.go); it remains a liveness fault, never a forgery.
func (d *DistributedBCCSigner) FinalizeWithBlame(r1 SignRound1, partials []Partial) (Aggregate, ConsensusCert, []AbortEvidence, error) {
	if !d.IsAggregator() {
		return Aggregate{}, ConsensusCert{}, nil, ErrAlgNotAggregator
	}
	if !d.haveC {
		return Aggregate{}, ConsensusCert{}, nil, ErrAlgNoNonceShare
	}
	agg, cert, blames, err := AggregateBCCWithBlame(d.params, d.setup, d.evalPoints, d.quorum, d.epoch, d.idVerify,
		d.ctx, d.msg, d.c, &d.cHat, d.w1, d.sid, d.nonceID, len(d.quorum), partials)
	return agg, cert, d.blamesToEvidence(blames), err
}

// blamesToEvidence maps PartyID-level PartialBlame to NodeID-level signed-
// complaint-ready AbortEvidence using this signer's quorum, with this node as
// the accuser. Out-of-range PartyIDs and self-accusation are dropped.
func (d *DistributedBCCSigner) blamesToEvidence(blames []PartialBlame) []AbortEvidence {
	if len(blames) == 0 {
		return nil
	}
	out := make([]AbortEvidence, 0, len(blames))
	for _, b := range blames {
		if int(b.PartyID) >= len(d.quorum) {
			continue
		}
		accused := d.quorum[b.PartyID]
		if accused == d.NodeID() {
			continue // never self-accuse
		}
		out = append(out, BadPartialEvidence(d.NodeID(), accused, d.epoch, b))
	}
	return out
}

// ── partial origin authentication (RED MEDIUM) ────────────────────────────

// partialAuthDigest is the 32-byte payload digest an authenticated z-partial's
// identity signature binds. It commits to the partial's SLOT (PartyID) AND its
// CONTENT (ZShare, Proof) under the round (session, nonce), so the signature is
// non-malleable: changing the claimed PartyID or any byte invalidates it. (MAC,
// Author, AuthSig are excluded — they are the envelope, not the signed payload.)
func partialAuthDigest(p Partial) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR/partial-auth-digest/v1"))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], p.PartyID)
	_, _ = h.Write(u4[:])
	_, _ = h.Write(p.SessionID[:])
	_, _ = h.Write(p.NonceID[:])
	_, _ = h.Write(p.ZShare)
	_, _ = h.Write(p.Proof)
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// partialAuthTBS is the canonical to-be-signed bytes for an authenticated
// z-partial: the producer's identity key signs (author ‖ slot ‖ payload-digest)
// via the shared protocol-message framing (ProtocolMessageTBS, round = Partial).
// One encoding, reused by the verifier — there is exactly one way to compute it.
func partialAuthTBS(p Partial, epoch uint64) []byte {
	return ProtocolMessageTBS(p.Author, ProtocolContext{
		Epoch:     epoch,
		SessionID: p.SessionID,
		NonceID:   p.NonceID,
		Round:     ProtocolRoundPartial,
	}, partialAuthDigest(p))
}

// authenticatePartial reports whether p is a genuine partial from the validator
// expected at p's slot. FAIL CLOSED on every doubt: nil verifier, a partial for
// the wrong round, an author that is not the slot's validator (impersonation),
// or a bad/absent signature all return false. This is the gate that stops an
// attacker stamping a victim's PartyID on a forged partial to get the victim
// blamed or front-run-excluded — the attacker cannot produce the victim's
// identity signature, so the forgery is dropped and the victim's real partial
// stands.
func authenticatePartial(p Partial, expectedAuthor NodeID, epoch uint64, sid, nonceID [32]byte, v AbortSignatureVerifier) bool {
	if v == nil {
		return false
	}
	if p.Author != expectedAuthor {
		return false // slot impersonation: author is not the slot's validator
	}
	if p.SessionID != sid || p.NonceID != nonceID {
		return false // not a partial for this round
	}
	m := SignedProtocolMessage{
		Author:        p.Author,
		Context:       ProtocolContext{Epoch: epoch, SessionID: sid, NonceID: nonceID, Round: ProtocolRoundPartial},
		PayloadDigest: partialAuthDigest(p),
		Signature:     p.AuthSig,
	}
	return VerifySignedProtocolMessage(&m, v)
}

// AggregateBCC is the free-function aggregation surface: ANY process
// holding the public setup, the challenge c, the public target w1, and the
// collected z-partials can produce the FIPS 204 signature WITHOUT any
// share, sk, or seed. This is the load-bearing no-reconstruct boundary —
// its parameter list carries no secret. It is the back-compat wrapper over
// AggregateBCCWithBlame (drops the blame list).
//
// threshold is the reconstruction threshold; partials is the collected set
// (at least threshold valid ones required). The result verifies under
// unmodified FIPS 204 ML-DSA.Verify (VerifyBytes / mldsa{65,87}.Verify).
func AggregateBCC(params *Params, setup *AlgSetup, evalPoints []uint32, quorum []NodeID, epoch uint64, auth AbortSignatureVerifier, ctx, msg []byte, c poly, cHat *poly, w1 polyVec, sid, nonceID [32]byte, threshold int, partials []Partial) (Aggregate, ConsensusCert, error) {
	agg, cert, _, err := AggregateBCCWithBlame(params, setup, evalPoints, quorum, epoch, auth, ctx, msg, c, cHat, w1, sid, nonceID, threshold, partials)
	return agg, cert, err
}

// AggregateBCCWithBlame is the canonical no-reconstruct aggregation surface
// with IDENTIFIABLE ABORT. It verifies every partial's sound linear-sigma proof
// bound to (λ_p, c, z_p, session, nonce, party) and the per-party commitments
// (shareCommitmentsFor — the single source of truth shared with Round2), and
// ATTRIBUTES every detected deviation to its PartyID (PartialBlame) instead of
// silently dropping it. Duplicate PartyIDs are rejected — CanonicalSignerSet
// does not dedupe, so a duplicate could otherwise satisfy the threshold with
// fewer than t DISTINCT signers. Malformed ZShares are rejected without
// panicking (unpackPolyVecChecked). It holds NO share, sk, or seed.
//
// ORIGIN AUTHENTICATION (RED MEDIUM). quorum maps PartyID → expected validator
// NodeID; auth is the identity-layer verifier; epoch binds the round. When auth
// is non-nil, a partial is ACCEPTED only if it carries a valid identity
// signature whose author IS quorum[PartyID] — a forged partial stamped with a
// victim's slot is dropped, so an attacker can neither blame nor front-run-
// exclude an honest victim. Blame is emitted ONLY for authenticated partials;
// it is NEVER produced off a raw unauthenticated PartyID (with auth == nil no
// blame is produced at all — attribution fails closed). The networked transport
// that authenticates DELIVERY remains a flagged residual.
func AggregateBCCWithBlame(params *Params, setup *AlgSetup, evalPoints []uint32, quorum []NodeID, epoch uint64, auth AbortSignatureVerifier, ctx, msg []byte, c poly, cHat *poly, w1 polyVec, sid, nonceID [32]byte, threshold int, partials []Partial) (Aggregate, ConsensusCert, []PartialBlame, error) {
	gamma2, beta, omega, ok := bccParams(params.Mode)
	if !ok {
		return Aggregate{}, ConsensusCert{}, nil, ErrBCCParamSet
	}
	K, L, _ := modeShape(params.Mode)
	_, _, gamma1Bits, _ := modeTauOmega(params.Mode)
	gamma1 := uint32(1) << gamma1Bits

	// 0. AUTHENTICATE ORIGIN before any attribution (RED MEDIUM). PartyID is an
	// unauthenticated wire field; an attacker can stamp a victim's slot on a
	// forged partial to get the victim blamed or front-run-excluded. When an
	// identity verifier is supplied, ACCEPT a partial only if it carries a valid
	// identity signature whose author IS the validator at that slot — drop any
	// unauthenticated / wrong-slot / forged partial HERE, with NO blame against
	// the slot's honest owner, BEFORE the first-per-PartyID and duplicate logic
	// (so a forgery cannot occupy the victim's slot or evict the victim's real
	// partial). With auth == nil the identity layer is not wired: the round still
	// aggregates sigma-checked partials but produces NO blame (see below).
	if auth != nil {
		authed := make([]Partial, 0, len(partials))
		for i := range partials {
			p := partials[i]
			if int(p.PartyID) >= len(quorum) {
				continue // unknown slot — nobody to frame; drop
			}
			if !authenticatePartial(p, quorum[p.PartyID], epoch, sid, nonceID, auth) {
				continue // forged / wrong-slot / unsigned — drop, never blame the victim
			}
			authed = append(authed, p)
		}
		partials = authed
	}

	// 1. Verify + ATTRIBUTE. A deviating partial is attributed to its PartyID
	// (PartialBlame), never silently dropped. The FIRST partial per PartyID is
	// authoritative; any later one carrying the same PartyID is rejected as a
	// duplicate (DoS / sub-threshold-via-duplicates vector).
	valid := make([]Partial, 0, len(partials))
	zByParty := make(map[uint32]polyVec, len(partials))
	seen := make(map[uint32]bool, len(partials))
	var blames []PartialBlame
	blame := func(party uint32, reason BlameReason) {
		// Never emit blame off an unauthenticated PartyID (RED MEDIUM): with no
		// identity verifier wired, attribution is not sound, so produce none.
		// With auth != nil only authenticated partials reach here, so the PartyID
		// is the genuine slot owner and the blame is sound.
		if auth == nil {
			return
		}
		blames = append(blames, PartialBlame{PartyID: party, Reason: reason, SessionID: sid, NonceID: nonceID})
	}
	for i := range partials {
		p := partials[i]
		if p.SessionID != sid || p.NonceID != nonceID {
			blame(p.PartyID, BlameSessionMismatch)
			continue
		}
		if int(p.PartyID) >= len(evalPoints) {
			blame(p.PartyID, BlameUnknownParty)
			continue
		}
		if seen[p.PartyID] {
			blame(p.PartyID, BlameDuplicatePartyID)
			continue
		}
		z, zerr := unpackPolyVecChecked(p.ZShare, L)
		if zerr != nil {
			seen[p.PartyID] = true
			blame(p.PartyID, BlameMalformed)
			continue
		}
		lambda := LagrangeAtZeroQ(evalPoints[p.PartyID], evalPoints)
		dkgCommit, nonceCommit := shareCommitmentsFor(setup, nonceID, evalPoints[p.PartyID])
		st := &PartialStatement{
			Mode:            params.Mode,
			Lambda:          lambda,
			C:               c,
			Z:               z,
			SessionID:       sid,
			NonceID:         nonceID,
			PartyID:         p.PartyID,
			DKGCommitment:   dkgCommit,
			NonceCommitment: nonceCommit,
		}
		if err := VerifyPartialProof(st, p.Proof); err != nil {
			seen[p.PartyID] = true
			blame(p.PartyID, BlameProofInvalid)
			continue
		}
		seen[p.PartyID] = true
		valid = append(valid, p)
		zByParty[p.PartyID] = z
	}

	// 2. Canonical (non-grindable) signer subset of exactly `threshold`.
	chosen, bitmap, err := CanonicalSignerSet(valid, threshold)
	if err != nil {
		return Aggregate{}, ConsensusCert{}, blames, err
	}

	// 3. z = Σ_chosen z_p  (Lagrange-linear; mod q). The per-party z_p are
	// full-range, but the sum telescopes to ȳ + c·s1 — the master s1 is
	// NEVER formed.
	zShares := make([]polyVec, len(chosen))
	for i, p := range chosen {
		zShares[i] = zByParty[p.PartyID]
	}
	z := FlatAggregateZ(zShares, L)

	// 4. ‖z‖∞ < γ1 − β (the FIPS 204 reject bound on z).
	if polyVecExceeds(z, gamma1-beta) {
		return Aggregate{}, ConsensusCert{}, blames, ErrBCCExhausted
	}

	// 5. w' = A·z − c·t1·2^d (PUBLIC; mirror bcc_sign step 8).
	t1Scaled := make(polyVec, K)
	for k := 0; k < K; k++ {
		t1Scaled[k].mulBy2toD(&setup.t1[k])
		t1Scaled[k].ntt()
	}
	zHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		zHat[l] = z[l]
		zHat[l].ntt()
	}
	wPrime := make(polyVec, K)
	for k := 0; k < K; k++ {
		var az poly
		polyDotHat(&az, setup.a[k], zHat)
		az.reduceLe2Q()
		var ct1 poly
		ct1.mulHat(cHat, &t1Scaled[k])
		az.sub(&az, &ct1)
		az.reduceLe2Q()
		az.invNTT()
		az.normalize()
		wPrime[k] = az
	}

	// 6. Recover the hint from PUBLIC (w', w1) via FindHint — never from a
	// secret residual. ok=false ⇒ the nonce was not admissible; the caller
	// retries with a fresh NonceMPC nonce.
	hint, ok := FindHint(wPrime, w1, gamma2, omega)
	if !ok {
		return Aggregate{}, ConsensusCert{}, blames, ErrNoFIPSHint
	}

	// 7. sigEncode(c̃, z, h) per FIPS 204 Algorithm 28. c̃ = H(μ, packW1(w1))
	// is recomputed from (tr, ctx, msg, w1) by every party identically; the
	// challenge c verified above was derived from this exact c̃ upstream.
	cTilde := deriveCTilde(params.Mode, setup.tr, ctx, msg, w1, gamma2, K)
	sigBytes, err := encodeBCCSignature(params, gamma1Bits, z, hint, cTilde)
	if err != nil {
		return Aggregate{}, ConsensusCert{}, blames, err
	}
	sig := Signature{Mode: params.Mode, Bytes: sigBytes}

	agg := Aggregate{SessionID: sid, NonceID: nonceID, SignerBitmap: bitmap, ZSum: packPolyVec(z)}
	cert := ConsensusCert{
		JointPKID:    pkID(setup.Pub),
		SignerBitmap: bitmap,
		Signature:    sig,
	}
	return agg, cert, blames, nil
}

// deriveCTilde is the single source of truth for c̃ = H(μ, packW1(w1)) with
// μ = SHAKE256(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ msg) (FIPS 204 §5.4). Every party's
// Round1 challenge c = SampleInBall(c̃) and the aggregator's signature c̃ are
// the SAME bytes for the same (tr, ctx, msg, w1) — there is exactly one way
// to compute it.
func deriveCTilde(mode Mode, tr [64]byte, ctx, msg []byte, w1 polyVec, gamma2 uint32, K int) []byte {
	var mu [64]byte
	deriveMuCtx(tr, ctx, msg, mu[:])
	cTildeSize := modeCTildeSize(mode)
	cTilde := make([]byte, cTildeSize)
	h := sha3.NewShake256()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(packW1Vec(w1, gamma2, K))
	_, _ = h.Read(cTilde)
	return cTilde
}

// encodeBCCSignature packs (c̃, z, h) into FIPS 204 sigEncode byte form.
func encodeBCCSignature(params *Params, gamma1Bits uint32, z, hint polyVec, cTilde []byte) ([]byte, error) {
	K, L, _ := modeShape(params.Mode)
	_, omega, _, _ := modeTauOmega(params.Mode)
	cTildeSize := modeCTildeSize(params.Mode)
	polyLeGamma1Size := int((gamma1Bits + 1) * mldsaN / 8)
	sigBytes := make([]byte, params.SignatureSize)
	copy(sigBytes[:cTildeSize], cTilde)
	off := cTildeSize
	for l := 0; l < L; l++ {
		polyPackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], gamma1Bits)
		off += polyLeGamma1Size
	}
	polyVecPackHint(hint, sigBytes[off:off+omega+K], omega)
	return sigBytes, nil
}

// pkID is a stable 32-byte identifier of a group public key (SHAKE-256 of
// the packed pk), used only as the ConsensusCert JointPKID tag.
func pkID(pub *PublicKey) [32]byte {
	var out [32]byte
	if pub == nil {
		return out
	}
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-BCC-CEF/joint-pk-id/v1"))
	_, _ = h.Write([]byte{byte(pub.Mode)})
	_, _ = h.Write(pub.Bytes)
	_, _ = h.Read(out[:])
	return out
}
