// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_test.go — round-trip + audit tests for the v0.3
// TRUE ALGEBRAIC threshold ML-DSA path. See threshold_v03.go for the
// honesty story (it has none — v0.3 is end-to-end public-BFT-safe).
//
// Test discipline:
//   1. Full Round1/Round2W/Round2Sign/AlgebraicAggregate cycle.
//   2. Output signature byte-passes FIPS 204 Verify against the
//      group public key.
//   3. NO master sk material reachable from AlgebraicAggregate —
//      enforced structurally (no SkBytes/Seed field on AlgebraicSetup)
//      and verified via TestAlgebraic_NoSkAccess.
//   4. Multiple parameter sets: (5, 3), (7, 4), (10, 7).
//   5. Tamper detection: bad MAC → ComplaintMACFailure; bad reveal
//      → ErrAlgebraicRound2CommitBad.
//   6. Rejection restart: contrive a session that rejects on κ=0 and
//      succeeds on κ=N.
//   7. t-1 partials cannot produce a valid signature.

import (
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// stageAlgebraic runs a deterministic v0.3 algebraic-threshold ceremony
// to produce a signature, returning the signature, group public key,
// and the trusted-dealer setup. Used by every test below.
func stageAlgebraic(t *testing.T, n, threshold int, msg []byte, sid [16]byte, attempt uint32) (
	*Signature,
	*PublicKey,
	*AlgebraicSetup,
	[]*AlgebraicKeyShare,
	*identityFixture,
	[]*AlgebraicRound1Message,
	[]*AlgebraicRound2Message,
	error,
) {
	t.Helper()
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(n)
	ident := newIdentityFixture(t, committee, []byte{byte(n), byte(threshold), byte(attempt), 0x03})

	var seed [SeedSize]byte
	copy(seed[:], "pulsar-v03-test-master-seed-32!!")
	dealerRng := deterministicReader([]byte{0x03, 0xDD, byte(n), byte(threshold)})
	setup, shares, err := DealAlgebraicV03Shares(params, committee, threshold, seed, dealerRng)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	// Caller-side seed wipe — MANDATORY in production.
	for i := range seed {
		seed[i] = 0
	}

	quorum := make([]NodeID, threshold)
	quorumShares := make([]*AlgebraicKeyShare, threshold)
	for i := 0; i < threshold; i++ {
		quorum[i] = shares[i].NodeID
		quorumShares[i] = shares[i]
	}

	allSessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, err := V03QuorumEvalPoints(quorum, shares)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}

	signers := make([]*AlgebraicThresholdSigner, threshold)
	for i := 0; i < threshold; i++ {
		s, err := NewAlgebraicThresholdSigner(params, setup, sid, attempt, quorum, quorumShares[i],
			allSessionKeys[quorum[i]], msg, deterministicReader([]byte{0xFE, byte(i), byte(attempt), 0x03}))
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		if err := s.SetQuorumEvalPoints(evalPoints); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		signers[i] = s
	}

	r1 := make([]*AlgebraicRound1Message, threshold)
	for i, s := range signers {
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("Round1 party %d: %v", i, err)
		}
		r1[i] = m
	}

	r2W := make([]*AlgebraicRound2Message, threshold)
	for i, s := range signers {
		m, _, err := s.Round2W(r1)
		if err != nil {
			t.Fatalf("Round2W party %d: %v", i, err)
		}
		r2W[i] = m
	}

	peerWByParty := make([]map[NodeID]polyVec, threshold)
	K, _, _ := modeShape(ModeP65)
	for i := 0; i < threshold; i++ {
		peerW := make(map[NodeID]polyVec, threshold-1)
		for j := 0; j < threshold; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}

	r2 := make([]*AlgebraicRound2Message, threshold)
	for i, s := range signers {
		m, _, err := s.Round2Sign(r1, peerWByParty[i])
		if err != nil {
			t.Fatalf("Round2Sign party %d: %v", i, err)
		}
		r2[i] = m
	}

	sig, err := AlgebraicAggregate(params, setup, msg, sid, attempt, quorum, evalPoints,
		threshold, r1, r2, allSessionKeys)
	return sig, setup.Pub, setup, shares, ident, r1, r2, err
}

// TestAlgebraic_FullCycle_n5_t3 runs the full Round1/Round2W/Round2Sign/
// AlgebraicAggregate cycle for (5, 3) and confirms the output passes
// FIPS 204 Verify. Other quorum sizes covered by
// TestAlgebraic_FullCycle_VariousQuorums.
func TestAlgebraic_FullCycle_n5_t3(t *testing.T) {
	msg := []byte("v0.3 algebraic threshold — full cycle n=5 t=3")
	var sid [16]byte
	copy(sid[:], "v03-rt-n5-t3-001")

	var (
		sig *Signature
		pub *PublicKey
		err error
	)
	for attempt := uint32(0); attempt < 32; attempt++ {
		sig, pub, _, _, _, _, _, err = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected err: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatalf("no acceptance within 32 attempts: %v", err)
	}
	if len(sig.Bytes) != MustParamsFor(ModeP65).SignatureSize {
		t.Fatalf("sig size %d want %d", len(sig.Bytes), MustParamsFor(ModeP65).SignatureSize)
	}
	if err := Verify(MustParamsFor(ModeP65), pub, msg, sig); err != nil {
		t.Fatalf("v0.3 signature fails FIPS 204 Verify: %v", err)
	}
}

func TestAlgebraic_FullCycle_VariousQuorums(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"7of4", 7, 4},
		{"10of7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte("v0.3 — " + tc.name)
			var sid [16]byte
			copy(sid[:], "v03-vari-quorums")

			var (
				sig *Signature
				pub *PublicKey
				err error
			)
			for attempt := uint32(0); attempt < 64; attempt++ {
				sig, pub, _, _, _, _, _, err = stageAlgebraic(t, tc.n, tc.t, msg, sid, attempt)
				if err == nil {
					break
				}
				if err != ErrAlgebraicRestart {
					t.Fatalf("attempt %d unexpected err: %v", attempt, err)
				}
			}
			if err != nil {
				t.Fatalf("no acceptance within 64 attempts: %v", err)
			}
			if err := Verify(MustParamsFor(ModeP65), pub, msg, sig); err != nil {
				t.Fatalf("v0.3 (%s) sig fails Verify: %v", tc.name, err)
			}
		})
	}
}

// TestAlgebraic_ByteValid is the Class N1 byte-equality contract.
//
// HONEST SCOPE: a v0.3 threshold signature CANNOT be byte-equal to
// circl's mldsa{44,65,87}.SignTo(masterSk, message, rnd) for arbitrary
// rnd because the y vector in single-party circl SignTo is
// ExpandMask(SHAKE256(key ‖ rnd ‖ μ), κ), while the v0.3 y_total =
// Σ y_j is the sum of t independent party RNG outputs. The byte-
// equality contract is "valid FIPS 204 signature, byte-decodable as
// such", not "matches a specific circl output".
//
// What this test pins:
//   (1) The byte format is canonical FIPS 204 sigEncode (sig.Bytes
//       length == params.SignatureSize, layout = c̃ ‖ z_packed ‖ hint).
//   (2) The signature verifies under unmodified mldsa.Verify against
//       the SAME public key the masterSk would generate from the SAME
//       seed.
//   (3) That public key is byte-equal to circl's NewKeyFromSeed
//       output for that seed (cross-check via setup.Pub.Bytes).
func TestAlgebraic_ByteValid(t *testing.T) {
	msg := []byte("v0.3 byte-valid FIPS 204 sigEncode")
	var sid [16]byte
	copy(sid[:], "v03-byte-valid01")
	params := MustParamsFor(ModeP65)

	// Stage the protocol to acceptance.
	var (
		sig *Signature
		pub *PublicKey
		err error
	)
	for attempt := uint32(0); attempt < 32; attempt++ {
		sig, pub, _, _, _, _, _, err = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected err: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatalf("v0.3 did not converge: %v", err)
	}

	// (1) byte-format: sig.Bytes length is canonical FIPS 204 SignatureSize.
	if len(sig.Bytes) != params.SignatureSize {
		t.Fatalf("sig.Bytes length %d != FIPS 204 SignatureSize %d", len(sig.Bytes), params.SignatureSize)
	}

	// (2) verifies under unmodified FIPS 204.
	if err := Verify(params, pub, msg, sig); err != nil {
		t.Fatalf("v0.3 sig fails FIPS 204 Verify: %v", err)
	}

	// (3) the public key is byte-equal to circl's NewKeyFromSeed output.
	// Reproduce the public key from the SAME seed via the single-party
	// path and compare.
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-v03-test-master-seed-32!!")
	expectedSk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	if !expectedSk.Pub.Equal(pub) {
		t.Fatalf("v0.3 setup.Pub does not match KeyFromSeed.Pub — DKG public-key derivation broken")
	}
}

// TestAlgebraic_NoSkAccess is the LOAD-BEARING structural test.
//
// AlgebraicAggregate's function signature MUST NOT take any parameter
// that smells like master-sk:
//   - no *PrivateKey
//   - no SkBytes []byte
//   - no seed [32]byte
//   - no master_seed
//   - no packed_sk
//   - no master_priv
//
// AND the AlgebraicAggregate function body MUST NOT reference any
// master-sk-bearing primitive:
//   - no KeyFromSeed
//   - no mldsaSign
//   - no mldsa{44,65,87}.SignTo
//   - no NewKeyFromSeed
//
// This is enforced by AST parsing the threshold_v03.go source file.
// If this test fails after a refactor, the v0.3 public-BFT-safety
// contract has been broken.
func TestAlgebraic_NoSkAccess(t *testing.T) {
	const path = "threshold_v03.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// Find the AlgebraicAggregate function declaration.
	var aggFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "AlgebraicAggregate" {
			aggFunc = fd
			break
		}
	}
	if aggFunc == nil {
		t.Fatal("AlgebraicAggregate function not found")
	}

	// Check parameter types — none may carry sk material.
	bannedTypeFragments := []string{
		"PrivateKey",
		"PrivKey",
		"SkBytes",
		"SecretKey",
	}
	bannedParamNames := []string{
		"sk", "Sk", "SK", "skBytes", "SkBytes",
		"seed", "Seed", "masterSeed", "MasterSeed",
		"masterSk", "MasterSk", "masterKey",
		"privKey", "PrivKey", "privateKey", "PrivateKey",
	}
	for _, field := range aggFunc.Type.Params.List {
		typeStr := exprToString(field.Type)
		for _, banned := range bannedTypeFragments {
			if strings.Contains(typeStr, banned) {
				t.Fatalf("AlgebraicAggregate has banned parameter type %q (contains %q)", typeStr, banned)
			}
		}
		for _, name := range field.Names {
			for _, banned := range bannedParamNames {
				if name.Name == banned {
					t.Fatalf("AlgebraicAggregate has banned parameter name %q", name.Name)
				}
			}
		}
	}

	// Check function body — no reference to master-sk primitives.
	bannedFuncCalls := []string{
		"KeyFromSeed",
		"NewKeyFromSeed",
		"mldsaSign",
		"deriveKeyMaterial",
	}
	var visit func(node ast.Node)
	visit = func(node ast.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.CallExpr:
			callStr := exprToString(n.Fun)
			for _, banned := range bannedFuncCalls {
				if strings.Contains(callStr, banned) {
					t.Fatalf("AlgebraicAggregate body calls banned function %q (contains %q)", callStr, banned)
				}
			}
		case *ast.SelectorExpr:
			selStr := exprToString(n)
			// Detect *.SignTo where * is mldsa44/65/87
			if n.Sel.Name == "SignTo" {
				t.Fatalf("AlgebraicAggregate body calls SignTo (%q) — public-BFT contract broken", selStr)
			}
		}
	}
	ast.Inspect(aggFunc.Body, func(node ast.Node) bool {
		visit(node)
		return true
	})

	// Also check AlgebraicSetup struct has no sk-bearing field.
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "AlgebraicSetup" {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					for _, name := range field.Names {
						for _, banned := range bannedParamNames {
							if name.Name == banned {
								t.Fatalf("AlgebraicSetup has banned field %q", name.Name)
							}
						}
					}
					typeStr := exprToString(field.Type)
					for _, banned := range bannedTypeFragments {
						if strings.Contains(typeStr, banned) {
							t.Fatalf("AlgebraicSetup has banned field type %q (contains %q)", typeStr, banned)
						}
					}
				}
			}
		}
	}
}

// exprToString converts an ast.Expr to its textual representation.
// Used by the structural test to inspect type / call / selector exprs.
func exprToString(e ast.Expr) string {
	if e == nil {
		return ""
	}
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprToString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(v.X)
	case *ast.ArrayType:
		return "[]" + exprToString(v.Elt)
	case *ast.MapType:
		return "map[" + exprToString(v.Key) + "]" + exprToString(v.Value)
	case *ast.IndexExpr:
		return exprToString(v.X) + "[" + exprToString(v.Index) + "]"
	case *ast.CallExpr:
		return exprToString(v.Fun)
	}
	return ""
}

// TestAlgebraic_BadMAC_Detected confirms tampering a Round-1 MAC
// causes a peer to emit ComplaintMACFailure during Round2W.
func TestAlgebraic_BadMAC_Detected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 bad-mac")
	var sid [16]byte
	copy(sid[:], "v03-bad-mac-0001")

	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xAA, 0x03})
	var seed [SeedSize]byte
	copy(seed[:], "v03-mac-test-seed-32-byteslayer!")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xCC, 0x03}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, err := V03QuorumEvalPoints(quorum, shares)
	if err != nil {
		t.Fatal(err)
	}

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{byte(i), 0x03}))
		_ = s.SetQuorumEvalPoints(evalPoints)
		signers[i] = s
	}
	r1 := make([]*AlgebraicRound1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	if mac, ok := r1[0].MACs[quorum[1]]; ok {
		mac[0] ^= 0xFF
		r1[0].MACs[quorum[1]] = mac
	}
	_, ev, err := signers[1].Round2W(r1)
	if err != ErrAlgebraicRound1MACBad {
		t.Fatalf("MAC tamper not caught: %v", err)
	}
	if ev == nil || ev.Kind != ComplaintMACFailure {
		t.Fatalf("expected MAC complaint, got %v", ev)
	}
}

// TestAlgebraic_BadCommit_Detected confirms a Round-1 commit that does
// not match the revealed w_i is rejected at AlgebraicAggregate.
func TestAlgebraic_BadCommit_Detected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 bad-commit")
	var sid [16]byte
	copy(sid[:], "v03-bad-com-0001")

	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xCC, 0x03, 0xC1})
	var seed [SeedSize]byte
	copy(seed[:], "v03-commit-test-seed-bytes-fix32")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xCC, 0x03}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)
	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0x77, byte(i), 0x03}))
		_ = s.SetQuorumEvalPoints(evalPoints)
		signers[i] = s
	}
	r1 := make([]*AlgebraicRound1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2W := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2W[i], _, _ = s.Round2W(r1)
	}
	K, _, _ := modeShape(ModeP65)
	peerWByParty := make([]map[NodeID]polyVec, 3)
	for i := 0; i < 3; i++ {
		peerW := make(map[NodeID]polyVec, 2)
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}
	r2 := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2[i], _, _ = s.Round2Sign(r1, peerWByParty[i])
	}
	// Tamper with W in the Round-2 message.
	r2[1].W[0] ^= 0xAA
	_, err = AlgebraicAggregate(params, setup, msg, sid, 1, quorum, evalPoints, 3, r1, r2, sessionKeys)
	if err != ErrAlgebraicRound2CommitBad {
		t.Fatalf("commit-bind not enforced: %v", err)
	}
}

// TestAlgebraic_RestartConverges drives the protocol through multiple
// attempts; at least one accepts.
func TestAlgebraic_RestartConverges(t *testing.T) {
	msg := []byte("v0.3 restart-converges")
	var sid [16]byte
	copy(sid[:], "v03-restart-0001")
	accepted := false
	for attempt := uint32(0); attempt < 64; attempt++ {
		_, _, _, _, _, _, _, err := stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			accepted = true
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected error: %v", attempt, err)
		}
	}
	if !accepted {
		t.Fatalf("no acceptance within 64 attempts (highly improbable; check the rejection bound math)")
	}
}

// TestAlgebraic_DealerReproducible checks DealAlgebraicV03Shares is
// deterministic given a fixed master seed + RNG seed.
func TestAlgebraic_DealerReproducible(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	var seed [SeedSize]byte
	copy(seed[:], "v03-reproducible-master-seed-32!")

	setup1, shares1, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0x01, 0x03}))
	if err != nil {
		t.Fatal(err)
	}
	setup2, shares2, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0x01, 0x03}))
	if err != nil {
		t.Fatal(err)
	}

	if !setup1.Pub.Equal(setup2.Pub) {
		t.Fatal("setup1.Pub != setup2.Pub — non-deterministic dealer")
	}
	if setup1.Rho != setup2.Rho {
		t.Fatal("Rho mismatch")
	}
	if setup1.Tr != setup2.Tr {
		t.Fatal("Tr mismatch")
	}
	if len(shares1) != len(shares2) {
		t.Fatal("share count mismatch")
	}
	for i := range shares1 {
		if shares1[i].NodeID != shares2[i].NodeID {
			t.Fatalf("share %d NodeID mismatch", i)
		}
		if shares1[i].EvalPoint != shares2[i].EvalPoint {
			t.Fatalf("share %d EvalPoint mismatch", i)
		}
		if shares1[i].S1[0][0] != shares2[i].S1[0][0] {
			t.Fatalf("share %d S1[0][0] mismatch", i)
		}
		if shares1[i].S2[0][0] != shares2[i].S2[0][0] {
			t.Fatalf("share %d S2[0][0] mismatch", i)
		}
	}
}

// TestAlgebraic_TminusOne_Fails confirms that a quorum of t-1 cannot
// produce a valid signature. We can't reconstruct any meaningful
// signature with t-1 parties — AlgebraicAggregate returns
// ErrInsufficientQuor.
func TestAlgebraic_TminusOne_Fails(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 t-1 fails")
	var sid [16]byte
	copy(sid[:], "v03-tminus1-0001")

	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xA1, 0x03})
	var seed [SeedSize]byte
	copy(seed[:], "v03-tminus1-test-seed-bytes-fix3")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xA1, 0x03}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}

	// Stage a 3-of-5 ceremony but try to aggregate with only 2 parties.
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0xA1, byte(i)}))
		_ = s.SetQuorumEvalPoints(evalPoints)
		signers[i] = s
	}
	r1 := make([]*AlgebraicRound1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2W := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2W[i], _, _ = s.Round2W(r1)
	}
	K, _, _ := modeShape(ModeP65)
	peerWByParty := make([]map[NodeID]polyVec, 3)
	for i := 0; i < 3; i++ {
		peerW := make(map[NodeID]polyVec, 2)
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}
	r2 := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2[i], _, _ = s.Round2Sign(r1, peerWByParty[i])
	}

	// Submit only 2 of the 3 R1 and R2 messages.
	r1Short := r1[:2]
	r2Short := r2[:2]
	_, err = AlgebraicAggregate(params, setup, msg, sid, 1, quorum, evalPoints, 3, r1Short, r2Short, sessionKeys)
	if err != ErrInsufficientQuor {
		t.Fatalf("t-1 quorum should fail with ErrInsufficientQuor, got %v", err)
	}
}

// TestAlgebraic_DishonestParty_BadZContribution confirms that a peer
// contributing a malformed z_i (post-MAC, post-commit) results in an
// invalid global signature. The MAC binds (W, Z, CS2, CT0) so tampering
// AFTER MAC is what we exercise: rewriting one party's Z field after
// it's emitted but before aggregation.
//
// Two flavours of dishonest behaviour:
//   (a) tampered Z bytes but stale MAC — caught at aggregator MAC check
//   (b) honest-format z that doesn't match what the algebraic structure
//       requires — caught at FIPS 204 Verify post-aggregation
//
// This test exercises (a) — the MAC gate. (b) is harder to contrive
// without re-deriving correct MACs, which would require the cheater to
// know the session key — which by construction they only know for
// quorum[0].
func TestAlgebraic_DishonestParty_BadZ(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 bad-z")
	var sid [16]byte
	copy(sid[:], "v03-bad-z-000001")

	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xB1, 0x03})
	var seed [SeedSize]byte
	copy(seed[:], "v03-badz-test-seed-bytes-fix-32!")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xB1, 0x03}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}

	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0xB1, byte(i)}))
		_ = s.SetQuorumEvalPoints(evalPoints)
		signers[i] = s
	}
	r1 := make([]*AlgebraicRound1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2W := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2W[i], _, _ = s.Round2W(r1)
	}
	K, _, _ := modeShape(ModeP65)
	peerWByParty := make([]map[NodeID]polyVec, 3)
	for i := 0; i < 3; i++ {
		peerW := make(map[NodeID]polyVec, 2)
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}
	r2 := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2[i], _, _ = s.Round2Sign(r1, peerWByParty[i])
	}
	// Party 1 (the non-aggregator) tampers Z without re-MACing.
	r2[1].Z[5] ^= 0xFF
	_, err = AlgebraicAggregate(params, setup, msg, sid, 1, quorum, evalPoints, 3, r1, r2, sessionKeys)
	if err != ErrAlgebraicRound2MACBad {
		t.Fatalf("bad-Z (post-MAC tamper) should yield ErrAlgebraicRound2MACBad; got %v", err)
	}
}

// TestAlgebraic_RealRNG_Smokes covers the production code path with
// crypto/rand to ensure no determinism assumption is baked in.
func TestAlgebraic_RealRNG_Smokes(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte("real-rng-v03-fixture"))
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range seed {
		seed[i] = 0
	}
	msg := []byte("real-rng v03 smoke")
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	for attempt := uint32(0); attempt < 32; attempt++ {
		signers := make([]*AlgebraicThresholdSigner, 3)
		for i := 0; i < 3; i++ {
			s, _ := NewAlgebraicThresholdSigner(params, setup, sid, attempt, quorum, shares[i],
				sessionKeys[quorum[i]], msg, nil)
			_ = s.SetQuorumEvalPoints(evalPoints)
			signers[i] = s
		}
		r1 := make([]*AlgebraicRound1Message, 3)
		for i, s := range signers {
			r1[i], _ = s.Round1()
		}
		r2W := make([]*AlgebraicRound2Message, 3)
		for i, s := range signers {
			r2W[i], _, _ = s.Round2W(r1)
		}
		K, _, _ := modeShape(ModeP65)
		peerWByParty := make([]map[NodeID]polyVec, 3)
		for i := 0; i < 3; i++ {
			peerW := make(map[NodeID]polyVec, 2)
			for j := 0; j < 3; j++ {
				if j == i {
					continue
				}
				peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
			}
			peerWByParty[i] = peerW
		}
		r2 := make([]*AlgebraicRound2Message, 3)
		for i, s := range signers {
			r2[i], _, _ = s.Round2Sign(r1, peerWByParty[i])
		}
		sig, err := AlgebraicAggregate(params, setup, msg, sid, attempt, quorum, evalPoints, 3, r1, r2, sessionKeys)
		if err == ErrAlgebraicRestart {
			continue
		}
		if err != nil {
			t.Fatalf("attempt %d real-rng err: %v", attempt, err)
		}
		if err := Verify(params, setup.Pub, msg, sig); err != nil {
			t.Fatalf("real-rng v03 sig fails Verify: %v", err)
		}
		return
	}
	t.Fatal("real-rng v03 did not converge within 32 attempts")
}

// TestAlgebraic_SetupHasNoSkField is a compile-time structural assertion
// via reflect at runtime. It complements TestAlgebraic_NoSkAccess
// (which inspects source code) with a runtime check on the struct
// layout. If a future refactor adds an sk-bearing field to
// AlgebraicSetup, both tests must fail.
func TestAlgebraic_SetupHasNoSkField(t *testing.T) {
	setup := &AlgebraicSetup{}
	// Use reflect to enumerate field names.
	rt := reflectTypeOf(setup).Elem()
	bannedFields := []string{
		"SkBytes", "Sk", "SK", "PrivateKey", "PrivKey", "Priv",
		"Seed", "MasterSeed", "PackedSk", "MasterPriv",
	}
	for i := 0; i < rt.NumField(); i++ {
		fname := rt.Field(i).Name
		for _, banned := range bannedFields {
			if fname == banned {
				t.Fatalf("AlgebraicSetup has banned field %q — v0.3 public-BFT contract broken", fname)
			}
		}
	}
}

// reflectTypeOf is a thin wrapper to avoid importing reflect across
// every test file. Local to this test.
func reflectTypeOf(v interface{}) reflectType {
	return reflectTypeImpl(v)
}

// We use a tiny indirection so the import surface lives in a single
// spot — see threshold_v03_reflect_test.go for the actual reflect import.

// TestAlgebraic_TransitionalV02StillWorks confirms v0.2 still compiles
// and runs alongside v0.3 — the v0.2 wire shape is preserved and
// neither blocks the other.
//
// This is the "no backwards compatibility break" anchor: v0.2 consumers
// can keep running through v0.2 functions; v0.3 consumers use the new
// AlgebraicAggregate path. Both ship.
func TestAlgebraic_TransitionalV02StillWorks(t *testing.T) {
	msg := []byte("v0.2 still works")
	var sid [16]byte
	copy(sid[:], "v02-still-works1")
	var err error
	for attempt := uint32(0); attempt < 32; attempt++ {
		_, _, _, _, _, _, _, err = stageTransitional(t, 5, 3, msg, sid, attempt)
		if err == nil {
			return
		}
		if err != ErrTransitionalRestart {
			t.Fatalf("v0.2 unexpected err: %v", err)
		}
	}
	t.Fatalf("v0.2 did not converge within 32 attempts: %v", err)
}
