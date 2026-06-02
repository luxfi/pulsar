// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build pulsar_combine_ct

// combine_ct.go — cgo bridge exposing pulsar.Combine to the C
// dudect harness in dudect_combine.c.
//
// CT POPULATION (operational framing, NOT a standards mandate):
// both dudect classes are VALID Combine inputs — independently
// randomized threshold ceremonies over the SAME shares. The bridge
// pre-builds a pool of K full (Round1, Round2) tapes by running the
// threshold protocol K times with different per-party RNG seeds. All
// K ceremonies produce the SAME final FIPS 204 signature (the
// reconstruction-aggregator collapses through the same master seed),
// but the intermediate Round-1 commits + Round-2 (mask, masked)
// reveals vary across tapes.
//
// dudect class assignment:
//   class A: always tape[0]      (byte-identical Combine inputs)
//   class B: tape[rand % K]      (varying-but-valid Combine inputs)
//
// Both classes pass every internal Combine check (MAC verify, commit
// re-derive, Lagrange reconstruct, FIPS 204 sign). Any timing
// difference between classes is a real signature-content-dependent
// timing in the Combine pipeline, not a rejection-path artifact.
//
// Earlier versions of this harness used class A = zero bytes and
// class B = random bytes — both INVALID Round-2 PartialSig — which
// produced different rejection-path timings (zero bytes pass parse
// then fail commit-bind; random bytes vary at parse). That was the
// same anti-pattern the verify-side harness was redesigned out of;
// the leak was a commit-mismatch-timing artifact, not a Combine CT
// regression on secret shares.
//
// Build (Linux):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_combine.so ./combine_ct.go
// Build (macOS):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_combine.dylib ./combine_ct.go

package main

// Force-include the ARM compat shim on AArch64 hosts so that
// dudect/src/dudect.h's unconditional <emmintrin.h>/<x86intrin.h>
// includes resolve via the shim's blocking #defines. Matches the
// Makefile behavior so `go build` and `make` agree on arm64.

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/pulsar/ref/go/pkg/pulsar"
)

// Pool size — K independent valid threshold ceremonies over the
// SAME shares. Larger K = more uniform class-B distribution. 16 is
// chosen as a balance between setup time (each ceremony runs the
// full threshold protocol) and uniformity of the class-B mixture.
const kCombineValidPool = 16

// Per-tape fixture: one full (Round1, Round2) tape from an
// independent threshold ceremony. The shares + sessionID + attempt
// stay constant across tapes; only the per-party RNG (hence the
// commits + reveals) varies.
type combineTape struct {
	round1 []*pulsar.Round1Message
	round2 []*pulsar.Round2Message
}

// Long-lived fixture: a real (n=3, t=2) threshold setup at ModeP65,
// plus a pool of kCombineValidPool valid (Round1, Round2) tapes.
var (
	cFixtureParams    *pulsar.Params
	cFixturePub       *pulsar.PublicKey
	cFixtureMsg       []byte
	cFixtureSessionID [16]byte
	cFixtureAttempt   uint32
	cFixtureQuorum    []pulsar.NodeID
	cFixtureThreshold int
	cFixtureShares    []*pulsar.KeyShare
	// cFixtureTapes is the K-entry valid-tape pool. Each entry is a
	// full (Round1, Round2) from an independent ceremony.
	cFixtureTapes [kCombineValidPool]combineTape
)

// Build a real threshold ceremony fixture once. Returns 0 on
// success, non-zero on failure.
//
// Topology: n=3 parties, t=2 threshold, ModeP65. This is the
// smallest non-trivial threshold ceremony — keeps the dudect run
// time per sample bounded.
//
//export pulsar_combine_ct_setup
func pulsar_combine_ct_setup() C.int {
	params := pulsar.MustParamsFor(pulsar.ModeP65)
	n, t := 3, 2

	committee := make([]pulsar.NodeID, n)
	for i := 0; i < n; i++ {
		committee[i] = pulsar.NodeID{byte(i + 1)}
	}

	// Identity fixture (BLOCKERS.md CR-8): every party gets a
	// long-term ML-KEM-768 + ML-DSA-65 identity, and an
	// IdentityDirectory carries every peer's published KEM pubkey
	// so Round-1 envelopes can be sealed.
	identities := make(map[pulsar.NodeID]*pulsar.IdentityKey, n)
	pubs := make(map[pulsar.NodeID]*pulsar.IdentityPublicKey, n)
	for _, id := range committee {
		ik, err := pulsar.GenerateIdentity(rand.Reader)
		if err != nil {
			return 10
		}
		identities[id] = ik
		pubs[id] = ik.PublicKey()
	}
	directory, err := pulsar.NewIdentityDirectory(pubs)
	if err != nil {
		return 11
	}

	// DKG.
	dkgSessions := make([]*pulsar.DKGSession, n)
	for i := 0; i < n; i++ {
		s, err := pulsar.NewDKGSession(params, committee, t, committee[i], identities[committee[i]], directory, rand.Reader)
		if err != nil {
			return 1
		}
		dkgSessions[i] = s
	}
	r1 := make([]*pulsar.DKGRound1Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round1()
		if err != nil {
			return 2
		}
		r1[i] = m
	}
	r2 := make([]*pulsar.DKGRound2Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round2(r1)
		if err != nil {
			return 3
		}
		r2[i] = m
	}
	outputs := make([]*pulsar.DKGOutput, n)
	for i, s := range dkgSessions {
		out, err := s.Round3(r1, r2)
		if err != nil {
			return 4
		}
		outputs[i] = out
	}

	pub := outputs[0].GroupPubkey
	shares := make([]*pulsar.KeyShare, n)
	for i := range outputs {
		shares[i] = outputs[i].SecretShare
	}

	// Threshold sign.
	msg := []byte("dudect constant-time smoke: Pulsar Combine class N4")
	quorum := make([]pulsar.NodeID, t)
	for i := 0; i < t; i++ {
		quorum[i] = shares[i].NodeID
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return 5
	}

	// Per-pair session keys for the quorum (BLOCKERS.md CR-7).
	// SymmetricSession runs the two-sided EstablishSession on each
	// (a, b) pair so both endpoints derive the same 32-byte key.
	sessionKeys := make(map[pulsar.NodeID]map[pulsar.NodeID][32]byte, t)
	for _, id := range quorum {
		sessionKeys[id] = make(map[pulsar.NodeID][32]byte, t-1)
	}
	for i := 0; i < t; i++ {
		for j := i + 1; j < t; j++ {
			a, b := quorum[i], quorum[j]
			key, err := pulsar.SymmetricSession(a, identities[a], b, identities[b], sid, msg)
			if err != nil {
				return 12
			}
			sessionKeys[a][b] = key
			sessionKeys[b][a] = key
		}
	}

	// Build the K-entry valid-tape pool. Each tape is an independent
	// run of (Round1, Round2) over the SAME shares, sessionID, attempt,
	// and message — only the per-party RNG (hence masks + commits +
	// reveals) differs. Every tape is sanity-checked: Combine must
	// succeed before the tape is admitted to the pool.
	for k := 0; k < kCombineValidPool; k++ {
		signers := make([]*pulsar.ThresholdSigner, t)
		for i := 0; i < t; i++ {
			s, err := pulsar.NewThresholdSigner(params, sid, 1, quorum, shares[i],
				sessionKeys[shares[i].NodeID], msg, rand.Reader)
			if err != nil {
				return 6
			}
			signers[i] = s
		}
		sr1 := make([]*pulsar.Round1Message, t)
		for i, s := range signers {
			m, err := s.Round1(msg)
			if err != nil {
				return 7
			}
			sr1[i] = m
		}
		sr2 := make([]*pulsar.Round2Message, t)
		for i, s := range signers {
			m, _, err := s.Round2(sr1)
			if err != nil {
				return 8
			}
			sr2[i] = m
		}
		// Sanity: this tape's Combine must succeed.
		if _, err := pulsar.Combine(params, pub, msg, nil, false, sid, 1, quorum, t, sr1, sr2, shares); err != nil {
			return 9
		}
		cFixtureTapes[k] = combineTape{round1: sr1, round2: sr2}
	}

	cFixtureParams = params
	cFixturePub = pub
	cFixtureMsg = msg
	cFixtureSessionID = sid
	cFixtureAttempt = 1
	cFixtureQuorum = quorum
	cFixtureThreshold = t
	cFixtureShares = shares
	return 0
}

// Returns the number of valid tapes in the per-startup pool.
//
//export pulsar_combine_ct_pool_size
func pulsar_combine_ct_pool_size() C.size_t {
	return C.size_t(kCombineValidPool)
}

// Returns the per-sample input width: 4 bytes (a big-endian uint32
// tape index, mod kCombineValidPool). The C harness sizes its
// dudect chunk to this width.
//
//export pulsar_combine_ct_input_size
func pulsar_combine_ct_input_size() C.size_t {
	return C.size_t(4)
}

// One dudect measurement sample.
//
// `data` points to a 4-byte big-endian uint32 tape index; the
// bridge reduces it mod kCombineValidPool and runs Combine on the
// indexed (Round1, Round2) tape. Both classes (A: fixed index 0,
// B: caller-supplied index) drive Combine through the SAME code
// path on VALID inputs — any timing difference is a real
// data-dependent signal, not a rejection-path artifact.
//
// IMPORTANT: this function must NOT branch on the data beyond the
// modular reduction. The reduction is constant-time over the
// 4-byte input.
//
//export pulsar_combine_ct
func pulsar_combine_ct(data *C.uint8_t) {
	if cFixtureParams == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 4)
	idx := (uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])) %
		uint32(kCombineValidPool)
	tape := cFixtureTapes[idx]

	_, _ = pulsar.Combine(
		cFixtureParams,
		cFixturePub,
		cFixtureMsg,
		nil,
		false,
		cFixtureSessionID,
		cFixtureAttempt,
		cFixtureQuorum,
		cFixtureThreshold,
		tape.round1,
		tape.round2,
		cFixtureShares,
	)
}

func main() {}
