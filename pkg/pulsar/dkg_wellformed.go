package pulsar

import "reflect"

// DKG public output: joint public key (t1) + share commitments + transcript
// root + well-formedness QC. It NEVER carries t0, s2 hint material, the full
// secret t, or any master secret (PULSAR-V13). Online signing needs only
// s1_i, y_i (held locally) and public t1.

type DKGShareCommitment struct {
	PartyID uint32
	Commit  []byte
}

type DKGPublicOutput struct {
	PKEpoch           uint64
	JointPublicKey    []byte // packed ML-DSA public key (rho + t1)
	ShareCommitments  []DKGShareCommitment
	DKGTranscriptRoot [32]byte
	WellFormednessQC  QuorumCert
}

func productionDKGTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(DKGPublicOutput{}),
		reflect.TypeOf(DKGShareCommitment{}),
	}
}
