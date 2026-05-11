# Test vectors

Two formats per NIST MPTC submission norms:

- `kat-v1.json` — input/output vectors per MPTC §IO-Testing. Each entry
  is a single threshold ceremony with full `(n, t, party_seeds,
  public_params, shares, commitments, preprocessing_transcript, message,
  per_party_messages, final_signature, verify_result, abort_evidence)`.

- `kat-v1.rsp` — CAVS-style response file for compatibility with
  legacy ACVP-inspired tooling. One signature per stanza, deterministic
  from a 48-byte seed.

`transcripts/` holds full-protocol KATs for `(n, t)` sweeps —
`transcripts/n3-t2.jsonl`, `transcripts/n7-t5.jsonl`, etc. — each line
a complete protocol run.

## Cross-validation against FIPS 204

The headline interchangeability claim (Class N1) requires every
`final_signature` in `kat-v1.json` to verify against unmodified FIPS 204
`ML-DSA.Verify(pk, message, signature)` returning `accept`. The
cross-validation harness at `test/interoperability/` runs each KAT
through:

- the reference implementation in `ref/go/`
- the FIPS 204 reference (Dilithium pq-crystals C reference)
- a third independent ML-DSA implementation (BoringSSL FIPS or
  OpenSSL 3.0 PQ provider, whichever is available)

A KAT mismatch with any of the three is a release blocker.

## Determinism

Every entry in `kat-v1.json` is reproducible from `master_seed` (a
48-byte hex value at the head of the file). `scripts/gen_vectors.sh`
must produce byte-identical output on any fresh checkout. Drift here
is a CI failure.

## Status

- [ ] KAT generator (`ref/go/cmd/genkat`) — implementation pending
- [ ] First v1 KAT set
- [ ] FIPS 204 cross-validation
- [ ] Independent-impl cross-validation
- [ ] Encoded into `vectors/transcripts/` for `(n, t) ∈ {(3,2), (5,3), (7,5), (10,7), (16,11), (32,21)}`
