# Security Invariants (reviewers verify each)

1. **No secret residual.** No production wire type, transcript, or log carries
   `c·s2`, `c·t0`, `r0`, `LowBits(w − c·s2)`, hint shares, or `CS2/CT0/D2/D0`.
   Enforced: `TestNoHintSecretFieldsInProductionWireTypes`.
2. **No full w.** `NonceCert` carries `W1 = HighBits(w)` only — never `w`, `w_i`,
   `LowBits(w)`, or boundary distances. Enforced: `TestNonceCertHasNoFullW`,
   `TestNonceTranscriptDoesNotRevealW`, `TestPublishingFullWWouldRevealResidual`.
3. **Public hint.** `FindHint(w', w1)` ≡ FIPS `UseHint`; never `MakeHint(secret)`.
   Enforced: `TestFindHintToTargetMatchesUseHint`.
4. **Boundary ⇒ r0 safe.** `BoundaryClear(w, 2β)` ⇒ HighBits stable under `c·s2`
   and hidden `r0 < γ2 − β`. Enforced: `TestBoundaryClearImpliesHighBitsStable`,
   `TestBoundaryClearEdgeCases`. **Parameter scope: ML-DSA-65/87 only**
   (`TestBCCParamGuard`; ML-DSA-44 violates `‖c·t0‖ < γ2`).
5. **Quorum-bound nonce cert.** `ClearanceQC` binds every cert field; tamper ⇒ reject.
   Enforced: `TestNonceCertBindsAllConsensusFields`, `TestBadNonceTranscriptRootRejected`.
6. **Canonical nonce.** Deterministic, non-grindable per session. `TestCanonicalNonce`.
7. **Coarse aborts.** Rejected attempts publish only a coarse class. `TestAbortClassesCoarse`.
8. **Accountable aggregation.** Tree==flat; duplicate/cross-session rejected; bitmap
   accountability. `TestTreeAggregateEqualsFlat`, `TestMergeAggregatesDuplicateAndSession`.

## OPEN (this review's subject — NOT yet sound)
- NonceTranscript validator-MPC malicious security (currently debug-oracle + fail-closed).
- PartialProof soundness (currently binding + fail-closed).
- DKG well-formedness proof (currently type-clean + reflection-tested).
- Independent-verifier interop on the production sign path.
- Machine-checked boundary-clearance / FindHint proof.
