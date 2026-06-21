# Test Matrix (what each test proves)

| Test | Proves |
|---|---|
| TestThresholdV03DisabledByDefault | leaking legacy path fails closed |
| TestNoHintSecretFieldsInProductionWireTypes | no CS2/CT0/D2/D0/R0/LowBits/Hint fields in prod wire |
| TestNonceCertHasNoFullW | NonceCert has W1, not full W |
| TestNonceTranscriptDoesNotRevealW | transcript public view has no w / LowBits(w) |
| TestNonceTranscriptOutputsCorrectW1_DebugOracle | W1 = HighBits(w) |
| TestNonceTranscriptBoundaryClear_DebugOracle | clear flag = BoundaryClear(w); non-clear unvotable |
| TestNonceCertBindsAllConsensusFields | QC binds every cert field (tamper-evident) |
| TestBadNonceTranscriptRootRejected | tampered transcript root rejected |
| TestPublishingFullWWouldRevealResidual_DebugOracle | w' − w = residual (why w is forbidden) |
| TestFindHintToTargetMatchesUseHint | FindHint ≡ FIPS UseHint round-trip |
| TestBoundaryClearImpliesHighBitsStable | boundary ⇒ HighBits stable + r0 bound |
| TestBoundaryClearEdgeCases | exact off-by-one at γ2 − 2β |
| TestBoundaryClearanceYield | offline yield ≈ 9.8% (ML-DSA-65) |
| TestBCCParamGuard | ML-DSA-65/87 only; 44 rejected |
| TestValidPartial/TestBadZShareRejected/binding | partial binding + fail-closed |
| TestCanonicalNonceSelection | deterministic non-grindable |
| TestAbortClassesCoarse | coarse aborts only |
| TestTreeAggregateEqualsFlat (to 1000) | tree == flat |
| TestMergeAggregatesDuplicateAndSession | duplicate/cross-session rejected |
| TestNoT0InProductionDKGTypes | DKG public types carry no t0/master |
| TestProductionBCCSigningDisabledUntilSoundZK | prod signing fails closed sans sound proofs |
