# PROOF-CLAIMS — Pulsar (assurance-vocabulary, HONEST)

> **What the Pulsar proof artifacts establish, and — critically — what
> they do NOT.** Every claim below carries one assurance-vocabulary tag
> that MATCHES the artifact's actual state. Read this before reading the
> code.
>
> Canonical companions: `AXIOM-INVENTORY.md` (bucketed axiom census),
> `BLOCKERS.md` (open findings), `docs/proof-claims.md` and
> `docs/proof-axiom-inventory.md` (deep dives). This root file is the one
> the high-assurance gate reads (`claims-vs-reality.sh`).

## §0 FINAL SCOPED CLAIM (canonical, user-approved)

> **Dealerless committee key/nonce gen + CEF/CSCP no-reconstruct signing +
> standard-ML-DSA-verifier output, semi-honest / no-leak today; malicious-CSCP +
> networked-MPC are gated residuals.**

This is the single sentence the project stands behind. Its honest decomposition:

- **No-reconstruct signing (CEF/CSCP)** — production v0.4 path; no process forms
  `s1`/seed/`sk`/`c·s2`/`c·t0`/`r0`/full `w`. **interop-tested** byte-equal under
  CIRCL + pq-crystals; Lean-machine-checked no-leak aggregate core.
- **Standard-ML-DSA-verifier output** — the committee signature verifies under the
  unmodified `mldsa{65,87}.Verify`. **interop-tested** (GATE-1).
- **Dealerless committee key/nonce gen** — the **target track**. Today's runnable
  keygen is a **trusted-dealer bootstrap quarantined to `_test.go`**; the
  dealerless line is the `feat/v02-pedersen-vss-no-reconstruct` exploration; the
  leak-free **NonceMPC** is a residual (the `DealNonceMPCDebug` stand-in exposes
  `w` to the **test harness only**, PULSAR-V13-W-LEAK). Permissionless safety is
  carried by the dealerless **Corona** leg.
- **semi-honest / no-leak today** — the leak-free property is proven **semi-honest**
  in an in-process simulation; a malicious deviation is bounded by `FindHint` +
  release-gate to a **liveness fault, never a forge/leak**.
- **malicious-CSCP + networked-MPC are gated residuals** — UNBUILT, fail-closed,
  tracked (Residual A). The merged **v0.5.0 + v0.5.1 malicious-HARDENING** (NOT
  fully-malicious-secure-PROVEN) advances this:
  **nonce single-use safe by construction** (per-share registry enforces it on the
  DEFAULT API, not opt-in; `w1`-only dedup closes cross-committee reuse; **epoch-
  pruned** so lifetime memory is bounded WITHOUT reopening reuse in the live
  window),
  **authenticated-PartyID blame, SAFE BY DEFAULT** (blame is gated on identity-
  signature validity — an attacker cannot frame or front-run-exclude an honest
  victim; no blame is ever emitted off a raw unauthenticated PartyID; and a
  **nil verifier is now refused FAIL-CLOSED** — `ErrOriginAuthRequired` — so a
  forgotten verifier cannot silently revert to unauthenticated aggregation; the
  unauthenticated path needs the explicit `UnauthenticatedAggregation` opt-out),
  identifiable-abort plumbing, and
  GATE-2 reachability **paired with an indirection lint** (the name call-graph is
  complete for DIRECT calls only — the lint forbids function-value/closure/
  `go:linkname` indirection of the banned primitives, so the pair is complete),
  now **sealed against the asm/C blind spot** (a CI test asserts the package is
  pure Go — no `.s`/`.c`/cgo unit the AST gates cannot model).
  Still residual: the **sound valid-sigma wrong-`z` blame** (needs BDLOP lattice
  commitments), a **persistent (crash-safe) nonce ledger** (the in-process default
  is safe AND lifetime-bounded now; surviving a restart is the residual), and
  **networked transport authentication** (the partial→producer crypto binding is
  in place; authenticated delivery is consensus-owned). See
  `ref/go/pkg/pulsar/VERSIONS.md`.

**NEVER claim:** FIPS/NIST-certified threshold ML-DSA · fully-malicious-secure-proven
· global-1000-validator DKG. (Any artifact asserting these is wrong — fix the
artifact, not this file.)

## Assurance vocabulary (canonical)

| Tag | Meaning |
|---|---|
| **machine-checked** | A proof assistant verifies it; the named EasyCrypt or Lean theory has ZERO `sorry` / `admit.` / `:= True` (real tactics, per the repo's own admit gate). The EasyCrypt toolchain **is live on the host** (opam switch `proofs`: easycrypt + why3 + alt-ergo, z3 solver) — all theories compile under `easycrypt compile`, enforced every run by `security/framework/checks/ec-machine-check.sh` (pulsar 14/14). Lean compiles under `lake build`. |
| **sound-by-reduction** | A pen-and-paper reduction to a stated assumption exists; not mechanized. |
| **interop-tested** | Validated by running against ≥2 INDEPENDENT implementations (CIRCL + pq-crystals), not the signer's own library. |
| **test-proven** | A property established by executable tests (transcript / structural / reflection / round-trip), not a proof assistant or a reduction; the tests are named. For TALUS-CSCP this is **semi-honest** and runs in an in-process N-party **SIMULATION** (not a networked MPC, not malicious-secure). |
| **asserted-axiom** | Taken as an axiom in EC; bucketed in AXIOM-INVENTORY.md (A/B). Not proved here. |
| **fail-closed-pending-review** | Implemented but gated to REFUSE until external review; not claimed correct. |
| **open-research** | Not done; multi-month roadmap. |

## §1 The headline claim — with its true assurance tag

> **Class N1 byte-equality (extracted corollary).** Every signature byte
> string produced by the Pulsar Combine procedure on honest-quorum inputs
> `(group_pk, m, ctx, quorum, shares, rho_rnd)` satisfying the
> well-formedness invariants is **bit-identical** to a single-party
> FIPS 204 ML-DSA-65 signature on the Lagrange-reconstructed group secret
> under the same `(m, ctx, rho_rnd)`.
> — Lemma `pulsar_n1_byte_equality_extracted`
> (`proofs/easycrypt/Pulsar_N1_Extracted.ec`).

**Assurance: there are now TWO models, and the distinction is the headline.**

> **Model 1 — idealised correctness (reconstruct-then-sign).** The EC
> `pulsar_n1_byte_equality_extracted` is structurally complete (no
> `admit.` / `sorry`) **relative to** the C-idealised axioms
> (`combine_body_axiom`, `S_functional_spec`, per-stage
> `combine_body_*_spec` / `sign_body_*_spec`). These assert the threshold
> output equals the centralised signer **applied to the
> Lagrange-reconstructed master secret** — a **reconstruct-then-sign**
> *correctness* statement. That is exactly the abstraction `BLOCKERS.md`
> § PULSAR-V13-HINT-LEAK says the **production leaderless path must never
> instantiate** (reconstructing `c·s2`/`c·t0`/the master leaks the key). So
> Model 1 is an idealised centralised-equivalent signer, NOT a proof the
> production path is leak-free.

> **Model 2 — the HONEST production residual (no-leak, standard
> assumption).** `proofs/easycrypt/Pulsar_N1_NoLeak.ec` states the
> production path the way it runs: the public Lagrange aggregate of the
> per-party **masked** responses equals the central `z` **without ever
> forming the master secret**, and the hint is recovered from the **public**
> `w' = A·z − c·t1·2^d` via FIPS `UseHint`. The CORRECTNESS core of Model 2
> is **machine-checked in Lean 4 + Mathlib on this host** (`lake build`
> green, 0 sorry): `Crypto.Pulsar.NoLeakAggregate`
> (`z_aggregate_no_reconstruct`, `hint_is_fips_hint`,
> `no_leak_under_standard_assumptions`) + `Crypto.Pulsar.BoundaryClearance`
> (`boundary_clearance`, `findHintCoeff_unique`) +
> `Crypto.Threshold_Lagrange`. The ONLY open assumption is
> `no_leak_reduction`: under **Module-LWE + Module-SIS** the public
> transcript leaks nothing about `(s1,s2,t0)` beyond one single-party FIPS
> 204 signature. That is a STANDARD PQ assumption — the SAME lattice
> hardness ML-DSA's own EUF-CMA rests on — **not** an implementation
> reconstruct. The EC side of Model 2 **machine-checks on the host** via
> `easycrypt compile` (gate `ec-machine-check.sh`); its Lean core is
> machine-checked too.

- The production no-leak property is ALSO **interop-tested**: the BCC
  single-key signature verifies **byte-for-byte under CIRCL + pq-crystals**
  (ML-DSA-65/87), per the BLOCKERS V13-HINT-LEAK resolution criteria. The
  novel ZK boundary-clearance / partial-z parts are
  **fail-closed-pending-review**.

## §2 Claim-by-claim assurance table

| Claim | Assurance | Evidence |
|---|---|---|
| EC threshold↔centralised refinement (`pulsar_n1_byte_equality`) | machine-checked modulo C-cone (asserted-axiom) | lemma in the N1 theory; 0 real `admit.` tactics (`scripts/checks/ec-admits.sh`); cone in AXIOM-INVENTORY.md §C |
| Class N4 reshare preserves `(rho,t1)` group key | machine-checked modulo A-cone | lemma in the N4 theory; 0 real `admit.` tactics; rests on `shamir_correct`/`reconstruct_linear`/`add_share_zeroR` (Lean-bridged) |
| The byte-walk = centralised signer on reconstructed secret (C-idealised cone) | asserted-axiom (OPEN; idealised CORRECTNESS only) | `combine_body_axiom`, `S_functional_spec`, `*_body_*_spec` — reconstruct-then-sign; NOT the production residual; BLOCKERS.md |
| No-leak masked-aggregate = central z, secret never formed | **machine-checked (Lean 4 + Mathlib, this host)** | `Crypto.Pulsar.NoLeakAggregate.z_aggregate_no_reconstruct`; EC mirror `Pulsar_N1_NoLeak.no_leak_z_aggregate` (EC-compiles on host, gate `ec-machine-check.sh`) |
| No-leak hint recovered from public `w'`, unique FIPS hint | **machine-checked (Lean 4 + Mathlib, this host)** | `Crypto.Pulsar.BoundaryClearance.{boundary_clearance,findHintCoeff_unique}`; EC mirror `Pulsar_N1_NoLeak.public_hint_roundtrip` (EC-compiles on host, gate `ec-machine-check.sh`) |
| Production no-leak residual (transcript leaks nothing extra) | **sound-by-reduction (STANDARD: Module-LWE + Module-SIS)** | `no_leak_reduction` (Pulsar_N1_NoLeak.ec); EC mirror of machine-checked Lean `Crypto.Pulsar.NoLeak.NoLeakReduction`; full simulation = v0.8 artifact |
| Final BCC signature interchangeable with FIPS 204 | interop-tested | 19/19 N1 subtests vs CIRCL; BCC no-leak sig byte-equal under CIRCL + pq-crystals (`test/interoperability/`, BLOCKERS V13) |
| Production no-leak (no `c·s2`/`c·t0`/master reconstruction) | interop-tested (single-key) + fail-closed-pending-review (threshold ZK) | BLOCKERS.md V13-HINT-LEAK / V13-W-LEAK / V13-PARTIAL-Z-PROOF |
| Constant-time, threshold layer | sound-by-reduction (jasmin-CT) + fail-closed on dudect-submission-grade | jasmin-ct 3/3; dudect 10⁹-sample run open-research |
| 5 Lagrange/algebra identities | machine-checked (Lean 4 + Mathlib), asserted-axiom (EC side) | `proofs/lean-easycrypt-bridge.md`; `scripts/check-lean-bridge.sh` |
| FIPS 204 per-type codec round-trips (B-cone) | asserted-axiom | AXIOM-INVENTORY.md §B; closing = Dilithium codec mechanization (open-research) |
| ML-DSA post-quantum hardness (M-LWE/M-SIS) | open-research (inherited) | NIST FIPS 204 analysis; NOT a Pulsar claim |
| TALUS sig verifies under stock FIPS-204 (circl `mldsa65`/`mldsa87.Verify`) | interop-tested (unmodified upstream verifier) | `TestTalus_MPC_EndToEnd_StockVerify`, `TestTalus_MPC_Mode87`; BCC single-key also byte-equal under CIRCL + pq-crystals |
| TALUS CSCP path leak-free (no node forms `w`/`w0`/`A0`; only `{valid,maskC,w1}` opened) | **test-proven — semi-honest, in-process N-party SIMULATION** (NOT machine-checked, NOT a networked MPC) | `TestCSCP_MultiNode_LeakFree`, `TestCSCP_LeakFree_Structural`, `TestCSCP_MaskOpen_HidesW` (transcript + source-structural + reflection) |
| TALUS malicious CSCP deviation = liveness-only (never forge/leak) | test-proven (FindHint + `TalusReleaseGate` mandatory stock verify) | `TestCSCP_WrongW1_CaughtByFindHint`; a corrupt `w1` is caught by `FindHint`, the release-gate refuses any non-verifying signature |
| Dealerless byte-FIPS-204 KEY DKG impossible (S_η argument) | sound-by-reduction (parameter-derived obstruction) | `distributed_bcc_dkg.go` → `ErrDealerlessByteFIPSUnreachable`; `s1,s2 ∈ S_η = {‖p‖∞ ≤ η}`, a dealerless sum has ‖·‖∞ ≤ N·η > η ⇒ breaks BCC (‖c·s2‖∞ ≤ N·β > β) + FIPS-204 equivalence; KEYGEN trusted-dealer, Corona carries permissionless |

### §2 addendum — TALUS / CSCP assurance (v1.2.0)

The four rows above record the v1.2.0 TALUS threshold ML-DSA assurance. The
leak-free CSCP property (`w`/`w0` never formed) is **semi-honest and proven in
an in-process N-party SIMULATION** — the harness holds every party's shares; it
is the *algorithm* that never reconstructs `w`/`w0`, faithfully proven, but this
is NOT yet a networked/deployed distributed MPC, and the malicious-secure CSCP
layer is UNBUILT (**Residual A**, `BLOCKERS.md`). A malicious deviation can
never forge or leak — `FindHint` + `TalusReleaseGate` bound it to a liveness
fault. KEYGEN stays trusted-dealer because dealerless byte-FIPS-204 KEY DKG is
proven unreachable (**Residual B**); the permissionless-public guarantee is
carried by the dealerless Corona leg of the Quasar AND-mode cert.

## §3 What is NOT proved (the load-bearing honesty disclosure)

1. **The production threshold path is NOT EC-proven.** The EC proof models
   reconstruct-then-sign; the production path (which must never reconstruct
   the secret) is covered by `BLOCKERS.md` open items + interop tests +
   fail-closed gates, not by the EC byte-equality.
2. **No-leak is interop-tested, not EC-proven.** See §1.
3. **ML-DSA hardness, side-channels beyond jasmin-CT, adaptive-corruption
   unforgeability, robust completion, async identifiable-abort** — not
   proved here (see `docs/proof-claims.md` §3 for the full list).
4. **The TALUS leak-free property is semi-honest and simulation-only.** It is
   not machine-checked, not a networked MPC deployment, and the malicious-secure
   CSCP layer is unbuilt (Residual A). KEYGEN is trusted-dealer (dealerless
   byte-FIPS-204 KEY DKG is proven unreachable, Residual B); permissionless
   safety rests on Corona.

## §4 The honest one-paragraph version

> Pulsar carries TWO models. Model 1 (the EC `pulsar_n1_byte_equality`
> refinement) is a structurally-complete (0-admit) proof that the threshold
> combine is bit-identical to single-party FIPS 204 ML-DSA-65 sign on the
> **Lagrange-reconstructed** group secret — an idealised CORRECTNESS
> statement relative to reconstruct-then-sign axioms (bucketed C-idealised),
> deliberately NOT the production path. Model 2 (`Pulsar_N1_NoLeak.ec`) is
> the HONEST production residual: the masked Lagrange aggregate equals
> central `z` **without forming the master secret** and the hint comes from
> the **public** `w'` — its CORRECTNESS core is **machine-checked in Lean
> on this host** (`Crypto.Pulsar.NoLeakAggregate` / `.BoundaryClearance`;
> `lake build` green), and the ONLY open assumption is a **Module-LWE +
> Module-SIS** reduction (a STANDARD PQ assumption, the same hardness
> ML-DSA's EUF-CMA uses), **not** an implementation reconstruct. The
> production no-leak signature is ALSO **interop-tested** byte-equal under
> CIRCL + pq-crystals; the novel threshold-ZK parts are
> **fail-closed-pending-review**. ML-DSA's post-quantum hardness itself
> inheres in NIST's FIPS 204 analysis.

---
- Name: `PROOF-CLAIMS.md` (root; gate-read) · supersedes the scope summary
  in `docs/proof-claims.md`, which remains the deep-dive narrative.
