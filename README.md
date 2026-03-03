# Pulsar

> Lux is not merely adding post-quantum signatures to a chain; it defines a hybrid finality architecture for DAG-native consensus, with protocol-agnostic threshold lifecycle, post-quantum threshold sealing, and cross-chain propagation of Horizon finality.

See [LP-105 §Claims and evidence](https://github.com/luxfi/lps/blob/main/LP-105-lux-stack-lexicon.md#claims-and-evidence) for the canonical claims/evidence table and the ten architectural commitments — single source of truth.

**Pulsar** is the Lux-evolved post-quantum threshold signature stack for **Quasar consensus**, derived from [daryakaviani/ringtail](https://github.com/daryakaviani/ringtail) (academic 2-round threshold signature from LWE) with the protocol additions needed to operate on a **leaderless open public chain**.

## Why "Pulsar"

`Lux` (Latin) → light. `Pulsar` → SI unit of luminous flux. Each validator emits a "pulsar" of signature toward consensus; aggregated, they form the chain's overall light. Brand-paired with Quasar (the consensus that consumes them).

## Relationship to upstream Ringtail

The upstream repo at `daryakaviani/ringtail` is an **academic proof-of-concept** ("not ready for production use" per its README). Pulsar is the production track:

| Layer | Upstream Ringtail | Pulsar |
|---|---|---|
| 2-round threshold sign | ✅ same byte-equal protocol | ✅ inherited |
| Trusted-dealer Gen | ✅ for fixed federation | ✅ retained for bridge MPC |
| **Proactive resharing** for epoch validator rotation | ❌ not specified | 🚧 **pulsar/reshare/** (this fork) |
| **Pedersen DKG over R_q** with proper hiding | ❌ not specified | 🚧 **pulsar/dkg2/** (this fork) |
| Per-validator triple-sign integration with Quasar | ❌ N/A | 🚧 **pulsar/consensus/** integration |

## Layout

- `sign/` — 2-round threshold signing (byte-equal with upstream)
- `primitives/` — Shamir, hashes, MACs, PRFs (byte-equal with upstream)
- `utils/` — NTT, Montgomery, ring helpers (byte-equal with upstream)
- `networking/` — TCP peer-to-peer (byte-equal with upstream)
- `dkg/` — original Lux DKG (Feldman VSS without noise; **broken** for public broadcast — see RED-DKG-REVIEW). Retained for reference.
- `dkg2/` — proper Pedersen DKG over R_q (Pulsar addition; this fork)
- `reshare/` — proactive secret resharing for epoch rotation (Pulsar addition; this fork)
- `cmd/` — KAT oracle generators

## Status

WIP. The 2-round Sign+Verify path is byte-equal-validated against the academic Ringtail spec via 16 SHA-256 KATs. The Pulsar-specific additions (resharing + Pedersen DKG) are under design and implementation.
