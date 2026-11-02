# lib

## Purpose

Shared domain utilities used across the codebase: tree construction, transaction
builders, tapscript policy compilation, BIP-322 signing, cross-package actor
message interfaces, and core Ark types.

## Sub-Packages

### lib/batchschedule
- [Schedule and Selection](batchschedule/AGENTS.md) — UTC registration windows,
  published opportunities, and authenticated cutoff selection.

### lib/tree
- `Tree` — Root node plus batch outpoint/output (encapsulates VTXO Merkle tree).
- `Node` — Individual tree node with children and outputs.
- `LeafDescriptor` — VTXO or connector output to include in tree construction.

### lib/arkscript
- `Node` — Sealed AST interface for tapscript spending conditions (Multisig, CSV, Condition, etc.).
- `VTXOPolicy` / `VHTLCPolicy` / `CheckpointPolicy` — High-level policy templates.
- `VHTLCTiming` / `VHTLCClaimWindow` — Shared vHTLC block-timing model with
  `ValidateOrder` (structural) and `ValidateClaimWindow` (chain-relative)
  admission checks; `DecodeVHTLCTiming` recovers the tuple from a template.
- `CompiledPolicy` — Fully compiled taproot tree with canonical leaf ordering.
- `PolicyTemplate` / `StandardVTXOParams` — Serializable policy template with helpers for encoding, decoding, and deriving pkScripts.
- `SpendInfo` / `AnchorPkScript` — Taproot spend helpers and standardized P2A anchor output construction.

### lib/tx
- `arktx` — Canonical output ordering and validation for Ark transactions.
- `checkpoint` — Checkpoint PSBT construction for OOR on-chain anchors.
- `oor` — OOR submit/finalize package builders and validators.
- `psbtutil` — PSBT encoding, decoding, and signature attachment helpers.

### lib/types
- `OperatorTerms` — Server-published terms (key, delays, fee rate, dust limit).
- `JoinRoundRequest` — Primary round participation message.
- `VTXORequest`, `BoardingRequest`, `LeaveRequest`, `ForfeitRequest` — Sub-requests.

### lib/bip322
- `Intent` — Application payload with ValidFrom/ValidUntil block height range.
- `Signer` — Interface for producing BIP-322 signatures over intents.

### lib/actormsg
- `VTXOActorMsg`, `VTXOManagerMsg`, `RoundReceivable` — Marker interfaces avoiding import cycles.
- `VTXOActorServiceKey()`, `VTXOManagerServiceKey()`, `RoundActorServiceKey()` — Deterministic actor lookup.
- `TriggerBoardMsg`, `RegisterIntentMsg` — Cross-package messages from wallet→round.
- `SelectAndReserveSpendRequest`, `ReserveForfeitRequest`, etc. — VTXO manager admission types.

### lib/keyfamily
- `Registry` — Every lnd-style key family (`m/1017'/coin'/family'`) Wavelength
  derives, each classed `Funds` (in output scripts or signing spends: 6, 42,
  44, 45, 202) or `Auth` (authentication only: 21, 43). Other packages alias
  these constants rather than declaring numbers; a test walks the repository
  and fails on a numeric family declared anywhere else, and another pins the
  table, so a new family cannot land unclassified. Every family stays at or
  below `MaxFamily` (255), the accounts a watch-only wallet can derive.

### lib/recovery
- `Proof` — Immutable unilateral-exit recovery graph for one target outpoint.
- `Session` / `SessionState` — Mutable planning state and its durable TLV
  projection, driven by broadcast/confirm/fail observations.

### lib/scripts
- Removed; superseded by `lib/arkscript`.

## Relationships

- **Depends on**: `baselib/actor` (actormsg only, for ServiceKey).
- **Depended on by**: nearly every client subsystem (`round`, `vtxo`, `oor`,
  `wallet`, `unroll`, `unrollplan`, `txconfirm`, `fraud`, `db`, `sdk`,
  `vhtlcrecovery`, `swapclientserver`, `waved`, `rpc`/`arkrpc`) — `lib`
  holds the shared domain types the rest of the client builds on.

## Deep Docs

- [lib/bip322/README.md](bip322/README.md) — BIP-322 implementation guide.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — System-wide package map.
