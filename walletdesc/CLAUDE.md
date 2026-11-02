# walletdesc

## Purpose

Parses, checksums and validates the output descriptors a self-managed
wallet (`lwwallet`, `btcwallet`) can be created from, and renders a wallet's
descriptors back as text. It has no daemon dependency, so the daemon, the
SDK and tests share one set of rules.

## Key Types

- `Parse(texts, params)` — validates a descriptor set and returns
  `*WalletDescriptors`: the shared BIP32 master key (`Root`), its
  `Fingerprint`, and the validated `Descriptors`. The caller must call
  `Zero`.
- `Descriptor` — one validated descriptor holding either the master private
  key or an account-level public key. `Render(includePrivate)` is the only
  way to get text; `String` and `LogValue` are redacted.
- `CanonicalPublic(root, params)` — the account-level public `tr` (86) and
  `wpkh` (84) descriptors a wallet built from `root` watches.
- `NewAccountDescriptor` — a public descriptor from an account xpub read back
  from btcwallet, with or without a known fingerprint.
- `Checksum` / `AddChecksum` — the BIP380 checksum.
- Sentinel errors (`ErrWatchOnlyDescriptor`, `ErrNotRootKey`,
  `ErrUnsupportedPath`, `ErrLegacyDerivationMismatch`, ...) — every `Parse`
  failure wraps exactly one, for `errors.Is` matching and RPC mapping.

## Relationships

- **Depends on**: btcd `hdkeychain`, `chaincfg` and `address` only.
- **Depended on by**: the daemon's wallet creation path (planned in
  `docs/descriptor-wallets-execplan.md`).

## Invariants

- Accepted descriptors are exactly `tr(ROOT/86h/0h/0h/BRANCH/*)` and
  `wpkh(ROOT/84h/0h/0h/BRANCH/*)`, where `ROOT` is a depth-zero private key
  and `BRANCH` is `0`, `1` or `<0;1>`. The coin type is `0'` on every network
  because btcwallet's on-chain scopes hard-code it; accepting anything else
  would make the wallet watch other addresses than the descriptor describes.
- All descriptors in a set share one master key: every Ark key is derived
  under `m/1017'/coin'/family'` with hardened family steps, which needs the
  master private key.
- A path whose hardened prefix derives differently under standard BIP32 and
  btcwallet's legacy `DeriveNonStandard` is refused
  (`ErrLegacyDerivationMismatch`), for the same reason.
- No error, `String` or `LogValue` output contains key material. Tests
  enforce this.

## Deep Docs

- [docs/descriptor-wallets-execplan.md](../docs/descriptor-wallets-execplan.md)
  — Why the rules are what they are, and how the daemon uses this package.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — System-wide package map.
