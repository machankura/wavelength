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
- `ParseWatchOnlyBundle(data, params)` — the account public keys a
  watch-only wallet is built from, as lnd's `wallet accounts list` JSON or as
  one `tr()`/`wpkh()` account descriptor or `[fp/1017h/coinh/familyh]KEY/0/*`
  key-family entry per line. Returns `*WatchOnlyBundle` with accounts in
  import order and keys normalized to standard `xpub`/`tpub` versions.
- `ParseAccountKeys(texts, params)` — account-level private keys: on-chain
  `tr()`/`wpkh()` account xprvs plus the key families as one coin-level
  `[fp/1017h/coinh]XPRV` or one `[fp/1017h/coinh/familyh]XPRV/0/*` per
  family. Validated through the same rules as a watch-only bundle;
  `AccountKeys.Bundle()` is the public half. `HasAccountKeys` routes a
  descriptor set to this parser or to `Parse`.
- `ParseBundle(data, params)` — a watch-only bundle that may be minimal: all
  public keys is a full bundle; text with private entries is a
  `*MinimalBundle` for split signing, the BIP86 account and fund families as
  public keys and the authentication families as private keys, nothing
  else. `MinimalBundle.WithPlaceholders` completes it for import with
  placeholder xpubs for every other family, derived from a discarded random
  key.
- `BtcwalletAccountKeys(root, params)` — the account keys a btcwallet built
  from `root` holds, derived exactly as btcwallet does: on-chain accounts and
  family 0 from in-memory `DeriveNonStandard` keys, families 1 to 255 from
  the padded stored coin-level key. A signer over them signs for exactly
  what a seed wallet of `root` uses.
- `FormatBundle(keys, minimal)` — renders account keys as a full or minimal
  bundle, checksummed, one entry per line.
- `ParseManifest(data, params)` / `Manifest` — per-slot key overrides: a
  JSON manifest assigning the on-chain account and each fund family a key
  from any source, with its real origin. Refuses authentication-family
  overrides, script descriptors, duplicate keys or origins and missing
  slots; `Hash` covers a canonical encoding; `CheckIdentity` refuses a
  family-6 override unless allowed; `MinimalBundle` joins it with the
  authentication keys (`ParseAuthKeys`) for import. `FormatManifest` and
  `FormatAuthKeys` are the export side.
- `Checksum` / `AddChecksum` — the BIP380 checksum.
- Sentinel errors (`ErrWatchOnlyDescriptor`, `ErrNotRootKey`,
  `ErrUnsupportedPath`, `ErrLegacyDerivationMismatch`, ...) — every `Parse`
  failure wraps exactly one, for `errors.Is` matching and RPC mapping.

## Relationships

- **Depends on**: btcd `hdkeychain`, `chaincfg` and `address`, and
  `lib/keyfamily` for the families a bundle must cover.
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
- A watch-only bundle must hold BIP86 account `86'/0'/0'` and every key
  family `1017'/coin'/0'` to `255'`, contiguous, because btcwallet numbers an
  imported account one past its scope's last account whatever the key's own
  child index says: a gap would shift every later family onto the wrong key.
  Each key's depth and child index must match its stated account, and every
  entry must be public.
- Account keys derive below the supplied key with standard BIP32. Against a
  seed wallet that agrees on every family, except that a coin-level key
  with a leading zero byte gives a different family 0 under btcwallet,
  which Wavelength never uses. A leading zero higher up the path (on
  `m/1017'`) is invisible from the coin-level key: software that exported
  it with standard BIP32 and btcwallet from the same seed disagree on every
  family. walletcore's `TestLegacyDerivationFamilyScope` pins this.
- A manifest slot's key may come from any root at any path, because the
  wallet derives only non-hardened children below a slot. Its origin is
  kept (`WatchOnlyAccount.Origin`, `AccountKey.Origin`) so btcwallet records
  the real fingerprint and the signer can export the manifest again.

## Deep Docs

- [docs/descriptor-wallets-execplan.md](../docs/descriptor-wallets-execplan.md)
  — Why the rules are what they are, and how the daemon uses this package.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — System-wide package map.
