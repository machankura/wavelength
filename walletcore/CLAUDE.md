# walletcore

## Purpose

Shared btcwallet wrapping used by both lwwallet (Esplora-backed) and btcwbackend
(neutrino-backed) wallet implementations. Extracts common HD key management,
signing, address generation, and balance operations that delegate to
btcwallet.BtcWallet regardless of the underlying chain source.

## Key Types

- `Wallet` — Core wallet struct embedding `input.Signer`. Provides key derivation, P2TR address generation, balance queries, and UTXO listing. Also implements `proofkeys.Backend` (via `ProofSigner` method). Chain-specific implementations embed this to satisfy `round.ClientWallet`.
  `Wallet.Controller` (an `lnwallet.WalletController`, set to `BtcWallet` by
  both backends) is the only path for funding and finalizing PSBTs, so a
  watch-only wallet can swap in a remote-signing controller while
  `BtcWallet` keeps tracking the chain.
- `BoardingBackendBase` — Shared boarding functionality: taproot script import under BIP86 scope, imported address tracking for UTXO filtering, and HD key derivation. Chain-specific adapters embed this and add `ListUnspent`, `GetTransaction`, `GetBlock`.
- `Config` — Base configuration (seed or BIP32 master `RootKey`, wallet
  password, birthday, chain params (mainnet/testnet/testnet4/regtest),
  recovery window, DB dir, logger) shared by all btcwallet-backed wallet
  backends. `Birthday`, when set, bounds recovery rescans instead of
  starting from genesis.
- `ValidateCreateInput` / `NewBtcWallet` — shared creation path. The first
  checks that at most one of seed and root key is set and that a root key is
  a private master key for the network; the second builds lnd's btcwallet
  wrapper, creating the database from the root key through
  `Loader.CreateNewWalletExtendedKey` and handing it over via
  `btcwallet.Config.Wallet`. A wallet built from a seed's master key is
  identical to one built from the seed (`rootkey_test.go`).
- `NewWatchOnlyBtcWallet` — creates a watch-only btcwallet from a
  `walletdesc.WatchOnlyBundle` (mirroring lnd's `importWatchOnlyAccounts`),
  or opens an existing one with a nil bundle. The user's password is the
  public passphrase, since a watch-only wallet has no private one.
- `RemoteSignerConfig` / `DialRemoteSigner` / `NewRemoteKeyRing` /
  `VerifyRemoteSigner` — connect to an lnd-compatible remote signer, put
  lnd's `rpcwallet.RPCKeyRing` in front of the watch-only wallet (it is the
  `Signer`, `KeyRing` and `Controller` at once), and check on start that the
  signer holds the identity key the imported xpubs imply. Dialing is
  compiled out of `js && wasm` builds, which cannot open the gRPC
  connection.
- `CreateAccountSigning` / `OpenExisting` / `OpenSigning` /
  `WalletSource` — the shared create-or-open path for both backends.
  Account-key wallets are watch-only btcwallets plus an
  `accountsigner` keystore, signing through the same RPC key ring as a
  remote-signing wallet but with the in-process `accountsigner.Signer` as
  its connection. `OpenExisting` tells the kinds apart on its own: a
  key-holding database signs through btcwallet, a watch-only one with a
  keystore loads it with the password, and a watch-only one without a
  keystore fails with `ErrWatchOnlyWithoutSigner`.
- `OpenWithSigner` / `routedConn` / `guardedKeyRing` — split signing from a
  `walletdesc.MinimalBundle`. `OpenRemoteSigning` dials and hands over to
  `OpenWithSigner`, which creates the watch-only wallet with placeholder
  families, keeps the authentication families' keys in the account
  keystore, and fronts the RPC key ring with a connection that routes
  families 21 and 43 to an in-process `accountsigner.Signer` and everything
  else to the remote signer. `guardedKeyRing` refuses `ErrFamilyNotSupplied`
  for any family outside the registry or not supplied, and an open whose
  stored bundle misses a registry family fails `ErrBundleOutdated`.
- `RemoteSignerConfig.Inbound` — an inbound connection the signer dialed
  into (lnd's `InboundConnection`), used instead of dialing out. The
  daemon owns it; the wallet borrows it (`borrowedConn`) and never stops
  it, because lnd's coordinator cannot restart. `VerifyRemoteSigner` waits
  up to the connection timeout for the signer before probing.
- `ProbeSigner` / `SlotProbe` — on every start of a signer-backed wallet,
  the signer must sign a fresh tagged challenge with each fund family's
  index-0 key and a key-path spend of a fabricated output on the on-chain
  account's first key, each verified against the watch-only wallet's own
  key. It replaces the identity-only check, and a single-root signer (lnd)
  fails it for every slot a manifest overrides.
- `ErrManifestMismatch` — a wallet created from a manifest stores it next
  to its keystore; every open checks btcwallet's accounts still hold the
  manifest's keys, and `Wallet.ManifestHash` carries its hash.
- `OutputLeaser` — Interface for UTXO reservation during coin selection:
  `LeaseOutput(ctx, id, outpoint, expiry)` and
  `ReleaseOutput(ctx, id, outpoint)`. Implemented by `lwwallet.BoardingBackendAdapter`
  and the btcwallet adapters in `waved`.
- `LockID [32]byte` — Caller-scoped identifier for output leases, stable
  across restarts. Each subsystem uses a distinct, hardcoded `LockID` so
  leases from one caller do not collide with another.
- `Utxo` — Simplified UTXO representation for coin selection: `Outpoint`,
  `PkScript`, `Amount`, `Confirmations`.

## Relationships

- **Depends on**: `build` (context logger extraction), `proofkeys` (implements Backend), `indexer` (SchnorrSigner interface).
- **Depended on by**: `lwwallet` (embeds Wallet + BoardingBackendBase), `btcwbackend` (embeds Wallet + BoardingBackendBase), `waved` (proof key backend), `wallet` (`LockID`/`OutputLeaser` aliases, `Utxo`), `txconfirm` (`Utxo`/`LockID`/`OutputLeaser` for fee-bump input selection and leasing).

## Invariants

- Taproot scripts must be imported under `KeyScopeBIP0086` (not the custom chain key scope), because btcwallet's block processing skips credit tracking for non-default scopes (`chainntfns.go:IsDefaultScope` check).
- **`Wallet.Balance` reports the default account only.** It passes
  `lnwallet.DefaultAccountName` to `ConfirmedBalance`, not the empty
  "all accounts" string. Imported taproot scripts (boarding and exit outputs
  registered via `ImportTaprootScript`) live in btcwallet's *imported* account
  and are deliberately excluded: they are unspendable by the wallet's own key
  ring, and the daemon already reports them under the separate boarding balance
  fields, so counting them here would overstate what the wallet can actually
  fund an exit or sweep with.
- `ImportedAddrs` is in-memory only and must be repopulated from the DB on
  restart. `ImportTaprootScript` recovers from
  `waddrmgr.ErrDuplicateAddress` by resolving the existing address via
  `addressForTaprootScript`, repopulating the filter without a second
  import attempt — covers the case where btcwallet already persisted the
  script but the in-memory filter started empty.
- Opening a watch-only wallet first checks the database exists:
  `btcwallet.New` would otherwise create a key-holding wallet from a random
  seed. A database that holds private keys is refused in watch-only mode.
- Imported accounts must get the number their key was derived at;
  `NewWatchOnlyBtcWallet` checks each import's `AccountNumber`, since
  btcwallet assigns one past the scope's last account.
- A split-signing wallet never derives from a placeholder family: their
  xpubs come from a key discarded at import, so funds sent to one could
  never be spent. The guard checks the family of every derivation, ECDH,
  message signature, MuSig2 session and locator-bearing `SignOutputRaw`.
  PSBT signing always goes to the remote signer, since authentication keys
  appear in no output script.
- Account-key wallets keep the static public passphrase, like seed
  wallets; the wallet password protects the keystore. Remote-signing
  wallets instead use the password as the public passphrase, which is why
  they need `RemoteSigner` configured to open.
- The user-supplied `Config.WalletPassword` is btcwallet's `PrivatePass`; the
  static `PublicWalletPassphrase` constant covers only public (watch-only)
  data. With neither `Config.Seed` nor `Config.RootKey` set the backend opens
  an existing wallet database; with exactly one set it creates a new one, and
  backends must refuse either when a database already exists (btcwallet
  would silently ignore it).

## Deep Docs

- [ARCHITECTURE.md](../ARCHITECTURE.md) — System-wide package map.
