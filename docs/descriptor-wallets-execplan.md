# Let self-managed wallets be defined by output descriptors

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current
while the work proceeds. Maintain this document according to `PLANS.md` in the
repository root.


## Purpose / Big Picture

Today a self-managed Wavelength wallet (the `lwwallet` and `btcwallet`
backends) can only be created from a 24-word aezeed mnemonic, from raw aezeed
entropy handed in by a host SDK, or from a hex seed in a development
environment variable. Users who already keep their Bitcoin keys as output
descriptors, for example the output of Bitcoin Core's `listdescriptors true`
or a backup produced by another descriptor wallet, have no way to bring that
key into Wavelength, and users of a Wavelength wallet have no way to take their
on-chain keys out to descriptor-based software, because aezeed is not BIP39 and
no other mainstream wallet reads it.

After this change an operator can run

    wavecli create --descriptor-file wallet.descriptors --birthday 2024-03-01

against a fresh daemon, where `wallet.descriptors` contains one or more
private output descriptors such as

    tr(tprv8ZgxMBicQKsPd.../86h/1h/0h/<0;1>/*)#xxxxxxxx

and get a working wallet: the identity public key, Ark boarding keys, VTXO
keys, out-of-round receive keys and on-chain taproot addresses are all derived
from the descriptor's root key exactly as they would have been from a seed,
`--recover` rebuilds Ark state the same way it does for a mnemonic, and
`wavecli wallet descriptors` prints the descriptors that the wallet watches so
they can be imported elsewhere. The same capability is exposed through the
`waverpc.InitWallet` RPC, the `wavewalletrpc.Create` RPC, the Go embedding SDK
(`sdk/wavewalletdk`), the gomobile bridge (`sdk/wavewalletdk/mobile`) and, in
the final milestone, the TypeScript, React Native and WDK packages that sit on
top of them.

The proof that it works is a round trip: create a wallet from a mnemonic,
fund it, export its private descriptors, stop the daemon, create a fresh
daemon from those descriptors with `--recover`, and observe the same
`identity_pubkey`, the same next on-chain address, and the same balance and
VTXOs.


## Progress

- [x] (2026-11-02) Audited seed handling in `waved`, `walletcore`, `lwwallet`,
  `btcwbackend`, `sdk/wavewalletdk`, `swapwallet`, the two protobuf services,
  and `wavecli create`; confirmed the btcwallet and lnd APIs this plan relies
  on in the module cache.
- [x] (2026-11-02) Re-audited after pulling 149 new commits (HEAD
  `3b7ed47f`): the plan's assumptions still hold; see `Surprises &
  Discoveries`. Added the watch-only and account-level extension design.
- [x] (2026-11-02) Milestone 0: prototype root-key wallet creation and prove
  key equivalence with the seed path. `TestRootKeyWalletMatchesSeedWallet`
  in `walletcore/rootkey_prototype_test.go` passes on regtest and mainnet;
  the three open questions are answered in `Surprises & Discoveries`.
- [x] (2026-11-02) Milestone 1: `walletdesc` package that parses, checksums
  and validates descriptors. All unit tests pass and 60 seconds of fuzzing
  (about 9 million executions) found nothing. `make ast-lint` could not run
  locally because the `sg` binary on this host is the shadow-utils group
  tool, not ast-grep; CI runs it.
- [x] (2026-11-02) Milestone 2: wallet backends accept a root extended key
  instead of a seed. `walletcore.ValidateCreateInput` and
  `walletcore.NewBtcWallet` are shared by both backends; `waved` carries a
  `walletCreateInput`. `TestWalletCreateFromRootKey` (lwwallet) shows a
  root-key wallet yields the same identity and first taproot address as the
  seed wallet and obeys the create/open invariants. `js/wasm` builds of
  `lwwallet` and `walletcore` compile.
- [x] (2026-11-02) Milestone 3: daemon RPC, CLI and swap-wallet admin
  surface for descriptor import. Proto fields added and regenerated with
  `make rpc`; `InitWallet` validates the source before claiming state;
  `swapwallet` forwards descriptors; `wavecli create --descriptor-file
  --birthday`. Unit tests cover the handler's early rejection and rollback,
  equivalence of the mnemonic and descriptor preparation paths, the swap
  wallet forwarding, and every CLI flag conflict. Remaining: the
  live-daemon acceptance run, folded into Milestone 4's system test.
  Deferred to Milestone 4: persisting the root fingerprint, which only
  export needs.
- [x] (2026-11-02) Milestone 4: descriptor export (`ListWalletDescriptors`,
  `wavecli descriptors`), fingerprint persistence (migration 28,
  `db.WalletKeyOriginStore`, SQLite and PostgreSQL tested) and round-trip
  tests. Done: a unit test drives the RPC over a real lwwallet (public export
  without origins, refusals, private export authorized by the mnemonic,
  fingerprint backfill, and a wallet rebuilt from the exported descriptors
  with the same identity and address chain). Two Docker system tests pass:
  `TestDescriptorWalletRestoresSeedWalletFunds` (75,000 sat recovered with
  the same identity and next address) and
  `TestDescriptorWalletSeesCoreDerivedFunds` (Bitcoin Core derives addresses
  from the public descriptors; the wallet sees both payments). Remaining: an
  end-to-end test that boards into a VTXO before export and restores Ark
  state with `--recover`. It needs the full in-process daemon with an
  operator. Recovery derives through the key ring, which Milestones 0 and 2
  prove identical for root-key wallets.
- [x] (2026-11-02) Milestone 5: Go embedding SDK and gomobile bridge.
  `wavewalletdk.StartDescriptorWallet` (golden-vector database password,
  cross-checked by an independent HKDF), `CreateWallet` with descriptors,
  `Client.ListWalletDescriptors`, the mobile `StartDescriptorWallet` and
  `ListWalletDescriptors`, the wasm `startDescriptorWallet` and
  `listWalletDescriptors` verbs, and `sdk/ark.InitWalletFromDescriptors`.
  The tagged SDK, mobile and wasm builds pass.
- [x] (2026-11-02) Milestone 6: downstream packages, each on its own
  `descriptors` branch. wavelength-sdk: types regenerated with tygo; core
  `DescriptorWalletClient` (`startDescriptorWallet`,
  `listWalletDescriptors`), descriptor `createWallet` and engine restores;
  the web profile lock and secret-field redaction; React Native native
  dispatch; docs and regenerated API data. All four package test suites
  pass (core 217, web 175, react 34, react-native 39). wavelength-mobile:
  Kotlin and Swift `createWallet(descriptors:birthday:)` and
  `listWalletDescriptors`. The Kotlin kit was compiled and unit-tested
  against an AAR built locally from this branch with `make mobile-android`;
  Swift was not compiled (no Swift toolchain on the build host).
  wavelength-wdk: Bare addon exports and stale-start retry for the new
  verbs. Not done: the demo apps' descriptor restore screens; the WDK
  manager-level descriptor mode, left for a product decision because
  `WalletManagerWavelength` is defined by one BIP39 seed with many accounts
  while a descriptor set is one fixed key; WDK tests, not run because the
  workspace has no installed dependencies.
- [x] (2026-11-02) Milestone 7: documentation and logging hygiene.
  `docs/daemon_cli_guide.md` and `docs/seed_restore_recovery.md` cover
  descriptor create, export and restore. Audit: no daemon interceptor logs
  request bodies, `walletdesc` values redact through `String` and
  `LogValue`, and web debug logs redact `descriptors`. Not done: the
  proposed ast-grep rule (ast-grep is not installed on the build host, so a
  rule could not be verified) and a release-notes entry (the repository has
  no release-notes file; `docs/release.md` describes the process).
- [x] (2026-11-02) Extension W0: `systest/remote_signer_test.go`
  (`TestRemoteSignerDaemon`) runs `waved` with `wallet.type=lnd` against the
  harness watch-only lnd and its lnd remote signer. It checks the identity key
  matches the signer, boards up to the JoinRound request (join authorization
  signed remotely), sends out of round up to the operator's SubmitPackage
  (Ark input signed remotely), and sweeps a matured boarding output on chain
  through its CSV exit leaf. It then times signer operations through the
  watch-only node and on the signer directly: Schnorr p95 about 1.9 ms remote
  against 0.6 ms local, MuSig2 session plus sign about 4.0 ms against 2.8 ms,
  so a 32-leaf wallet in a depth-12 tree projects to about 1.6 s of the
  30-minute admission budget. Setup and figures are in
  `docs/daemon_cli_guide.md` ("lnd with a remote signer"). Gap: the systest
  operator is a fake mailbox, so no round completes; tree and forfeit
  signing cost is measured with direct signer calls, not inside a round.
- [x] (2026-11-02) Extension W1: remove the raw private key and
  concrete-btcwallet signing assumptions. PSBT funding and signing go
  through the new `walletcore.Wallet.Controller`. Indexer proof signing
  already used the key ring's tagged-message path; a test with a key ring
  that refuses `DerivePrivKey` now pins it.
- [x] (2026-11-02) Extension W2, full bundles: `wallet.type=lwwallet` or
  `btcwallet` runs watch-only with `wallet.remotesigner.*`, no lnd behind
  the daemon. Done: `lib/keyfamily` registry with a pin test and a
  repository-walking test that refuses numeric families declared elsewhere
  (in place of the ast-grep rule, which cannot be verified on the build
  host); `walletdesc.ParseWatchOnlyBundle` (lnd account JSON or one entry
  per line, families 0 to 255 contiguous); `walletcore` watch-only
  creation and open, lnd's RPC key ring as Signer, KeyRing and Controller,
  and the start-up signer challenge; both backends; `InitWallet` /
  wavewalletrpc `Create` `watch_only_bundle`; `wavecli create
  --watch-only-bundle-file`; key origin source 2. Acceptance:
  `TestNativeRemoteSignerDaemon` passes the W0 scenario on lwwallet with a
  full bundle from an lnd signer. Not done: inbound (signer-dials-daemon)
  connections, and the SDK and mobile bridges for bundles.
- [x] (2026-11-03) Extension W2, minimal bundles: `walletdesc.ParseBundle`
  recognises a text bundle with private entries as a minimal bundle (BIP86
  account and fund families 6, 42, 44, 45, 202 as xpubs, authentication
  families 21 and 43 as xprvs, nothing else); `MinimalBundle.
  WithPlaceholders` completes it with placeholder xpubs from a discarded
  random key. `walletcore.OpenWithSigner` stores the local keys in the
  account keystore with the supplied family set, routes 21 and 43 to an
  in-process `accountsigner.Signer` and everything else (PSBTs included)
  to the remote signer, and wraps the RPC key ring in `guardedKeyRing`,
  which refuses any family outside the registry or not supplied. Opening
  restores the split and refuses a stored bundle missing a registry family
  (`ErrBundleOutdated`). Acceptance: `TestSplitSigning` (walletcore) uses a
  recording signer that sees no request for 21 or 43 and one for each fund
  family touched; `TestMinimalBundleDaemon` runs the W0 scenario on
  lwwallet against an lnd signer. Deviations: the guard is a wrapper over
  the RPC key ring plus a routing connection, rather than a `splitKeyRing`
  that implements every interface itself, so the key ring's signature
  verification covers both sides; the vHTLC and taproot-asset family
  checks are the same guard, since those families are used through this
  key ring; the recording-signer acceptance runs in walletcore rather than
  the systest, because an lnd signer cannot record requests per family.
- [x] (2026-11-02) Extension W3: account-level private keys with an
  in-process signer. `walletdesc.ParseAccountKeys` takes the on-chain
  `tr()`/`wpkh()` account xprvs plus the families as one coin-level
  `[fp/1017h/coinh]xprv` or one xprv per family, validated through the
  watch-only bundle rules. `accountsigner.Signer` answers the ten requests
  lnd's RPC key ring sends a remote signer (SignPsbt ported from lnd's
  `BtcWallet.SignPsbt`, SignMessage, DeriveSharedKey, seven MuSig2 calls
  via `input.MusigSessionManager`), so an account-key wallet is the W2
  remote-signing wallet with an in-process connection. The keys are
  encrypted with snacl under the wallet password in a
  `wavelength-account-keys` bucket of the wallet database, and
  `walletcore.OpenExisting` recognises the wallet by that bucket on
  unlock. InitWallet's `descriptors`, `wavecli create --descriptor-file`
  and `wavewalletdk.StartDescriptorWallet` accept the keys; key origin
  source 3. Acceptance: `TestAccountKeysDaemon` runs the W0 scenario on
  lwwallet with no lnd and no remote signer. Deviation from the plan: the
  plan said account-level keys are immune to the legacy-derivation caveat;
  that holds for per-family keys but not fully for a coin-level key (see
  Surprises).
- [x] (2026-11-03) Extension W4: Wavelength signer and bundle export, so no
  lnd is needed anywhere. `signerserver` serves an `accountsigner.Signer`
  as lnd's `signrpc.Signer` and `walletrpc.WalletKit` (the ten W2 requests
  plus read-only `ListAccounts`), with a generated TLS pair and its own
  macaroon. `cmd/wavesigner` adds `create` (encrypted key store from
  master-key descriptors, account keys or a Wavelength mnemonic), `run`,
  and `export-watchonly [--minimal]`. `walletdesc.BtcwalletAccountKeys`
  expands a master key into exactly the account keys btcwallet holds,
  checked against real wallets for all three legacy-derivation cases, and
  `walletdesc.FormatBundle` renders both bundle forms. Acceptance:
  `TestWaveSignerDaemon` and `TestWaveSignerMinimalDaemon` run the W0
  scenario with no lnd. Deviations: the signer is a separate small binary
  rather than a `waved` mode; the export is `wavesigner export-watchonly`
  run on the signer's key store, not `wavecli wallet export-watchonly`
  against a full-key daemon, which would need a new daemon RPC that
  releases account private keys for `--minimal`; and the systests run the
  signer in-process through the same `signerserver` package the binary
  serves, rather than as a second process.
- [x] (2026-11-03) Extension W5: per-family key overrides for fund slots.
  `walletdesc.Manifest` (JSON, version 1) assigns the on-chain account and
  each fund family a key with its real origin. `ParseManifest` refuses
  auth-family overrides, script descriptors, duplicate keys or origins and
  missing slots, and `CheckIdentity` refuses a family-6 override without
  `override_identity`. `MinimalBundle` joins the manifest with the
  authentication keys for the W2 split-signing import, keeping each
  account's origin so btcwallet records the real fingerprint. The wallet
  stores the canonical manifest in its keystore bucket, checks its accounts
  against it on every open (`ErrManifestMismatch`), and reports its hash in
  InitWallet, Create and GetInfo. On every start of a signer-backed wallet,
  `walletcore.ProbeSigner` replaces the identity-only check with a check of
  every fund slot. `wavesigner create --override SLOT=FILE` and
  `export-watchonly --manifest-out --auth-keys-out` are the signer side, and
  `wavecli create --watch-only-manifest --auth-keys-file
  [--override-identity]` is the daemon side. Acceptance:
  `TestManifestSignerDaemon` overrides families 42, 44 and 202 and the
  on-chain account from three other roots. It runs the W0 scenario
  (boarding with overridden 42, an out-of-round spend of a VTXO owned by
  overridden 44, a boarding sweep). A primary-only signer is refused for
  exactly those four slots, and a fresh wallet restored from the manifest
  derives every fund slot's key and reports the same hash. Deviations:
  - The signer keeps no separate routing table. Its account keys hold each
    slot's key at the slot's logical position, so a logical locator or PSBT
    path is translated implicitly, and the existing derived-key check still
    applies.
  - The W3 in-process path (`descriptors` with account keys) takes no
    manifest. Overrides need a signer.
  - The restore check compares keys, not recovered state. `--recover` needs
    an indexer, and the fake operator does not serve one.
  - No check makes a restore from the primary seed alone fail loudly. Such
    a restore is simply a different wallet, and the guide says so under
    Backup.
- [x] (2026-11-02) Extension W6: Ark output descriptor export
  (`ListArkOutputDescriptors`, `wavecli descriptors --ark [--kind]`), one
  `rawtr()` per boarding output, live VTXO and receive script. A
  miniscript-mismatch test passes, and Bitcoin Core derives the same address
  from a standard policy's export. Deviations: the response field is
  `output_descriptor`, because `descriptor` collides with protobuf's
  generated `Descriptor()` method; there is no cursor, so the list is bounded
  by wallet size; VTXO entries report exit delay 0 (unknown) because the
  delay sits in the policy template, which is not decoded here.
- [x] (2026-11-03) Follow-ups after W5:
  - **Restore check:** `Manifest.MatchKeys`, plus `wavesigner create
    --manifest`, refuses a key store that does not fill every slot with the
    manifest's key, and names the missing sources.
  - **Export from a full-key daemon:** the `ExportWatchOnlyBundle` RPC and
    `wavecli export-watchonly [--minimal]`. They need resupplied seed
    material, checked as for private descriptor export.
  - **SDK and mobile:** `wavewalletdk.StartWatchOnlyWallet` with
    `Config.RemoteSigner`, the mobile `StartWatchOnlyWallet` with
    `remote_signer_*` config fields, and `sdk/ark.InitWatchOnlyWallet`.
  - **Inbound signers:** `wallet.remotesigner.allowinbound` serves lnd's
    `SignCoordinatorStreams` behind `remotesigner:generate`, and
    `signerserver.ConnectWatchOnly` with `wavesigner run --watchonly-host`
    dials it. `TestWaveSignerInboundDaemon` is the acceptance test.
  - **Deviations:**
    - A restore from the primary seed alone, without the manifest, still
      cannot be detected. Nothing the seed derives records the overrides.
    - The SDK watch-only path is unit-tested against a stub daemon, like
      the descriptor path. No systest drives the SDK.
    - The downstream wavelength-wdk bindings do not expose the new verbs.
- [ ] Not started:
  - signer-side spending policy;
  - manifests for in-process account-key wallets (a local `wavesigner`
    covers them on native platforms);
  - the ast-grep rule against logging descriptors, which needs ast-grep
    installed to verify;
  - wavelength-wdk bindings for watch-only wallets;
  - a completed Ark round against a real operator.


## Surprises & Discoveries

- Observation: Wavelength's aezeed seed is not the seed lnd would use for the
  same mnemonic. `waved.MnemonicToSeedWithBirthday` copies the 16-byte aezeed
  entropy into a 32-byte array, so the BIP32 master key is computed from the
  entropy followed by 16 zero bytes, while lnd feeds the 16 bytes directly.
  Evidence: `waved/seed_manager.go` (`var seed [rawSeedLen]byte;
  copy(seed[:], cipherSeed.Entropy[:])` with `rawSeedLen = walletcore.SeedLen
  = 32`) and `aezeed.EntropySize = 16` in lnd's `aezeed/cipherseed.go`. This
  derivation is frozen for every existing wallet and must not change. It also
  means descriptor export is the only way to move an existing Wavelength key
  into other software, which strengthens the case for Milestone 4.

- Observation: btcwallet derives every hardened step with the deprecated
  `hdkeychain.ExtendedKey.DeriveNonStandard`, which for roughly one hardened
  derivation in 256 produces a different child from standard BIP32 (the
  parent private key is not left-padded to 32 bytes; the btcutil source
  calls this "issue 172" and exposes `IsAffectedByIssue172`). Bitcoin Core and
  other descriptor wallets use standard derivation. A descriptor imported
  from them can therefore, rarely, describe different addresses than the ones
  btcwallet will derive. Evidence: `waddrmgr/manager.go` lines 1455-1512 and
  `waddrmgr/scoped_manager.go` lines 398-405 in
  `btcwallet@v0.18.1-0.20260826052527-33c252f3b4d6`;
  `waved.WalletIdentityPubKeyFromSeed` already mirrors the non-standard
  derivation on purpose. Non-hardened steps are unaffected because their
  HMAC input is the public key.

- Observation: btcwallet can already build a wallet from a master extended
  key, and lnd's wrapper can adopt a wallet built outside it. Evidence:
  `wallet.Loader.CreateNewWalletExtendedKey(pubPass, privPass, rootKey,
  birthday)` in btcwallet's `wallet/loader.go`, and the `Wallet` field of
  `lnwallet/btcwallet.Config`, which `btcwallet.New` uses instead of opening
  or creating its own when non-nil.

- Observation: btcwallet's on-chain key scopes use coin type `0'` on every
  network. `KeyScopeBIP0049Plus`, `KeyScopeBIP0084`, `KeyScopeBIP0086` and
  `KeyScopeBIP0044` are all declared with `Coin: 0` in
  `waddrmgr/scoped_manager.go`, and lnd's `LndDefaultKeyScopes` reuses them.
  Only lnd's `m/1017'` scope uses the network coin type (`1'` off mainnet,
  via `walletcore.CoinTypeForNet`). So a regtest Wavelength wallet's
  taproot addresses are `m/86'/0'/0'/...`, while a Bitcoin Core regtest
  wallet's are `m/86'/1'/0'/...`. An earlier version of this plan required
  coin type `1'` off mainnet, which would have silently watched the wrong
  addresses; corrected in Milestone 1, the Decision Log, the tests and
  Concrete Steps.

- Observation: the standard Ark exit leaf cannot be written in miniscript.
  `CSV.Script` in `lib/arkscript/node.go` emits the inner script followed by
  `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP`, so the exit leaf of
  `StandardVTXOTemplate` is `<owner> OP_CHECKSIG <delay> OP_CSV OP_DROP`.
  Miniscript has no fragment ending in `OP_DROP`, and
  `and_v(v:pk(K),older(N))` compiles to `<K> OP_CHECKSIGVERIFY <N> OP_CSV`
  instead. The cooperative leaf, `<owner> OP_CHECKSIGVERIFY <operator>
  OP_CHECKSIG`, is plain `and_v(v:pk(OWNER),pk(OPERATOR))`. The internal key
  is the fixed `arkscript.ARKNUMSKey`, and `BuildTree` refuses any other.
  Consequence: Ark outputs can be exported only as concrete `rawtr()`
  descriptors, not as a ranged template (Milestone W6). An earlier
  conversational sketch used `and_v(v:pk(..),older(..))` for the exit leaf
  and would have described the wrong address.

- Observation (Milestone 3): `hdkeychain.ExtendedKey.Neuter` returns a key
  that shares its chain-code and public-key byte slices with the private
  key, so calling `Zero` on the private key afterwards also wipes the public
  key. The first `walletdesc` release rendered account xpubs with a zeroed
  chain code, and Bitcoin Core refused them ("key ... is not valid"). The
  original unit test compared against the same aliased helper, so it did not
  catch this. Fixed by re-parsing the serialization (`independentPublic`),
  with a test against an independent derivation that fails before the fix.
  A cross-check against Bitcoin Core 31.1 (regtest) on a root-key `lwwallet`
  then showed agreement on both checksums and the first address for both
  script types:

      tr pub: checksum match=True
      tr pub: Core index 0 == wallet first address: True (bcrt1pge4k5cjurqpq350ntvzpkvpnpvp27qxge6y5tsqu9h2f2qdfcjtqmprkn7)
      wpkh pub: checksum match=True
      wpkh pub: Core index 0 == wallet first address: True (bcrt1qw4ac9ct90eyh5cq5446yqnccq3x0dfyd2py94h)

- Observation (Milestone 4): btcwallet stores BIP84 account public keys
  with SLIP-132 version bytes (`vpub` on test networks, `zpub` on mainnet),
  while BIP86 keys use plain `tpub`/`xpub`. The key and chain code are
  identical, so a string comparison failed on the right mnemonic and a
  rendered descriptor would have carried a `vpub` no descriptor parser
  accepts. Evidence from a debug run:

      wpkh ours=tpubDCVGHLVWGWKy... btcw=vpub5YT79mKzFsHZ... same pubkey=true same chaincode=true

  Fixed by `walletdesc.StandardAccountPublicKey`, which normalizes to the
  network's standard version before comparing or rendering.

- Observation (Milestone 4): a public rendering of an account-level private
  descriptor printed the account `xprv`. It was caught by
  `TestCanonicalPrivate` before release and fixed by always neutering in the
  public branch of `Descriptor.Render`.

- Observation: no descriptor parser exists anywhere in the module graph
  (`grep -i 'descriptor\|miniscript' go.sum` is empty) and btcwallet has no
  descriptor support.

- Observation: btcwallet stores the encrypted master private key under the
  unexported `mhdpriv` bucket key and reads it with the unexported
  `fetchMasterHDKeys`; there is no exported way to read the root private key
  back from an existing wallet. Exporting private descriptors from a wallet
  that was created from a mnemonic therefore needs either an upstream accessor
  or a different export shape. Milestone 0 settles which.

- Observation (Milestone 0): a btcwallet built with
  `Loader.CreateNewWalletExtendedKey` from `hdkeychain.NewMaster(seed)`
  derives the same keys as one built with `Loader.CreateNewWallet(seed)`: all
  seven families (6, 21, 42, 43, 44, 45, 202) at indexes 0, 1 and 99, and
  the BIP86 and BIP84 account-0 xpubs, on regtest and mainnet.
  `waved.WalletIdentityPubKeyFromSeed` matches family 6, index 0.
  Evidence:

      --- PASS: TestRootKeyWalletMatchesSeedWallet (0.00s)
          --- PASS: TestRootKeyWalletMatchesSeedWallet/mainnet (3.95s)
          --- PASS: TestRootKeyWalletMatchesSeedWallet/regtest (3.97s)

- Observation (Milestone 0, question 1): a wallet built outside lnd's
  wrapper can be handed to `lnwallet/btcwallet.New` through `Config.Wallet`.
  `lwwallet` and `btcwbackend` close the database through
  `InternalWallet().Database().Close()` (`lwwallet/wallet.go`,
  `btcwbackend/wallet.go`), not through the loader, so ownership of the
  handle is unchanged. The browser loader options (`walletdb_wasm.go`) are
  loader options, and both `CreateNewWallet` and `CreateNewWalletExtendedKey`
  go through the same `Loader.createNewWallet`, so the browser build needs no
  separate path.

- Observation (Milestone 0, question 2): btcwallet does not record the master
  key fingerprint for the default accounts. `AccountProperties(scope,
  0).MasterKeyFingerprint` is `00000000` for both the seed-created and the
  root-key-created wallet. Evidence:

      scope m/86'/0': master fingerprint seed=00000000 root=00000000
      scope m/84'/0': master fingerprint seed=00000000 root=00000000

  Export therefore cannot learn the origin fingerprint from btcwallet.

- Observation (Milestone 0, question 3): btcwallet exports no function that
  returns an account-level or master extended private key. The only
  exported private derivation, `Wallet.DeriveFromKeyPath`, returns a bare
  `*btcec.PrivateKey` with no chain code, which cannot be rendered as an
  `xprv`.

- Observation: every downstream package (TypeScript web and React Native,
  native WalletKit, WDK) reaches Go only through the `sdk/wavewalletdk/mobile`
  JSON facade, via gomobile, the `cmd/wavewalletdk-wasm` build, or the Bare
  addon. None of them mention descriptors, xpubs or xprvs today.
  Evidence: survey summarized in `Artifacts and Notes`. Consequence: getting
  Milestone 5's facade verbs right is what unblocks all of Milestone 6, and
  the web transport picks them up without extra Go work.

- Observation (re-audit at `3b7ed47f`): the btcwallet bump to
  `v0.18.1-0.20261020173225-6bc3e2a4e6fc` changes only `wallet/chainntfns.go`,
  `wallet/interface.go` and `wallet/wallet.go` (reorg handling); `waddrmgr` is
  byte-identical, so `CreateNewWalletExtendedKey`, the `DeriveNonStandard`
  derivation and the unexported `fetchMasterHDKeys` are unchanged. lnd is
  unchanged. None of `waved/seed_manager.go`, `waved/wallet_ops.go`,
  `waved/rpc_wallet.go`, `walletcore`, `btcwbackend` or `cmd_create.go`
  changed. `lwwallet/walletdb_wasm.go` now retries `SQLITE_BUSY` and "database
  is locked" opens, which Milestone 0's browser-loader check must account for.
  New proto fields consumed numbers in `daemon.proto` and `wallet.proto`, so
  pick field numbers at implementation time. No new Ark key family was added,
  but commit `156e3485` signs indexer proofs for vHTLC recovery targets with a
  key family read from the database, which reinforces that the set of families
  is open-ended.

- Observation: commit `e8ab9b8d` ("accept watch-only lnd.account on remote
  signers") means Wavelength already runs with no private keys in its own
  process when `wallet.type=lnd` points at a watch-only lnd that signs through
  an lnd remote signer. `waved/lnd_account.go` detects remote signing by the
  `default` taproot account being watch-only. That is the existing watch-only
  deployment path and the template for the extension below.

- Observation: lnd ships every piece a native watch-only backend needs.
  `lnwallet/rpcwallet.NewRPCKeyRing(watchOnlyKeyRing, watchOnlyWalletController,
  remoteSignerConn, netParams)` implements `keychain.SecretKeyRing`,
  `input.Signer` (including all MuSig2 calls), `keychain.MessageSignerRing`
  and `lnwallet.WalletController`, forwarding signing, ECDH and MuSig2 to a
  remote signer; only `DerivePrivKey` returns
  `ErrRemoteSigningPrivateKeyNotAvailable`. lnd's `importWatchOnlyAccounts`
  (`config_builder.go`) builds the watch-only btcwallet by calling
  `ImportAccountWithScope` once per account xpub, including one account per
  key family in the `m/1017'/coin'` scope (lnd initializes 255 of them).
  Wavelength's own code needs a raw private key in exactly one place,
  `indexer.KeyRingSchnorrSigner.SignSchnorr` (`indexer/signer_adapters.go`),
  and calls the concrete `BtcWallet` for `FundPsbt`/`FinalizePsbt` in
  `waved/server.go` and `lwwallet/wallet.go`; everything else already goes
  through key-ring interfaces.

- Observation: remote-signer compatibility has been built up over several
  commits, not one. `7fdcca2c` (2026-02-26) replaced raw indexer private keys
  with a `SchnorrSigner` interface; `574ed11d` (2026-06-15) moved the
  out-of-round receive family from 987200 to 202 because a watch-only lnd has
  only the pre-provisioned families 0 to 255 and cannot create new family
  accounts without the master key; `a33908a9` (2026-07-30) added watch-only
  lnd test nodes backed by a signer to `harness/`; `e8ab9b8d` (2026-10-20)
  accepted a watch-only `lnd.account`. Consequence for W2: every key family
  Wavelength ever uses must stay below 256, and W0 should reuse the
  `a33908a9` harness constructor rather than build a new one.

- Observation: a watch-only lnd verifies every signature its remote signer
  returns, and a plain lnd does not. The first W0 run failed with "remote
  signer returned invalid taproot script spend signature" because the systest
  fixture seeds a VTXO paying a random key at locator (44, 7): a plain lnd
  signs with its own (44, 7) key and returns a signature that does not verify,
  which the fake operator never checks. The remote-signer test seeds a VTXO
  owned by the signer's real key instead (`seedVTXOWithOwner`). Consequence
  for W2 and W4: a native remote signer should verify returned signatures the
  same way, since it turns a silent bad signature into an immediate error.
  Evidence: `systest/remote_signer_test.go`, first-run log.

- Observation: the remote signer hop adds about 1 to 1.5 ms per signature on
  one host, far below lnd's 5 s `remotesigner.timeout`. W0 found no need to
  raise any timeout; W2's own signer timeout can start from the same 5 s and
  revisit for cross-network signers.
  Evidence: `TestRemoteSignerDaemon` log, 20 samples per operation.


- Observation: btcwallet numbers an imported watch-only account one past the
  last account of its scope and ignores the key's own child index, and an
  empty scope starts at 0. A bundle with a gap, or imported out of order,
  would therefore put every later family's key under the wrong number and
  lock funds to keys the signer would derive differently. lnd's own
  `importWatchOnlyAccounts` sorts with a comparator that is not a strict
  order (`Purpose < || Index <`), which happens to work only because lnd
  always imports complete sets. Wavelength requires families 0 to 255
  contiguous, sorts by (purpose, account), and checks each import's
  `AccountNumber`.
  Evidence: `waddrmgr.ScopedKeyManager.NewAccountWatchingOnly`,
  `walletcore/watchonly.go`.

- Observation: `btcwallet.New` with no bundle and no database silently
  creates a key-holding wallet from a random seed. The watch-only open path
  probes the database first.
  Evidence: lnd `lnwallet/btcwallet.New`.

- Observation: btcwallet's legacy hardened derivation reaches into a seed
  wallet's key family accounts in three distinct ways, measured on real
  wallets (walletcore `TestLegacyDerivationFamilyScope`): no leading zero
  byte on `m/1017'` or `m/1017'/coin'` leaves every family equal to
  standard BIP32; a leading zero on the coin-level key changes family 0
  only, because btcwallet derives account 0 from its unpadded in-memory key
  while creating the scope and every later account from the stored, padded
  key; a leading zero on `m/1017'` changes every family. Also, a key parsed
  from text is always padded, so comparing standard and legacy derivation
  on a parsed key never differs; the first attempt at a coin-level check
  did exactly that and passed every key. Consequence: coin-level imports
  are accepted (family 0 is unused), and the `m/1017'` case is documented
  as undetectable from the coin-level key.
  Evidence: `walletcore/legacy_family_test.go`, `walletdesc/accountkeys.go`.

- Observation: lnd's `rpcwallet.OutboundConnection.RequestTimeout()` returns
  its connection timeout and never reads `ExperimentalRequestTimeout`, so
  W2's `wallet.remotesigner.requesttimeout` had no effect until
  `DialRemoteSigner` wrapped the connection to report it.
  Evidence: lnd `lnwallet/rpcwallet/remote_signer_connection.go`,
  `walletcore/remote_signer_dial.go`.

- Observation: a signer holding only the primary root fails the slot probe
  for exactly the overridden slots and passes every other one. So the
  probe's error names which slots of a backup are missing their keys.
  Evidence: `walletcore/signer_probe_test.go`,
  `systest/manifest_signer_test.go`.

- Observation: the signer needs no routing table. `rpcwallet.RPCKeyRing`
  sends logical locators and, for PSBT inputs, the logical path under the
  fingerprint btcwallet stored for the account. That is the override's real
  fingerprint, because the import passes it. An account-key signer that
  holds each slot's own key at that slot already answers both correctly.
  Evidence: `TestManifestSignerDaemon`, whose on-chain probe signs a PSBT
  with the overridden account.

## Decision Log

- Decision: In this plan a "descriptor wallet" is a wallet whose private
  descriptors all share one BIP32 master (depth-zero) private key. Wavelength
  extracts that root key and builds the wallet from it; the descriptors'
  script types and paths are validated against what the wallet will actually
  watch but do not otherwise change behaviour.
  Rationale: Every Ark key Wavelength uses (identity, boarding, VTXO owner and
  signing, round-join auth, out-of-round receive, vHTLC signer) is derived
  under the lnd key scope `m/1017'/coin'/family'/0/index`, with hardened
  family steps. Only the master private key can produce those. An
  account-level key such as `[d34db33f/86h/0h/0h]xprv...` cannot, so a wallet
  built from it could receive on chain but could never join a round, sign a
  forfeit, or authenticate to its mailbox. Bitcoin Core's own private export
  uses the master-key form, so the common real-world input is covered.
  Date/Author: 2026-11-02, plan author.

- Decision: Milestones 0 to 7 reject watch-only (xpub) descriptors and
  account-level private descriptors with explicit errors; both are delivered
  by the extension milestones W0 to W3 below, which build on Milestones 1 and
  2.
  Rationale: Ark participation is interactive signing (MuSig2 round trees,
  forfeits, out-of-round sends, mailbox and indexer proofs, exit sweeps), so a
  watch-only daemon needs an online signer, and account-level keys need a
  signer that is not btcwallet. Both reduce to "watch-only btcwallet plus a
  pluggable signer", which lnd already implements (`rpcwallet.RPCKeyRing`),
  so they are a contained follow-on rather than a redesign. Shipping the
  root-key path first keeps the first release small and gives W0 to W3 the
  parser and backend plumbing they need.
  Date/Author: 2026-11-02, plan author (revised after re-audit).

- Decision: Accept only `tr(...)` key-path descriptors under purpose 86 and
  `wpkh(...)` descriptors under purpose 84, account 0, with coin type `0'`
  on every network (see the btcwallet coin-type observation in
  `Surprises & Discoveries`), using receive/change branches `0` and `1`
  (either as BIP389 `<0;1>` multipath or as two separate descriptors).
  Descriptors with coin type `1'` from test-network wallets such as
  Bitcoin Core are refused rather than remapped. Supporting them would need
  an extra `{86, 1}` btcwallet scope, and Wavelength's own address and change
  generation would have to move to it, because lnd maps the taproot address
  type to the fixed `KeyScopeBIP0086`. That is out of scope.
  Rationale: btcwallet creates its default scopes (`waddrmgr.DefaultKeyScopes`:
  BIP49-plus, BIP84, BIP86, BIP44) for account 0 only. Purpose 49 in btcwallet
  is "BIP49-plus", whose change branch is native P2WKH rather than nested, so
  change outputs another wallet created at `49'/.../1/*` would be invisible.
  Accepting a path btcwallet does not watch would silently hide funds, so it
  is an error rather than a warning. Wavelength itself only issues BIP86
  addresses.
  Date/Author: 2026-11-02, plan author.

- Decision: Refuse to import any descriptor whose hardened path from the root
  derives differently under standard BIP32 and under `DeriveNonStandard`.
  Rationale: otherwise the wallet would watch different addresses than the
  descriptor describes, the exact silent-loss failure this feature must not
  have. The check is cheap and deterministic; the error message names the
  cause so a user can move funds with their original software.
  Date/Author: 2026-11-02, plan author.

- Decision: Write a small in-repository parser (`walletdesc`) instead of
  adding a third-party descriptor library.
  Rationale: the accepted grammar is tiny (two script functions, one key
  expression form, paths, multipath, checksum), the module graph currently
  depends only on btcsuite and lnd for key handling, and key-parsing code is
  security-sensitive enough that owning and testing it is preferable to a new
  dependency. Milestone 1 may revisit this if a well-maintained btcsuite-based
  library appears; record any change here.
  Date/Author: 2026-11-02, plan author.

- Decision: Descriptor import is additive. Fresh wallets are still generated
  as aezeed mnemonics, existing wallet databases are untouched, and nothing
  about the descriptor is persisted by Wavelength beyond what btcwallet
  already stores (the encrypted master key and account public keys).
  Rationale: avoids a database migration and a second source of truth; the
  descriptors can always be recomputed from btcwallet when the wallet is
  unlocked.
  Date/Author: 2026-11-02, plan author. Superseded in part by the next
  entry.

- Decision (after Milestone 0): Wavelength persists the root key fingerprint
  at wallet creation, for both mnemonic and descriptor wallets, in a new
  single-row table in the daemon database added by an sqlc migration. Public
  export uses it as the key origin. A wallet created before this change has
  no stored fingerprint. Its public export omits the origin, which BIP380
  allows, until the user supplies the mnemonic or root descriptor once, at
  which point the fingerprint is computed and stored.
  Rationale: Milestone 0 showed btcwallet stores `00000000` for the default
  accounts, so there is no other source for the fingerprint.
  Date/Author: 2026-11-02, plan author.

- Decision (after Milestone 0): private export needs no upstream btcwallet
  change. `ListWalletDescriptors` with `include_private` requires the caller
  to resupply the mnemonic (with its passphrase) or the root descriptor.
  `waved` recomputes the root key, checks it against the open wallet's BIP86
  and BIP84 account xpubs and identity key, refuses on any mismatch, and only
  then renders the private descriptors.
  Rationale: btcwallet exposes no extended private key (Milestone 0,
  question 3). Re-entering the secret also stops an unlocked daemon from
  leaking its root key to anyone holding an admin macaroon. The verification
  step makes this a safe "convert my mnemonic to descriptors" operation that
  cannot produce descriptors for a different wallet.
  Date/Author: 2026-11-02, plan author.

- Decision: W2 supports split signing. Fund keys (`86'` account, families 6,
  42, 44, 45, 202) stay on the remote signer. Authentication keys (families
  21 and 43) are held locally as account-level xprvs from the same root.
  Families a minimal bundle does not supply get placeholder xpubs behind a
  derive-and-sign guard, and all families are classified in one registry
  enforced by lint and tests.
  Rationale: these two authentication families are needed to operate (round
  joins, Lightning receives) but cannot move funds. Keeping them local means
  the signer holds exactly the keys that matter, and the bundle shrinks from
  255 family keys to seven. Placeholders are unavoidable while lnd's
  `BtcWallet.Start` insists on accounts 1 to 255. They are safe only if
  nothing can ever derive from them, hence the guard and the registry. The
  protection is for keys at rest, not against a compromised running daemon,
  which can still ask the signer to sign; signer-side policy is future work.
  Date/Author: 2026-11-02, plan author, at the user's request.

- Decision: Add W5, per-family overrides. Each fund slot (families 6, 42,
  44, 45, 202 and the on-chain account) may take its key from an independent
  source, described by a manifest. Authentication families stay on the
  primary root. Overrides are single keys only, and the signer routes by
  slot.
  Rationale: the user asked to choose which keys move funds per family.
  `waved` only ever derives non-hardened children from account xpubs, and
  btcwallet stores a fingerprint per imported account, so the watch-only
  side needs no structural change. The signer does change, because lnd's
  remote key ring names keys logically (family and index), and an lnd signer
  resolves those against one root. Multisig slots are excluded because Ark
  policies and tree signing assume one user key. The cost is a harder backup
  (every source plus the manifest), which is why restore without the
  manifest is made to fail loudly and the manifest hash is shown everywhere.
  Date/Author: 2026-11-02, plan author, at the user's request.

- Decision: Key-family entries in bundles and manifests are ranged BIP380
  key expressions with a mandatory `/0/*` suffix and a checksum, not output
  descriptors. Ark outputs are exported, never imported, as one non-ranged
  `rawtr()` descriptor per concrete output (W6).
  Rationale: no family key is paid to on its own. The scripts that hold them
  also depend on operator terms that rotate, on per-swap payment hashes, or
  on other round participants, and the standard exit leaf has no miniscript
  form. A ranged output descriptor would therefore be either wrong or stale.
  `waved` needs only the key from the user, and it takes operator data from
  authenticated terms, never from user input. The `/0/*` suffix states the
  derivation the key ring performs, and the checksum catches copy errors.
  Exporting concrete `rawtr()` descriptors is exact by construction, because
  each one is read from the pkScript `arkscript` already produced.
  Date/Author: 2026-11-02, plan author, at the user's request.

- Decision (Milestone 1): the text-rendering method is
  `Descriptor.Render(includePrivate bool) (string, error)`, not
  `String(includePrivate bool)`. `Descriptor` and `WalletDescriptors` instead
  implement a redacted `String()` and `slog.LogValuer`. The package also
  exports `Checksum`, `AddChecksum`, `Fingerprint`, `NewAccountDescriptor`,
  `MaxDescriptors` and the extra sentinels `ErrMalformedDescriptor`,
  `ErrBadChecksum`, `ErrUnsupportedDescriptor`, `ErrNoDescriptors`,
  `ErrTooManyDescriptors` and `ErrDuplicateDescriptor`.
  Rationale: a method named `String` with a parameter cannot satisfy
  `fmt.Stringer`. If `fmt` printed a struct whose exported field holds an
  `*hdkeychain.ExtendedKey`, it would call that key's `String` and print the
  `xprv`, so the safe default for `%v` has to be a redacted `String()`.
  `NewAccountDescriptor` is needed by Milestone 4 to render public
  descriptors from btcwallet's account xpubs when no master key is
  available. The extra sentinels let every `Parse` failure map to exactly
  one error for RPC status codes.
  Date/Author: 2026-11-02, implementer.

- Decision (Milestone 4): the CLI command is `wavecli descriptors`, a
  top-level command in the Introspection group next to `getinfo`, not
  `wavecli wallet descriptors`. Private export needs only the resupplied
  mnemonic or root descriptors, not the wallet password as well.
  Rationale: there is no `wallet` command group, and the top-level wallet
  verbs are all `wavewalletrpc`-backed while this one is a `waverpc` call
  like `getinfo`. Possession of the seed material is a strictly stronger
  authorization than the password, and the daemon verifies it against the
  open wallet's account keys and identity before rendering anything. The RPC
  sits under the same `info:write` macaroon permission as `InitWallet`.
  Date/Author: 2026-11-02, implementer.

- Decision: W3's signer implements lnd's `RemoteSignerConnection` and sits
  behind the same `rpcwallet.RPCKeyRing` as W2, rather than implementing
  `input.Signer` and a PSBT-finalizing controller directly.
  Rationale: the RPC key ring already turns every signing call, tweak and
  PSBT finalization into ten requests and verifies each returned
  signature, and W2's systest proves that path under Ark traffic. Only
  PSBT signing had to be ported. lnd's own signrpc server could not be
  reused in process: it is behind the `signrpc` build tag.
  Date/Author: 2026-11-02, implementer.

- Decision: account-key wallets keep the static public passphrase and put
  the password on the keystore, unlike W2's remote-signing wallets.
  Rationale: the backend can then open any database with the static
  passphrase and tell a key-holding, account-key or remote-signing wallet
  apart afterwards (keystore bucket present, or not), so unlocking an
  account-key wallet needs no config. Their public data has the same
  protection as a seed wallet's.
  Date/Author: 2026-11-02, implementer.

- Decision: watch-only mode is selected by `wallet.remotesigner.enable`,
  not by a stored marker, and the wallet key origin records source 2 as a
  cross-check. btcwallet's own `WatchOnly()` flag is the authority: a
  database that holds private keys is refused in remote-signing mode, and
  lnd refuses the reverse.
  Rationale: the daemon needs the mode before it can open the database (the
  password is the public passphrase only for watch-only wallets), so a
  marker inside that database cannot select it.
  Date/Author: 2026-11-02, implementer.

- Decision: migration 000028 was widened in place to admit source 2 rather
  than rebuilt by a new migration.
  Rationale: it has not shipped; SQLite cannot alter a CHECK constraint, so
  a new migration would have to rebuild the table for no compatibility gain.
  Date/Author: 2026-11-02, implementer.

- Decision: the remote signer request timeout defaults to 10 s.
  Rationale: W0 measured 1 to 4 ms per signature on one host; 10 s leaves
  room for a signer across a network while staying far inside a round's
  signing budget.
  Date/Author: 2026-11-02, implementer.

- Decision: W0 runs against the systest fake operator and stops each flow at
  the operator boundary, measuring round signing with direct signer calls.
  Rationale: this repository has no real Ark operator to complete a round,
  and the remote-signer risk is in the signing calls, which the test drives
  through the same watch-only node waved uses. A completed round needs an
  end-to-end environment with a real operator.
  Date/Author: 2026-11-02, implementer.

- Decision: W5 manifests reach the daemon as a separate
  `watch_only_manifest` plus `auth_keys` pair rather than as a third bundle
  form.
  Rationale: the manifest is public and is the backup record whose hash
  users compare, while the authentication keys are secret. Keeping them in
  separate files lets the manifest be copied freely and the keys be written
  owner-only.
  Date/Author: 2026-11-03, implementer.

- Decision: an inbound signer connection is owned by the daemon, not the
  wallet. An existing wallet is auto-unlocked only after the RPC listener
  serves.
  Rationale: lnd's `SignCoordinator` cannot run again once stopped, so a
  wallet that stopped it on a failed start would leave the daemon unable to
  sign until restart. The signer can only connect once the listener is up,
  and the old order unlocked before it, so every start would time out.
  Date/Author: 2026-11-03, implementer.

- Decision: Protobuf changes add new fields rather than wrapping the existing
  `mnemonic` field in a `oneof`.
  Rationale: moving an existing field into a `oneof` is wire compatible but
  changes the generated Go accessors and breaks every caller. Mutual
  exclusion is enforced in the handlers instead.
  Date/Author: 2026-11-02, plan author.


## Outcomes & Retrospective

Nothing implemented yet.


## Context and Orientation

Wavelength is a Go repository whose daemon, `waved` (package `waved/`,
binary `cmd/waved`), runs a Bitcoin wallet, an Ark client and optional
Lightning swaps. Ark is an off-chain protocol in which a user's coins are
represented as VTXOs (virtual transaction outputs) that the user co-signs with
an operator in periodic "rounds"; taking part requires the wallet to produce
Schnorr and MuSig2 signatures on demand. The companion CLI is `wavecli`
(`cmd/wavecli`).

The wallet backend is chosen with `wallet.type`. `lnd` delegates keys to an
external lnd node and is out of scope here. `lwwallet` (package `lwwallet/`,
chain data from an Esplora HTTP API) and `btcwallet` (package `btcwbackend/`,
chain data from neutrino) are the "self-managed" backends. Both embed
`walletcore.Wallet` (`walletcore/wallet.go`), which wraps lnd's
`lnwallet/btcwallet.BtcWallet`, which in turn wraps the btcsuite `btcwallet`
library. btcwallet keeps keys in an encrypted bbolt database (or an OPFS
SQLite database in browser builds) inside the daemon's network data
directory; the user's wallet password is its "private passphrase".

BIP32 hierarchical deterministic keys start from a 64-byte HMAC of a seed,
giving a master (root, depth 0) extended private key, written `xprv...` on
mainnet and `tprv...` on test networks. Child keys are addressed by paths such
as `m/86'/0'/0'/0/5`; an apostrophe or `h` marks a hardened step, which needs
the parent's private key. The root key's fingerprint is the first four bytes
of HASH160 of its public key.

An output descriptor (BIP380 and siblings) is a text description of a set of
output scripts. In `tr([d34db33f/86h/0h/0h]xpub.../<0;1>/*)#abcd1234`, `tr`
is the script function (taproot key path), `[d34db33f/86h/0h/0h]` is the key
origin (root fingerprint and path from the root), `xpub...` is the key,
`/<0;1>/*` means "branch 0 and branch 1 (BIP389 multipath), every index", and
`#abcd1234` is an eight-character checksum (BIP380). When the key is a root
key the origin is usually omitted and the full path follows the key:
`tr(xprv.../86h/0h/0h/<0;1>/*)`. A "private descriptor" contains `xprv`/`tprv`;
a "public" or "watch-only" one contains `xpub`/`tpub`.

lnd's key ring (`keychain.NewBtcWalletKeyRing`) derives application keys at
`m/1017'/coin'/family'/0/index`, where coin is 0 on mainnet and 1 elsewhere
(`walletcore.CoinTypeForNet`) and "family" is a small integer naming the use.
Wavelength uses family 6 (`keychain.KeyFamilyNodeKey`), index 0, for the
daemon identity key, which determines its mailbox ID (`waved/rpc_wallet.go`,
`identityKeyFamily`), signs mailbox, indexer and credit-account
authentication, and is also the client key in Lightning swap vHTLCs
(`sdk/swaps/in_swap.go`, `sdk/swaps/recovery.go`); 21, index 0
(`lndclient.SharedKeyLocator`), as the base of the per-payment receive-auth
keys, which `RPCServer.deriveReceiveAuthKey` computes as a tagged hash of
`ECDH(key, NUMS point)` and the payment hash; 42 for boarding keys
(`wallet/wallet.go`); 43 for round-join authentication
(`round/join_auth.go`); 44 and 45 for VTXO owner and tree-signing keys
(`lib/types/boarding.go`); 202 for out-of-round receive keys
(`waved/receive_script.go`); and families read back from the database for
vHTLC recovery and taproot assets. Of these, 6, 42, 44, 45 and 202 lock or
spend funds; 21 and 43 only authenticate. All of them are hardened under the
root, which is why the root private key is required.

Wallet creation flows today:

`waved/seed_manager.go` holds `GenerateSeed` (new aezeed mnemonic),
`MnemonicToSeedWithBirthday` (mnemonic to 32-byte seed plus birthday),
`LoadSeedFromEnv` (`WAVED_LWWALLET_SEED`, hex, development only) and
`LoadSeedBirthdayFromEnv`. `waved/wallet_ops.go` holds
`WalletSeedFromMnemonic` (validation used by the RPC and SDK) and
`WalletIdentityPubKeyFromSeed` (computes the identity key without opening a
database, used to pin identity before creation). `waved/rpc_wallet.go`
implements `GenSeed`, `InitWallet` and `UnlockWallet` on the `waverpc`
`DaemonService` (`waverpc/daemon.proto`), guarded by the atomic `walletState`
machine (`None`, `Locked`, `Unlocking`, `Ready`), and calls
`Server.startSelfManagedWallet(ctx, seed, password, birthday)`, which
dispatches to `startLwwallet` or `startBtcwallet`. A nil seed means "open the
existing database"; a non-nil seed means "create". `waved/server.go` (around
line 1940) runs the environment-seed create-or-open path at startup.
`walletcore.Config` (`walletcore/config.go`) carries `Seed`,
`WalletPassword`, `Birthday`, `ChainParams`, `RecoveryWindow` and `DBDir`;
`lwwallet.New` (`lwwallet/wallet.go`) and the btcwbackend constructor enforce
"seed only when no database exists" in `checkWalletInvariants` and pass
`HdSeed` to `btcwallet.New`.

`rpc/wavewalletrpc/wallet.proto` is the flat wallet facade. Its `Create` RPC
(`CreateRequest`: `wallet_password`, `seed_passphrase`, `mnemonic`,
`recover_state`, `recovery_window`) proxies `GenSeed` plus `InitWallet`; it is
implemented in `swapwallet/admin.go` and `swapwallet/service.go`. `wavecli
create` (`cmd/wavecli/waveclicommands/cmd_create.go`) exposes
`--wallet-password-file`, `--password-stdin`, `--seed-passphrase-file`,
`--print-mnemonic-json`, `--recover`, `--mnemonic-file` and
`--recovery-window`.

The Go embedding SDK `sdk/wavewalletdk` runs the daemon in-process.
`client.go` has `CreateWallet` and `UnlockWallet`; `external_seed.go` has
`StartExternalSeedWallet`, which takes 16 bytes of host-derived entropy,
derives a database password from it with HKDF
(`deriveExternalSeedDBPassword`, info string
`wavewalletdk:external-seed:dbpw:v1`), optionally pins
`ExpectedIdentityPubKey`, and imports or unlocks; `passkey.go` derives
entropy from a WebAuthn PRF output. `sdk/wavewalletdk/mobile` exposes these
as JSON-in/JSON-out functions for gomobile (`CreateWallet`,
`StartExternalSeedWallet`, and so on). The separate repositories
`wavelength-sdk` (TypeScript monorepo), `wavelength-mobile` (Android and iOS)
and `wavelength-wdk` (WDK wallet module and a Bare native addon) consume these
bridges; Milestone 6 covers them.

Ark-state recovery (`docs/seed_restore_recovery.md`,
`Server.RecoverWalletState`) scans key indexes `0..N-1` in the boarding, VTXO
owner and out-of-round receive families through the key ring. Because it only
uses the key ring, it works unchanged for a descriptor wallet once the key
ring is built from the same root.

Repository rules that apply throughout (from `CLAUDE.md`): never edit
generated code (`make rpc` after `.proto` edits, committed separately); run
`make fmt-changed`, `make lint-changed-local` and the relevant tests before
every commit; commit subjects are `pkg: summary` of at most 69 characters;
no underscores in Go test names.


## Plan of Work

The work is seven milestones. Milestones 0 to 4 are the core daemon change
and should land in order. Milestone 5 depends on 3. Milestone 6 is in other
repositories and depends on 5 being released. Milestone 7 runs alongside the
others and closes the work.


### Milestone 0: prototype root-key wallets (prototyping)

Goal: prove, before any surface changes, that a btcwallet built from a master
extended key is indistinguishable from one built from the corresponding seed,
and settle the open questions about reading keys back out.

Add a test-only file `walletcore/rootkey_prototype_test.go` (or under
`lwwallet/` if a running chain backend is needed; prefer a pure database test
with no chain source). For a fixed 32-byte seed, build wallet A with
`wallet.Loader.CreateNewWallet(pub, priv, seed, birthday)` and wallet B with
`hdkeychain.NewMaster(seed, params)` followed by
`Loader.CreateNewWalletExtendedKey(pub, priv, rootKey, birthday)`, each in its
own temporary directory, both for regtest and mainnet parameters. Wrap each
in `keychain.NewBtcWalletKeyRing` and assert that `DeriveKey` returns the same
public key for families 6, 42, 43, 44, 45 and 202 at indexes 0, 1 and 99, that
the first five BIP86 and BIP84 external and internal addresses match, and that
`waved.WalletIdentityPubKeyFromSeed` agrees with the family-6 key.

Then answer three questions and record the answers in `Surprises &
Discoveries`: whether `lnwallet/btcwallet.New` with a pre-built `Config.Wallet`
starts correctly through the existing `lwwallet.New` path (including the
browser `walletdb_wasm.go` loader options, which create the database handle
the loader adopts); whether `waddrmgr.AccountProperties.MasterKeyFingerprint`
is populated for the default account-0 scopes of a seed-created wallet (if
not, the fingerprint must be computed at import and export needs it from
somewhere else); and whether any exported btcwallet API returns an account or
master extended private key. If none does, decide between a minimal upstream
accessor in btcwallet (preferred, used via a `replace` directive until
released) and exporting public descriptors only in Milestone 4.

Acceptance: `make unit pkg=./walletcore case=TestRootKeyWalletMatchesSeedWallet`
passes, and the three answers are written into this document. Delete the
prototype or promote it into the Milestone 2 tests before Milestone 2 lands.


### Milestone 1: the `walletdesc` package

Goal: a self-contained package that turns user-supplied descriptor text into a
validated root key, or a precise error, with no daemon dependency.

Create `walletdesc/` with `doc.go`, `checksum.go`, `parse.go`,
`validate.go`, `derive.go` and a `CLAUDE.md`/`AGENTS.md` pair matching the
other packages. The parser handles: optional `#checksum` (verified with the
BIP380 polymod algorithm when present, and always emitted on output);
script functions `tr(KEY)` with no script tree and `wpkh(KEY)`; key
expressions with an optional origin `[8 hex chars` followed by `/step`s`]`;
extended keys in base58 (`xprv`, `tprv`, `xpub`, `tpub`); path steps with `h`,
`H` or `'` as the hardened marker; a single optional `<a;b>` multipath step;
and a final `*`. Everything else (`sh`, `pkh`, `wsh`, `multi`,
`sortedmulti`, `rawtr`, `addr`, `raw`, `combo`, `tr` with a script tree,
hardened wildcards `*h`, more than one multipath step, WIF keys, bare public
keys) is a parse error naming the unsupported construct.

Validation (`validate.go`) takes the parsed descriptors plus
`*chaincfg.Params` and enforces, in this order, with a distinct exported
error for each so callers and tests can match them: at least one descriptor
and at most a small fixed number (eight is plenty); every key is private
(`ErrWatchOnlyDescriptor`); every key is a root key, meaning depth zero and,
if an origin is present, an origin fingerprint equal to the key's own
fingerprint and an empty origin path (`ErrNotRootKey`, whose message
explains that Ark keys need the master key); all descriptors share the same
root (`ErrMixedRootKeys`); the key's network version bytes match the params
(`ErrNetworkMismatch`); each path is exactly
`purpose'/0'/0'/branch/*` with purpose 86 for `tr` or 84 for `wpkh`, coin
type `0` on every network (btcwallet's on-chain scopes hard-code it; only the
`1017'` scope uses `walletcore.CoinTypeForNet`), account 0, and branches drawn
from {0, 1} (`ErrUnsupportedPath`, whose message for a `1'` coin type on a
test network says why); and the hardened prefix of each path
derives the same account key with `Derive` and with `DeriveNonStandard`
(`ErrLegacyDerivationMismatch`, explained in `Surprises & Discoveries`).

The package exposes:

    // Parse parses and validates descriptor text for the given network.
    func Parse(text []string, params *chaincfg.Params) (*WalletDescriptors, error)

    type WalletDescriptors struct {
            // Root is the master private key shared by every descriptor.
            Root *hdkeychain.ExtendedKey
            // Fingerprint is the root key fingerprint.
            Fingerprint uint32
            // Descriptors are the validated descriptors in canonical form.
            Descriptors []Descriptor
    }

    // Zero wipes the private key material.
    func (w *WalletDescriptors) Zero()

    // Render renders a descriptor in canonical form with checksum; private
    // keys are rendered only when includePrivate is true. (Implemented as
    // Render rather than String(bool) so that String can be a redacted
    // fmt.Stringer; see the Decision Log.)
    func (d *Descriptor) Render(includePrivate bool) (string, error)

    // CanonicalPublic returns the account-level public descriptors that a
    // wallet built from root watches: tr for purpose 86 and wpkh for 84.
    func CanonicalPublic(root *hdkeychain.ExtendedKey, params *chaincfg.Params) ([]Descriptor, error)

`Descriptor.String(false)` renders the public form as the account xpub with
its origin, for example `tr([d34db33f/86h/1h/0h]tpub.../<0;1>/*)#...`, which
is what other wallets import as watch-only. `Descriptor` must not implement
`fmt.Stringer` or `slog.LogValuer` in a way that could print private keys; add
a `LogValue` that prints only the fingerprint and script type.

Tests (`walletdesc/*_test.go`): checksum vectors from BIP380; parse vectors
covering every accepted form and every rejected construct; validation tests
for each exported error; a known Bitcoin Core mainnet `listdescriptors true`
output that must parse to the expected fingerprint; a Bitcoin Core regtest
output (coin type `1'`) that must be refused with `ErrUnsupportedPath`;
round-trip `Parse` then `String(true)` then `Parse` equality; and an
issue-172 vector, found by a small search in the test over fixed seeds for a
root whose `86'` or `84'` hardened chain is affected, asserting
`ErrLegacyDerivationMismatch`. Add a Go fuzz test for `Parse` that asserts it
never panics.

Acceptance: `make unit pkg=./walletdesc` passes and `go test -fuzz=FuzzParse
-fuzztime=60s ./walletdesc` finds nothing.


### Milestone 2: wallet backends accept a root key

Goal: `lwwallet` and `btcwallet` can create a wallet database from a root
extended key, with the same invariants that protect the seed path.

In `walletcore/config.go` add a field `RootKey *hdkeychain.ExtendedKey` next
to `Seed`, documented as an alternative creation input. Update
`checkWalletInvariants` in `lwwallet/wallet.go` and its btcwbackend twin so
that exactly zero or one of `Seed` and `RootKey` is set, `RootKey` must be a
private depth-zero key, and the existing "create input only when no database
exists" rule covers both. In both constructors, when `RootKey` is set, build
the loader with `btcwallet.NewWalletLoader(cfg.ChainParams,
cfg.RecoveryWindow, loaderOptions...)`, call
`CreateNewWalletExtendedKey(walletcore.PublicWalletPassphrase,
cfg.WalletPassword, cfg.RootKey, cfg.Birthday)`, and pass the result as
`Config.Wallet` to `btcwallet.New` instead of `HdSeed`; follow whatever
Milestone 0 found about loader handles in browser builds. Factor the shared
part into a helper in `walletcore` so the two backends cannot drift.

In `waved`, change `Server.startSelfManagedWallet`, `startLwwallet` and
`startBtcwallet` to take a small value type instead of a bare seed:

    // walletCreateInput is the material used to create a new wallet
    // database. The zero value opens an existing database.
    type walletCreateInput struct {
            seed     []byte
            rootKey  *hdkeychain.ExtendedKey
            birthday time.Time
    }

and update every caller (`InitWallet`, `UnlockWallet`, the environment-seed
path in `server.go`, and tests). In `waved/wallet_ops.go` add
`WalletIdentityPubKeyFromRootKey(root *hdkeychain.ExtendedKey, network
string) (string, error)` and reimplement `WalletIdentityPubKeyFromSeed` on top
of it, keeping its `DeriveNonStandard` walk unchanged.

Update `walletcore/CLAUDE.md`, `lwwallet/CLAUDE.md` and
`btcwbackend/CLAUDE.md` invariants to say "seed or root key".

Acceptance: the Milestone 0 equivalence test now goes through `lwwallet.New`
and the btcwbackend constructor; new unit tests prove that a root key plus an
existing database fails with `ErrWalletExists`, that setting both inputs
fails, and that a depth-one or public key is refused. `make unit
pkg=./lwwallet`, `pkg=./btcwbackend`, `pkg=./walletcore` and `pkg=./waved`
pass.


### Milestone 3: daemon RPC, CLI and swap-wallet admin

Goal: a user can create a wallet from descriptors through gRPC, REST and
`wavecli`.

In `waverpc/daemon.proto`, add to `InitWalletRequest`:

    // descriptors are private output descriptors that share one BIP32 master
    // key. Mutually exclusive with mnemonic. See docs/seed_restore_recovery.md.
    repeated string descriptors = <next free number>;
    // birthday_unix is the earliest time the descriptor keys may have been
    // used, in Unix seconds. Zero scans from genesis. Ignored for mnemonics,
    // which carry their own birthday.
    int64 birthday_unix = <next>;

and to `InitWalletResponse` a `repeated string descriptors` field carrying
the canonical public descriptors and a `string root_fingerprint` (eight hex
characters). Make the same additions to `CreateRequest` and `CreateResponse`
in `rpc/wavewalletrpc/wallet.proto`, and rewrite the `Create` comment so it no
longer implies a mnemonic is always involved. Run `make rpc` and commit the
generated code separately. Check that the REST gateway annotations and the
`wavecli` dev RPC registry (`cmd/wavecli/waveclicommands/devrpc`) regenerate
cleanly.

In `waved/wallet_ops.go` add the SDK-reusable entry point, mirroring
`WalletSeedFromMnemonic`:

    // WalletRootFromDescriptors validates descriptor text and the wallet
    // password and returns the root key and canonical descriptors.
    func WalletRootFromDescriptors(descriptors []string, network string,
            walletPassword []byte) (*walletdesc.WalletDescriptors, error)

In `RPCServer.InitWallet`, before claiming the state transition, reject a
request that sets both `mnemonic` and `descriptors` (`InvalidArgument`,
"mnemonic and descriptors are mutually exclusive") or `seed_passphrase`
together with `descriptors`. When `descriptors` is set, call
`WalletRootFromDescriptors`, `defer` its `Zero`, build a `walletCreateInput`
with the root key and `time.Unix(birthday_unix, 0)` (or the zero time), and
continue through the unchanged rollback, recovery and identity logic. Map
every `walletdesc` validation error to `InvalidArgument` with its message.
Populate the new response fields from `walletdesc.CanonicalPublic`.

In `swapwallet/admin.go`, the `Create` handler currently generates a seed
when `mnemonic` is empty. Change the branch so that a request with
`descriptors` skips `GenSeed`, forwards `descriptors` and `birthday_unix` to
`InitWallet`, returns an empty `mnemonic`, and copies the new response
fields. A request with neither keeps today's generate-a-mnemonic behaviour.

In `cmd/wavecli/waveclicommands/cmd_create.go` add `--descriptor-file`
(path to a file with one descriptor per line; blank lines and lines starting
with `#` are ignored; the file is read, never taken from argv, because argv
is visible to other local users) and `--birthday` (RFC3339 or `YYYY-MM-DD`,
reusing the same layouts as `seedBirthdayLayouts` in
`waved/seed_manager.go`). `--descriptor-file` is mutually exclusive with
`--mnemonic-file`, `--seed-passphrase-file` and `--print-mnemonic-json`.
`--recover` is allowed with it. Warn on stderr if the file is group- or
world-readable. Print the identity, fingerprint and public descriptors.

Optionally, for CI parity with `WAVED_LWWALLET_SEED`, add
`WAVED_LWWALLET_DESCRIPTORS` (newline-separated) and reuse
`WAVED_LWWALLET_SEED_BIRTHDAY`; setting both seed variables is a startup
error. Only do this if a system test needs it.

Acceptance: unit tests in `waved/rpc_wallet_test.go` for the happy path, each
mutual-exclusion error, each `walletdesc` error surfacing as
`InvalidArgument`, a failed start rolling the state back to `None`, and the
identity in the response equalling `WalletIdentityPubKeyFromRootKey`. A
`swapwallet` test for the forwarded branch. A CLI test for the flag
conflicts. Manually, against regtest as in `docs/daemon_cli_guide.md`:

    wavecli --no-tls --no-macaroons --network=regtest create \
      --descriptor-file wallet.descriptors --birthday 2026-01-01

prints `identity_pubkey`, `root_fingerprint` and two `descriptors`, and
`wavecli recv --onchain` then returns a `bcrt1p...` address that Bitcoin
Core's `deriveaddresses` reports as index 0 of the `tr` descriptor.


### Milestone 4: descriptor export and the round-trip test

Goal: any self-managed wallet, including every existing mnemonic wallet, can
show its descriptors, and the full round trip is proven end to end.

Add `rpc ListWalletDescriptors (ListWalletDescriptorsRequest) returns
(ListWalletDescriptorsResponse)` to `waverpc.DaemonService`, with request
fields `bool include_private` and `bytes wallet_password`, and response
fields `string root_fingerprint` and `repeated string descriptors`. It is
available only for self-managed wallets in state `Ready`. Public output comes
from the BIP86 and BIP84 account-0 `AccountProperties` (account xpub and the
fingerprint, as settled in Milestone 0). Private output requires
`include_private`, a `wallet_password` that btcwallet accepts (verify it with
the manager's unlock check, not a string compare), and the admin macaroon
permission used by `InitWallet`; it renders the root-key form unless the
path is affected by the legacy derivation difference, in which case it
renders the account-level private key with an origin, which every wallet
derives identically below the account. If Milestone 0 found no way to read
private keys, ship public export only and leave private export as a recorded
follow-up. Never log the response. Add the same RPC to `wavewalletrpc` only if
product wants it there; otherwise keep it on the admin surface.

Add `wavecli wallet descriptors [--private]`; `--private` reads the password
the same way `create` does and prints a one-line warning to stderr.

Write the round-trip system test under `systest/` (follow
`docs/testing-guide.md` for where and how) and, if the root-repository
integration harness is available, an `itest` mirroring
`TestBoardingIntegrationRecoveryCLIFromSeedRestoresBoardingFunds`: create
from mnemonic, fund a boarding address and board into a VTXO, export private
descriptors, stop the daemon, create a fresh daemon from the descriptors with
recovery, and assert equal identity, next address index, on-chain balance,
boarding UTXOs and VTXO outpoints. Add a second case that imports a
hand-built descriptor `tr(tprv.../86h/0h/0h/<0;1>/*)` (coin type `0'`, which
is what btcwallet uses on regtest), loads the same descriptor into a Bitcoin
Core descriptor wallet in the regtest harness so both sides agree, sends to
the first address from Core, and asserts Wavelength sees the funds.

Acceptance: both tests pass under `make systest` and `make systest
db=postgres`; the test fails if `walletcore` is reverted to ignore
`RootKey`.


### Milestone 5: Go embedding SDK and gomobile bridge

Goal: host applications embedding the daemon can open a wallet from
descriptors with the same guarantees as the external-seed path.

In `sdk/wavewalletdk/types.go` add `Descriptors []string` and `Birthday
time.Time` to `CreateWalletRequest` and `RootFingerprint string` and
`Descriptors []string` to `CreateWalletResult`; wire them through
`Client.CreateWallet` in `client.go`. Add `sdk/wavewalletdk/descriptor.go`
modelled on `external_seed.go`:

    type DescriptorWalletRequest struct {
            Descriptors            []string
            Birthday               time.Time
            ExpectedIdentityPubKey string
            RecoverState           bool
            RecoveryWindow         uint32
    }

    func StartDescriptorWallet(ctx context.Context, cfg Config,
            req DescriptorWalletRequest, opts ...Option) (*Client,
            *DescriptorWalletOpenResult, error)

plus a `WithContexts` variant. It validates with `walletdesc.Parse`, pins the
identity before starting the daemon using
`waved.WalletIdentityPubKeyFromRootKey`, derives the database password with
HKDF-SHA256 over the root private key bytes and chain code using the info
string `wavewalletdk:descriptor:dbpw:v1` (never the external-seed info string,
so the two schemes cannot collide), imports or unlocks, verifies the identity
again, and optionally runs recovery, exactly as the external-seed function
does. Refuse to run while `WAVED_LWWALLET_SEED` or `WAVED_WALLET_PASSWORD` is
set, as the external-seed path does. Add `ListWalletDescriptors` to `Client`.

In `sdk/wavewalletdk/mobile` add `StartDescriptorWallet(reqJSON []byte)
([]byte, error)` and `ListWalletDescriptors(reqJSON []byte) ([]byte, error)`
next to their siblings, using the same JSON conventions, and extend the JSON
of `CreateWallet`. Mirror the creation option in `sdk/ark` (`client.go`) if it
exposes wallet creation to hosts. Update `docs/wavewalletdk_integration.md`
and `docs/wavewalletdk_mobile.md`.

Acceptance: tests mirroring `external_seed_test.go` and
`external_seed_compat_test.go` (import, reopen unlocks rather than
re-imports, wrong identity pin fails before any directory is created,
environment variables are refused, recovery counters populate), and a mobile
JSON round-trip test. `make unit pkg=./sdk/wavewalletdk/...` passes.


### Milestone 6: downstream packages

Goal: the TypeScript SDK, the native mobile kits and the WDK module expose
descriptor creation and export. Every downstream consumer reaches Go through
exactly one surface, the `sdk/wavewalletdk/mobile` facade, compiled three
ways: gomobile (`Wavewalletdk.aar` and `Wavewalletdk.xcframework`, published
with Wavelength releases), WebAssembly (`cmd/wavewalletdk-wasm`, exposing a
global `wavewalletdkCall(method, json)`), and the iOS Bare native addon,
which links the xcframework. No downstream code calls the `wavewalletrpc`
gRPC service; it appears only in generated docs. So Milestone 6 is mostly
"teach each transport two new facade verbs (`startDescriptorWallet`,
`listWalletDescriptors`) and the extra `createWallet` fields", then expose
them in each package's typed API. Each repository gets its own branch and
pull request after a Wavelength release that contains Milestone 5. The
exact files are listed in `Artifacts and Notes`.

Milestone 6a, `wavelength-sdk` (TypeScript monorepo). Regenerate the Go-derived
types with `pnpm gen:types` and the proto docs with `pnpm gen:api-docs`. In
`packages/core`, add `descriptors?: string[]` and `birthday?` to
`CreateWalletRequest`, add a `DescriptorWalletRequest` with a validator that
throws a new error code `invalid_descriptor`, add `startDescriptorWallet` to
`ExternalSeedWalletClient` (or a sibling `DescriptorWalletClient`; record the
choice), add `listWalletDescriptors` to `WavelengthClient`, register both in
`FACADE_METHODS`, map them in `facade.ts` and `response-normalization.ts`,
block `startDescriptorWallet` in `callFacade` the way `start` and
`startExternalSeedWallet` are blocked, and extend the
`public-api-assertions.ts` pins. Let `WalletEngine.restoreWallet` accept
descriptors instead of rejecting with "a restore needs a mnemonic". Add
`'descriptor'` to `WalletKind`. The redaction lists `SECRET_FIELDS` in
`packages/web/src/util.ts` and its hand-copied twin in
`wavewalletdk-worker.js` must gain `descriptors` (a private descriptor is
seed-equivalent); add a case to `debug-redaction.test.ts`. Take the per-profile
Web Lock for `startDescriptorWallet` exactly as for
`startExternalSeedWallet`. In `packages/react-native`, add both verbs to the
Android `when(method)` table in `WavelengthModule.kt`, the iOS table in
`WavelengthModule.mm`, and the regex pins in `native-dispatch.test.ts`. In
`packages/react`, let `useWalletRestore` take descriptors. Add a "Descriptor"
tab to the two demo apps' restore screens and a "Show descriptors" item to
their settings screens. Update the docs and skills listed below.

Milestone 6b, `wavelength-mobile` (native WalletKit for Android and iOS). This
repository only exposes `createWallet(walletPassword, mnemonic)` and
`unlockWallet`. Add a `descriptors` parameter (Kotlin
`List<String> = emptyList()`, Swift `[String] = []`) to `createWallet` with the
`@SerialName("Descriptors")` / coding-key mapping, add
`listWalletDescriptors(walletPassword?, includePrivate)`, extend the result
models with `rootFingerprint` and `descriptors`, and update
`docs/api-guide.md`. The repository has no secure-storage code and tells hosts
to save the mnemonic themselves; the guide must say the same about private
descriptors and recommend the Android Keystore and iOS Keychain.

Milestone 6c, `wavelength-wdk` (optional, decide with product). The WDK
module's model is "one BIP39 seed, many accounts": `WalletManagerWavelength`
derives per-account aezeed entropy with BIP85 and calls
`startExternalSeedWallet`. A descriptor set is one fixed root key, so it maps
to exactly one account. If wanted, accept a `{ descriptors }` configuration
object in the manager constructor that yields account 0 only (other indexes
and `getAccountByPath` throw a clear "descriptor wallets have one account"
error), route it to `startDescriptorWallet`, add the verbs to the Bare addon's
`binding.mm` method table and export list and to `index.d.ts`, add
`startDescriptorWallet` to `START_METHODS` in `facade-retry.js`, and extend
the transport tests. If not wanted, record that in the `Decision Log` and skip
6c.

Acceptance for each repository: its own unit test suite passes with new
tests for the added verbs, the demo or sample app can restore a regtest
wallet from a Bitcoin Core descriptor and show the same identity public key
that `wavecli create --descriptor-file` reports for the same file, and the
debug log of the web demo shows the descriptor field redacted.


### Milestone 7: documentation, hygiene and release notes

Extend `docs/seed_restore_recovery.md` with a "Restore from descriptors"
section (supported forms, the legacy-derivation refusal, birthday advice, the
same "never run two daemons with the same key" warning, since the root key
determines the identity and mailbox), and `docs/daemon_cli_guide.md` with the
new flags and command. Add an `ast-grep` rule or a unit test that fails if a
`walletdesc.WalletDescriptors` or a descriptor string field is passed to a
logger. Audit every new handler for `zeroBytes`/`Zero` on all paths. Add a
release-notes entry describing the feature and its explicit limits (no
watch-only, no account-level import, purposes 84 and 86 only).


## Concrete Steps

All commands run from the root of this repository unless stated.

    make unit pkg=./walletcore case=TestRootKeyWalletMatchesSeedWallet
    make unit pkg=./walletdesc
    go test -fuzz=FuzzParse -fuzztime=60s ./walletdesc
    make rpc
    make build
    make unit pkg=./waved
    make unit pkg=./swapwallet
    make unit pkg=./sdk/wavewalletdk/...
    make systest
    make systest db=postgres
    make fmt-changed && make lint-changed-local
    make commitmsg-lint range="origin/main..HEAD"

Building a descriptor for manual regtest testing. Bitcoin Core's own regtest
descriptors use coin type `1'` and are refused (see the Decision Log), so
take only the root key from Core and build the path btcwallet uses:

    bitcoin-cli -regtest createwallet descsrc
    ROOT=$(bitcoin-cli -regtest -rpcwallet=descsrc listdescriptors true \
      | jq -r '.descriptors[] | select(.desc | startswith("tr(")) | .desc' \
      | head -1 | sed -E 's/^tr\(([^/]+)\/.*/\1/')
    for BRANCH in 0 1; do
      D="tr($ROOT/86h/0h/0h/$BRANCH/*)"
      SUM=$(bitcoin-cli -regtest getdescriptorinfo "$D" | jq -r .checksum)
      echo "$D#$SUM"
    done > wallet.descriptors

Use the `checksum` field, not the `descriptor` field, of
`getdescriptorinfo`: the latter is returned without private keys and would be
refused as watch-only.

The root key in Core's output is the master key, so this is the same wallet
seen through btcwallet's paths. Importing `$DESC` back into the Core wallet
with `importdescriptors` lets Core pay to and recognise the same addresses.
On mainnet, Core's own `86h/0h/0h` descriptors are accepted unchanged. Update
this section with real transcripts as milestones land.


## Validation and Acceptance

The feature is accepted when all of the following are observed. A fresh
regtest daemon created with `wavecli create --descriptor-file` reports the
same identity public key that `WalletIdentityPubKeyFromRootKey` computes
offline. Its first on-chain address equals Bitcoin Core's
`deriveaddresses "<tr descriptor>" "[0,0]"` for a root key not affected by
the legacy derivation difference. A descriptor set containing an xpub, an
account-level xprv, mixed roots, a mainnet key on regtest, a purpose-49
path, a coin type of `1'`, or an account other than 0 is refused with `InvalidArgument` and a
message naming the reason, and no wallet database is created (the daemon
remains in state `None`). The Milestone 4 round-trip systest passes on SQLite
and PostgreSQL. Existing mnemonic and external-seed tests pass unchanged,
which shows the change is additive.


## Idempotence and Recovery

Creation is guarded by the existing `walletState` compare-and-swap and by the
"create input only when no database exists" invariant, so retrying a failed
descriptor import is safe: if the database was not created the state returns
to `None`; if it was, the state becomes `Locked` and the retry path is
`UnlockWallet`, exactly as for mnemonics. Recovery is idempotent as documented
in `docs/seed_restore_recovery.md`. No database migration is introduced. To
abandon a half-built manual test wallet, stop the daemon and delete only that
test data directory.


## Artifacts and Notes

Downstream file map for Milestone 6, from a read-only survey on 2026-11-02.
Paths are relative to each repository root. Line numbers drift, so search
for the named symbol.

In `wavelength-sdk`: `packages/core/src/requests.ts` (`CreateWalletRequest`,
`ExternalSeedWalletRequest`, `validateExternalSeedWalletRequest`,
`RestoreWalletRequest`); `generated.ts` (tygo output from
`sdk/wavewalletdk`, regenerated by `scripts/gen-types.mts`); `results.ts`;
`client.ts` (`WavelengthClient`, `ExternalSeedWalletClient`); `facade.ts`
(`FACADE_METHODS`, `toGoCreateWalletReq`); `base-client.ts` (`callFacade`
lifecycle-verb guard); `response-normalization.ts`; `errors.ts`; `passkey.ts`
(`WalletKind`); `engine/engine.ts` (`restoreWallet`); `public-api-assertions.ts`;
`index.ts`. `packages/react/src/hooks.ts` (`useWalletCreate`,
`useWalletRestore`). `packages/web/src/util.ts` and `wavewalletdk-worker.js`
(`SECRET_FIELDS`), `clients/worker.ts` and `clients/main.ts` with
`runtime-lock.ts` (per-profile Web Lock). `packages/react-native/android/.../WavelengthModule.kt`
and `ios/WavelengthModule.mm` (method tables), `src/native-dispatch.test.ts`.
Demo apps `apps/web-wallet-demo` and `apps/rn-wallet-demo`
(`RestoreWalletScreen.tsx`, `OnboardingFlow.tsx`, `SettingsScreen.tsx`,
`WalletTypePicker.tsx`, `walletRegistry.ts`). Docs under
`apps/docs/src/content/docs`: `concepts/keys-backup-and-recovery.mdx`,
`guides/restore-a-wallet.mdx`, `guides/create-a-wallet.mdx`,
`reference/wavelength-core.mdx`, `reference/wavelength-react-native.mdx`,
`cli/create.mdx`, `glossary.mdx`; also `docs/key-management.md` and the
`apps/docs/src/data/api/wallet.json` generated from `wallet.proto`. Skills:
`skills/wavelength-web`, `skills/wavelength-react-native`,
`skills/wavelength-api`, `skills/wavelength-cli`, and
`.claude/skills/syncing-daemon-release`.

In `wavelength-mobile`: `android/walletkit/.../client/WalletClient.kt` and
`Models.kt`; `ios/WalletKit/Sources/WalletKit/WalletClient.swift`,
`Models.swift` and `Bindings.swift` (including its stubs); samples
`WalletDemoScreen.kt` and `ContentView.swift`; `docs/api-guide.md`,
`README.md`, `ios/README.md`.

In `wavelength-wdk`: `wdk-wallet-wavelength/src/wallet-manager-wavelength.js`
(constructor rejects anything but a BIP39 phrase or seed today),
`src/external-seed-account.js` (BIP85 account derivation),
`src/facade-retry.js` (`START_METHODS`), the three `#transport`
implementations, `types/src/*.d.ts`, the tests under `tests/`, and
`wavelength-bare-addon/binding.mm` and `index.d.ts`. Note for reviewers: the
`example/wdk-mobile` app stores its seed phrase in a plaintext JSON file by
design ("demo only"); do not copy that pattern for descriptors.

`wavelength-lab` has no source, only a dependency on the published web and
React packages; nothing to change.


## Interfaces and Dependencies

No new third-party dependency. Use `github.com/btcsuite/btcd/btcutil/v2/hdkeychain`
(or the `btcutil` version already used by `walletcore`; match it) for
extended keys, `chaincfg` for network version bytes, btcwallet's
`wallet.Loader.CreateNewWalletExtendedKey`, and lnd's
`lnwallet/btcwallet.Config.Wallet`. If Milestone 0 requires an upstream
btcwallet accessor for private export, add it via a `replace` directive in
`go.mod` per `CLAUDE.md` and record the upstream pull request in the
`Decision Log`.

At the end of the work these exist: package `walletdesc` with `Parse`,
`WalletDescriptors`, `Descriptor`, `CanonicalPublic` and the exported errors
named in Milestone 1; `walletcore.Config.RootKey`;
`waved.WalletRootFromDescriptors` and `waved.WalletIdentityPubKeyFromRootKey`;
the proto fields and the `ListWalletDescriptors` RPC named in Milestones 3 and
4; `wavewalletdk.StartDescriptorWallet`, `DescriptorWalletRequest`,
`DescriptorWalletOpenResult` and `Client.ListWalletDescriptors`; and mobile
`StartDescriptorWallet` and `ListWalletDescriptors`.

The extension milestones W2 to W6 add the following proposed names, all
illustrated under "Sample usage (proposed API)". They are proposals, so
change them freely before implementation and record the change here.

- `lib/keyfamily`: the family registry, with a `Class` of `Funds` or
  `Auth` per family.
- `walletdesc.ParseManifest(data []byte, params *chaincfg.Params)
  (*Manifest, error)`, with `Manifest.Hash() string` and the errors
  `ErrAuthFamilyOverride`, `ErrDuplicateKey`, `ErrScriptDescriptorSlot`,
  `ErrIdentityOverride`, `ErrMissingFamily`, `ErrMixedNetworks` and
  `ErrBadKeyExpressionChecksum`.
- `walletcore.splitKeyRing`: the derive and sign guard and router.
- `InitWalletRequest` fields `watch_only_manifest` (bytes), `auth_keys`
  (bytes) and `override_identity` (bool), alongside Milestone 3's
  `birthday_unix`; `InitWalletResponse` fields `manifest_hash` and a
  repeated `signer_probes` of slot and result. The same additions go on
  `wavewalletrpc.CreateRequest` and `CreateResponse` if the flat facade
  should expose watch-only creation.
- `waved` configuration `wallet.remotesigner.rpchost`, `.tlscertpath`,
  `.macaroonpath`, `.requesttimeout` and `.inbound`; signer mode
  `--mode=signer` with `signer.keysfile` and `signer.listenaddr`.
- CLI: `wavecli create --watch-only-manifest --auth-keys-file
  [--override-identity]`; `wavecli wallet export-watchonly [--minimal]
  [--primary NAME] [--slot SLOT=SOURCE[:PATH]] --manifest-out
  --auth-keys-out`; `wavecli wallet descriptors --ark [--kind ...]`.
- `waverpc.DaemonService.ListArkOutputDescriptors`.
- `wavewalletdk.StartWatchOnlyWallet`, `WatchOnlyWalletRequest`,
  `RemoteSignerConfig` and a result carrying `IdentityPubKey` and
  `ManifestHash`. These are native-only, as described in W2.


## Extension: watch-only, account-level and overridden keys (milestones W0 to W6)

This section designs the follow-on that lets a self-managed wallet be
defined by public keys only (with signing done elsewhere) or by
account-level private keys. It starts after Milestone 2.

What "watch-only" can and cannot mean for Ark. Every key Wavelength uses is
`m/1017'/coin'/family'/0/index`. The `family'` step is hardened, so a single
xpub at `m/1017'/coin'` cannot produce them, but an xpub at the account level
`m/1017'/coin'/family'` can, because the remaining `/0/index` steps are not
hardened. One such xpub per family is exactly what lnd exports from a remote
signer and imports into a watch-only node. In descriptor notation each is a
key expression like `[d34db33f/1017h/0h/44h]xpub.../0/*`; there is no
standard script function for them because they are keys used inside Ark
policies, not output scripts in their own right, so the import format is a
key bundle rather than a list of output descriptors. Public keys are enough
to compute the identity, mailbox ID, boarding and receive scripts and to
track on-chain funds. They are not enough to operate: joining a round,
signing forfeits, sending out of round, refreshing VTXOs before they expire,
authenticating to the mailbox and indexer, and even sweeping a unilateral
exit all need a signature, often within a round deadline. So a watch-only
Wavelength wallet must be paired with an online, unattended signer that
supports taproot signing, tagged Schnorr messages, ECDH and MuSig2 sessions.
lnd in signer mode qualifies. Hardware wallets do not (no unattended MuSig2
or arbitrary ECDH), and neither does a phone's secure enclave (no secp256k1).
A cold, signer-less "monitor" mode is possible for on-chain balance only and
is not proposed, because its Ark funds would expire.

Milestone W0 (no code, about a week): prove and document the path that
already exists. Write a system test that runs `waved` with `wallet.type=lnd`
against a watch-only lnd paired with an lnd remote signer, boards, completes a
round, sends out of round, and exits; measure the added signing latency per
round against `docs/round_admission_deadlines.md`; and document the setup in
`docs/daemon_cli_guide.md`. This de-risks every later milestone because it
exercises `rpcwallet.RPCKeyRing` under real Ark traffic.

Milestone W1: remove the two private-key assumptions. Change
`indexer.KeyRingSchnorrSigner` to sign through
`keychain.MessageSignerRing.SignMessageSchnorr` with the proof tag and
message, the way `indexer.LNDSchnorrSigner` and
`Server.signTaggedSchnorrViaKeyRing` already do, and prove with a test that
the signature verifies under the same digest
(`chainhash.TaggedHash(proofTag(), message)` in `indexer/client.go`). Route
the concrete `BtcWallet.FundPsbt` and `FinalizePsbt` calls in
`waved/server.go` and `lwwallet/wallet.go` through an
`lnwallet.WalletController` field on `walletcore.Wallet`, so a remote key
ring can stand in. These are safe refactors with no behaviour change for seed
wallets.

Milestone W2: native watch-only self-managed backend with a remote signer.
After W2, `wallet.type=lwwallet` (or `btcwallet`) runs from public keys
only; no lnd node is involved on the daemon side.

The input is a watch-only key bundle. Its on-chain part is ordinary output
descriptors: `tr([fp/86h/0h/0h]xpub.../<0;1>/*)` (coin type `0'` on every
network) and optionally the
matching `wpkh` for purpose 84. Its Ark part is one xpub per key family at
`m/1017'/coin'/family'`. btcwallet must end up with an account for every
family from 1 to 255, not just the ones Wavelength uses. The reason is in
lnd, not Wavelength: `lnwallet/btcwallet.BtcWallet.Start` always calls
`wallet.InitAccounts(scope, ..., 255)` on the `1017'` scope, which loops over
accounts 1 to 255 and calls `NewRawAccount` for any that is missing; that
fails on a watch-only wallet because it needs the master private key. lnd's
own watch-only nodes satisfy this by importing every account their signer
lists. Wavelength supports that "full bundle" and also a "minimal bundle"
that carries only the families it uses, with placeholders for the rest; see
"Split signing" below. On the on-chain side only the `86'` account is
needed: on a watch-only wallet, `waddrmgr.Manager.NewScopedKeyManager` can
create the `49'` and `84'` scopes empty, which is all `Start` asks for. There is no standard output-descriptor form for a key that is only
used inside Ark policies, so `walletdesc` accepts the family keys in two
shapes: lnd's watch-only account JSON (what `lncli wallet accounts list`
prints on an lnd signer and what `lncli createwatchonly` consumes), and a
plain list of ranged key expressions such as
`[fp/1017h/1h/44h]tpub.../0/*#q7m2x9kd`, one per line. A family entry is a
BIP380 key expression (the part of a descriptor that goes inside a script
function) with the mandatory suffix `/0/*`, because that is the derivation
the key ring actually performs, and an optional BIP380 checksum computed over
the entry text to catch copy errors. `walletdesc` verifies the checksum when
present and always writes one. The checksum on a bare key expression is a
Wavelength convention: the BIP380 algorithm accepts any string, but other
tools only check it on full descriptors. Any suffix other than `/0/*` is
refused. Why family entries are key expressions and not output descriptors
is explained under Milestone W6. Validation requires one master fingerprint across the bundle (W5
relaxes this for fund slots), the
daemon's network and coin type, and the exact purpose, coin and account path
of each key. A full bundle must have no gaps in families 1 to 255; a minimal
bundle must contain exactly the required families listed under "Split
signing". Bundles are generated by the
signer, never typed by hand; Milestone W4 adds the Wavelength command that
writes one.

In `walletcore`, add a watch-only creation path that mirrors lnd's
`importWatchOnlyAccounts` (`config_builder.go`):
`Loader.CreateNewWatchingOnlyWallet(pubPass, birthday)`, then
`ImportAccountWithScope(name, xpub, masterFingerprint, scope, addrSchema)`
for every account sorted by purpose and index, naming index 0 `default`.
Pass the result as `btcwallet.Config.Wallet` with `WatchOnly: true`, build
`keychain.NewBtcWalletKeyRing` over it, and wrap both in
`rpcwallet.NewRPCKeyRing(watchOnlyKeyRing, watchOnlyBtcWallet,
remoteSignerConn, params)`. Then set `walletcore.Wallet.Signer` and
`walletcore.Wallet.KeyRing` to the RPC key ring and keep
`walletcore.Wallet.BtcWallet` for chain tracking. `round.ClientWallet` is
just `input.Signer` plus `DeriveNextKey`, and lnd's RPC key ring implements
`input.Signer` including every MuSig2 call, so the round code does not
change. After W1, the only signing that went around those fields (the
`FinalizePsbt` calls in `waved/server.go` and `lwwallet/wallet.go`, and the
indexer proof signer) goes through them too.

A watch-only btcwallet has no private passphrase, so the user's wallet
password becomes btcwallet's public passphrase for watch-only wallets
(instead of the static `walletcore.PublicWalletPassphrase`). That keeps
`InitWallet` and `UnlockWallet` meaning the same thing to callers and keeps
the addresses and xpubs encrypted at rest. Persist a small marker (the
wallet kind and master fingerprint) so `UnlockWallet` knows which open path
to take; btcwallet's own `AddrManager().WatchOnly()` is the authority and the
marker is only a cross-check.

Add `wallet.remotesigner.*` configuration: signer address, TLS certificate,
macaroon, connection and per-request timeouts, and inbound or outbound
connection mode. Reuse lnd's `rpcwallet` connection builders rather than
writing a new client; the per-request timeout should default to something
derived from round deadlines rather than lnd's 5 seconds, once W0 has
measured real latency. The signer must serve exactly the requests
`rpcwallet.RemoteSignerRequests` makes: `signrpc` `DeriveSharedKey`,
`SignMessage` and the seven `MuSig2*` calls (`CreateSession`,
`RegisterNonces`, `RegisterCombinedNonce`, `GetCombinedNonce`, `Sign`,
`CombineSig`, `Cleanup`), plus `walletrpc` `SignPsbt`, which is how
`SignOutputRaw` and `ComputeInputScript` reach it. On every unlock, ask the
signer to sign a fresh challenge with the family-6 index-0 key and refuse to
start unless it verifies against the identity derived from the imported
xpub, so a daemon can never run against the wrong signer. Ark-state recovery
works unchanged because it derives through the key ring, but it needs the
signer online, since indexer queries carry proof signatures.

Split signing. The goal is that the remote signer holds every key that can
move funds while `waved` keeps only keys whose theft cannot. The families
fall into two classes:

- Fund keys (remote): the `m/86'/0'/0'` on-chain account and families 6
  (identity, which is also the swap vHTLC key), 42 (boarding), 44 (VTXO
  owner, which also signs forfeits and exit sweeps), 45 (VTXO tree MuSig2)
  and 202 (out-of-round receive).
- Authentication keys (local): families 43 (round-join authentication) and
  21 (receive-auth base). Neither appears in any output script or spends
  anything. Both are still required to operate: without 43 the wallet cannot
  join rounds, so it cannot board or refresh, and its VTXOs drift towards
  expiry and forced exits; without 21 Lightning receives and swaps fail.

Introduce a single key-family registry, a new package `lib/keyfamily`, that
declares every family Wavelength derives, each with its class (`Funds` or
`Auth`), and move the existing constants there (`identityKeyFamily`,
`wallet.BoardingKeyFamily`, `joinRoundAuthIdentifierKeyFamily`,
`types.VTXOOwnerKeyFamily`, `types.VTXOSigningKeyFamily`,
`oorReceiveKeyFamily`, and a named constant for `lndclient.SharedKeyLocator`'s
family 21), leaving aliases where moving would create import cycles. Add an
`ast-grep` rule (see `docs/ast-grep-guide.md`) that rejects a
`keychain.KeyFamily(...)` literal or a new `keychain.KeyFamily` constant
outside the registry, and a unit test that pins the registry contents, so a
future family cannot be added without being classified and without failing
review.

In a minimal bundle, the fund families arrive as xpubs and the
authentication families arrive as account-level xprvs from the same root
(`[fp/1017h/coin'h/43h]xprv...`, `[fp/1017h/coin'h/21h]xprv...`). They must
come from the same root, not be generated locally: family 21 drives
per-payment receive-auth keys, so a restore from the seed has to reproduce it.
The W4 export command writes this form with `--minimal`. The local xprvs are
encrypted under the wallet password in the same keystore W3 introduces, so W3's
storage piece is a prerequisite for minimal bundles. Full bundles from an lnd
signer remain supported; in that mode every family is remote, including 43
and 21.

For every family from 1 to 255 that a minimal bundle does not supply, `waved`
imports a placeholder xpub so `InitAccounts` finds the account. Placeholders
are derived from a random key generated at import and discarded immediately,
so no private key exists for them anywhere. That makes them dangerous if ever
used, so add a guard. Wrap the key ring in a `splitKeyRing` type (in
`walletcore`) that implements `keychain.SecretKeyRing`, `input.Signer` and
`keychain.MessageSignerRing`, and that:

- refuses `DeriveKey`, `DeriveNextKey` and every signing call for a family
  that is not in the registry or not supplied by the bundle, so funds can
  never be locked to a placeholder key;
- routes calls for `Auth` families to an in-process signer over the local
  xprvs (W3's signer code) and everything else to `rpcwallet.RPCKeyRing`,
  dispatching on the `KeyLocator` family of the key descriptor, or on the
  derivation path for `SignPsbt` inputs;
- checks families read back from the database (vHTLC `SignerKeyFamily`,
  taproot-asset owner families) against the same rule before use.

Record the bundle mode and the supplied family set in the wallet marker so
the guard survives restarts, and refuse to start if the registry gains a
`Funds` family the stored bundle does not cover, with a message telling the
user to export a new bundle from their signer. Never fall back to a
placeholder.

What split signing protects and what it does not, stated plainly in the docs.
It keeps every fund key off the `waved` host at rest: someone who copies the
data directory and the wallet password gets the authentication keys and all
xpubs, so they can impersonate the wallet to the operator and see its
balances, but they cannot sign a spend. It does not stop an attacker who
controls the running `waved` process from asking the signer to sign a theft,
because an lnd remote signer signs whatever valid request it receives.
Closing that gap needs signer-side policy (for example, the W4 signer
accepting only spends to the wallet's own scripts or to an operator-approved
round), which is recorded as future work.

The `rpcwallet` package dials gRPC over TCP, which the browser build cannot
do, so W2 is compiled out of `js && wasm` builds with a build tag and the
SDK and mobile bridges expose it only on native targets. Phones and browsers
use W3 instead, where the keys sit in the same process.

Acceptance is the W0 system test passing with `wallet.type=lwwallet` and no
lnd on the watch-only side (the signer may still be lnd until W4), run once
with a full bundle and once with a minimal bundle. In the minimal run, a
recording signer must show no request for families 21 or 43 and requests for
every fund family the scenario touches. Unit tests must cover:

- bundle validation (missing family, mixed fingerprints, wrong coin type);
- the wrong-signer refusal;
- restart with the wallet locked;
- `splitKeyRing` refusing to derive or sign for a placeholder family and for
  a family missing from the registry;
- the startup refusal when the registry has a `Funds` family the stored
  bundle lacks;
- the registry pin test failing when a new family constant is added outside
  it.

Milestone W3: account-level private keys. An account-level `xprv` for
`86'` or `84'` alone can sign on-chain spends but cannot produce any
`1017'` family key, so it cannot run Ark. Two inputs are therefore accepted:
the on-chain account xprvs together with the family-level xprvs
`[fp/1017h/coin'h/family'h]xprv...`, or the coin-level `[fp/1017h/coin'h]xprv`
from which every family can be derived. Deriving Ark keys from the on-chain
account key under some Wavelength-defined subpath was considered and
rejected: no other software would reproduce those keys from the mnemonic, so
recovery would depend on Wavelength forever. Build W3 on W2's watch-only
database by computing the xpubs from the supplied xprvs, and add an in-process
signer package (for example `accountsigner`) that implements
`keychain.SecretKeyRing`, `input.Signer` and `keychain.MessageSignerRing` over
those keys, reusing `input.NewMusigSessionManager(fetchPrivKey)` for MuSig2
and following lnd's `lnwallet/btcwallet/signer.go` for `SignOutputRaw` and
`ComputeInputScript`. btcwallet cannot store account-level private keys, so
encrypt them at rest under the wallet password with btcwallet's `snacl`
scheme in a separate bucket of the wallet database, and decrypt them in
`UnlockWallet`. The legacy-derivation caveat applies only to hardened steps
above the supplied key, so account-level keys are immune to it, which makes
W3 the safer import path for keys exported from other software.

Milestone W4: a Wavelength signer, so no lnd is needed anywhere. W2 still
needs something to sign, and until now that is an lnd node in signer mode.
Add a `signer` mode to `waved` (or a small `wavesigner` binary built from the
same packages) that holds private keys through the Milestone 2 root-key path
or the W3 account-key path, runs no chain backend, no Ark actors and no
mailbox, and serves only the ten requests listed in W2 over gRPC with TLS
and a dedicated macaroon. The handlers map directly onto what
`walletcore.Wallet` already implements: `DeriveSharedKey` to `KeyRing.ECDH`,
`SignMessage` to the key ring's message signers, the `MuSig2*` calls to
`input.Signer`, and `SignPsbt` to lnd's `btcwallet.SignPsbt`. The signer
must check every requested derivation path against its own key scopes and
refuse paths outside `m/86'`, `m/84'` and `m/1017'`. Add `wavecli wallet
export-watchonly`, run against the signer (or any full-key daemon), which
writes the W2 key bundle: by default the public on-chain descriptors from
Milestone 4 plus xpubs for families 1 to 255 (a full bundle); with
`--minimal`, the `86'` account and the registry's `Funds` families as xpubs
plus its `Auth` families as account-level xprvs (a minimal bundle, for split
signing). `--minimal` prints a warning that the output contains private keys
and refuses to write to a group- or world-readable path. The deployment then
becomes: the signer holds the
private descriptor and is reachable only from the watch-only daemon; the
watch-only daemon holds the bundle, the chain backend and all Ark state.
Acceptance is the W0 system test passing with two `waved` processes and no
lnd at all.

Milestone W5: per-family key overrides. After W5, a user can say "take the
VTXO owner keys from this key, the boarding keys from that one, and the
on-chain account from a third", instead of deriving every fund family from
one master key. It builds on W2's bundle and `splitKeyRing`, W3's keystore
and in-process signer, and W4's signer.

Why it is possible. `waved` never derives a hardened step itself. For each
family it holds one account xpub in btcwallet's `m/1017'/coin'/family'` slot
and derives `/0/index` children from it. For the on-chain wallet it does the
same with the `86'` account's `/0/*` and `/1/*` children. btcwallet's
`ImportAccountWithScope(name, accountPubKey, masterKeyFingerprint, scope,
schema)` takes a fingerprint per account, so nothing in the watch-only
wallet requires the accounts to share a root. The slot is a logical address;
the key placed in it can come from anywhere.

What an override is. A bundle line that assigns one fund slot to a key
source: `family 44 = [b2c3d4e5/9000h/7h]xpub.../0/*#q7m2x9kd` or
`onchain = tr([e5f6a7b8/86h/0h/3h]xpub.../<0;1>/*)#k3l9x2qp`. Family entries
use the ranged key-expression form defined in W2. Rules, enforced in
`walletdesc` and each with its own error:

- Only `Funds` slots in the `lib/keyfamily` registry (families 6, 42, 44, 45,
  202) and the on-chain account may be overridden. `Auth` families 21 and 43
  always come from the primary root as in W2. Overriding them would add
  nothing, since they are held locally and cannot move funds, and family 21
  must stay restorable from the primary seed.
- Each override is a single extended public key whose children are
  non-hardened `/0/*` (and `/1/*` for the on-chain account). Script
  descriptors such as `multi(...)`, `sortedmulti(...)` or a `tr` with a script
  tree are refused: Ark policies put exactly one user key beside the
  operator key, and VTXO tree signing assumes one user cosigner, so a
  multisig slot would need Ark protocol changes.
- The origin can be any path from any root, because `waved` derives nothing
  hardened. The legacy-derivation caveat does not apply on the `waved` side.
- No two slots may hold the same key or keys from the same account path of
  the same root. Two families deriving identical keys would make a VTXO owner
  key equal a receive or boarding key, and recovery could not attribute what
  it finds.
- Overriding family 6 changes the wallet identity, mailbox ID and the key in
  every swap vHTLC, so the operator sees a different wallet. It is allowed
  only on a fresh wallet with an explicit `--override-identity` flag, and
  never on an existing database, where it would orphan the mailbox and any
  in-flight swaps.

The bundle stops being "one root plus placeholders" and becomes a manifest:
a JSON document with a version, the network, the primary fingerprint, the
on-chain account as an output descriptor, and each fund family as a ranged
key expression carrying its source fingerprint and origin path. The format
is shown under "Sample usage" at the end of this extension. The manifest
hash is SHA-256 over its canonical encoding: keys sorted, no insignificant
whitespace, checksums included. `waved` stores the manifest (public data only) beside the wallet
marker, prints a manifest hash in `GetInfo` and on creation, and refuses to
unlock if the btcwallet accounts no longer match it.

The signer has to route by slot. `rpcwallet.RPCKeyRing` always names keys
logically, never by real origin: `SignMessage`, `SignMessageSchnorr`,
`DeriveSharedKey` and `MuSig2CreateSession` send a `KeyLocator` (family and
index), and `SignPsbt` inputs carry either the account's stored fingerprint
with the logical path, or, for outputs the wallet does not track, the logical
path `m/1017'/coin'/family'/0/index` with no reliable fingerprint
(`rpcwallet.go`, around the `Bip32Derivation` construction). An lnd remote
signer derives every locator from its own single root, so it cannot serve an
override bundle. The W4 signer gains a routing table, loaded from the same
manifest plus the private material for each source: slot to (key source,
real origin path). It translates each logical request to the real key,
derives the private key, checks that the resulting public key equals the
public key in the request whenever the request carries one, and refuses
anything outside the table. W3's in-process signer gets the same table, so a
wallet with local account-level xprvs can use overrides without any remote
signer.

Detecting the wrong signer. W2's identity challenge only proves family 6.
With overrides, on every unlock `waved` probes every fund slot. For each
family it asks the signer for a `SignMessageSchnorr` over a fresh challenge
with the index-0 key. For the on-chain account it asks for a `SignPsbt` over
a non-broadcastable transaction spending a fabricated outpoint locked to the
account's `/0/0` key. Each signature is verified against the manifest xpub,
and `waved` refuses to start on any mismatch. This is also what makes an lnd
signer fail safely: it would sign with its own root's keys and fail the
probe for every overridden slot.

Backup and recovery change, and the documentation must say so prominently.
The primary mnemonic or root descriptor is no longer enough. A restore needs
every key source named in the manifest plus the manifest itself, which
records which source fills which slot and cannot be inferred from the keys.
The W4 export command writes the manifest, and its output and `GetInfo` show
the manifest hash so a user can check a backup. Ark-state recovery itself is
unchanged: it scans families 42, 44 and 202 through the key ring, and the key
ring follows the manifest. A restore attempted with the primary seed alone
must fail loudly rather than come up with an empty wallet: when the manifest
has overrides, `--recover` requires the manifest, and the identity probe
fails if family 6 was overridden.

What W5 does not enable. A hardware wallet still cannot be the source for
any fund slot, because the signer must answer unattended: family 45 needs
interactive MuSig2 within round deadlines, family 44 signs forfeits and exit
sweeps during rounds, and the on-chain account pays exit fee bumps
automatically. Overrides change where keys come from, not the need for an
online signer.

Acceptance: the W0 system test passes with a manifest in which families 42,
44 and 202 and the on-chain account each come from different roots, using
the W4 signer: board, complete a round, send and receive out of round, exit,
then restore into a fresh daemon from the manifest and the four sources with
`--recover` and see the same balance and VTXOs. Unit tests cover:

- each override validation error (auth-family override, script descriptor,
  duplicate key, identity override on an existing wallet or without the
  flag);
- signer routing, including refusal of unmapped slots and of a request
  whose public key does not match the derived key;
- the per-slot unlock probe rejecting an lnd-style single-root signer;
- `--recover` without the manifest failing with a clear message.

Milestone W6: Ark output descriptor export. Families 42, 44 and 202 end up in
real on-chain outputs: boarding outputs are on chain from the start, and
VTXOs and out-of-round receives reach the chain on a unilateral exit. After
W6, `waved` can print an output descriptor for every such output it knows
about, so an external watch-only tool such as Bitcoin Core can track
boarding funds and exits. W6 depends only on Milestone 4 and Milestone 1's
checksum code, not on W2 to W5; it works for seed and descriptor wallets
alike.

Why the family keys are not themselves output descriptors, and why the
export lists outputs one by one rather than as a ranged template. An output
descriptor describes a script, and none of these keys is ever paid to on its
own. Each sits inside the standard Ark policy
(`lib/arkscript/standard_vtxo.go`, `StandardVTXOTemplate`): a taproot output
whose internal key is the fixed Ark NUMS key `ARKNUMSKey`
(`lib/arkscript/nums.go`, hex `02372f22...ec65`, no known private key), with
two leaves. The cooperative leaf is `<owner> OP_CHECKSIGVERIFY <operator>
OP_CHECKSIG`. The exit leaf is `<owner> OP_CHECKSIG <delay>
OP_CHECKSEQUENCEVERIFY OP_DROP` (`lib/arkscript/node.go`, `Multisig.Script`
and `CSV.Script`). Three things stop a ranged descriptor from describing
this:

- The operator key and exit delay come from authenticated operator terms and
  change when the operator rotates, so one family maps to a different
  template per (operator key, delay) epoch, and `waved` must not take those
  values from user input.
- The exit leaf is not expressible in miniscript. Miniscript has no fragment
  that ends in `OP_DROP`. The nearest candidate, `and_v(v:pk(K),older(N))`,
  compiles to `<K> OP_CHECKSIGVERIFY <N> OP_CHECKSEQUENCEVERIFY`, which is a
  different leaf and therefore a different address. Standard `tr()`
  descriptors (BIP386) have no raw-leaf form, so no standard descriptor can
  produce the Ark leaf.
- Families 45 (MuSig2 aggregates with other round participants), 6 (vHTLCs
  with a per-swap payment hash) and 21 and 43 (never in a script) have no
  fixed script at all.

So the import format stays as key expressions, and the export emits one
non-ranged `rawtr(OUTPUT_KEY)#checksum` descriptor per concrete output, where
`OUTPUT_KEY` is the x-only taproot output key taken from the pkScript that
`arkscript.PolicyTemplate.PkScript` produced. That is exact by
construction, with no reimplementation of the policy. `rawtr()` is supported
by Bitcoin Core since version 23; `addr()` is the fallback for tools without
it.

Add `rpc ListArkOutputDescriptors (ListArkOutputDescriptorsRequest) returns
(ListArkOutputDescriptorsResponse)` to `waverpc.DaemonService`. The request
takes a `kinds` filter (`BOARDING`, `VTXO_EXIT`, `OOR_RECEIVE`) and a cursor;
the response lists entries of `descriptor`, `kind`, `key_family`,
`key_index`, `operator_pubkey`, `exit_delay`, `outpoint` (when known) and
`created_height`. Source the entries from the stores that already hold these
scripts: the boarding address store, the VTXO store, and the owned
receive-script store. Add `wavecli wallet descriptors --ark [--kind ...]`.
The output is public data, but it reveals the wallet's whole Ark footprint,
so the RPC requires the same read macaroon as `ListVTXOs`. Document in
`docs/daemon_cli_guide.md` that these descriptors are for watching only:
spending an exit still needs Wavelength (or the operator for the cooperative
leaf), because no external wallet can build the leaf witness from a
`rawtr()` descriptor.

Acceptance: unit tests assert that each exported descriptor's checksum
verifies and that decoding `OUTPUT_KEY` reproduces the stored pkScript for
boarding, VTXO and receive entries, including across an operator rotation in
the test harness. A system test imports the exported boarding descriptors
into a Bitcoin Core watch-only wallet with `importdescriptors`, funds a
boarding address from the harness, and checks that Core's
`listunspent` reports the same outpoint and amount as `wavecli balance`
(`pending_in_sat`). A unit test also pins the miniscript non-equivalence: it
compiles the exit leaf with `arkscript` and asserts it differs from the
script of `and_v(v:pk(K),older(N))`, built by hand in the test. If miniscript
or descriptors ever gain a matching form, that test is the place to notice.

Rough sizing, for planning only: W0 is mainly test harness work; W1 is two
small refactors; W2 is the largest piece (bundle parser, watch-only wallet
construction, configuration, signer connection lifecycle, identity
challenge, an unlock flow for watch-only wallets, and native-only SDK
surfaces); W3 is a medium-sized signer package plus encrypted key storage;
W4 is a thin gRPC layer over code that exists by then, plus the export
command. W2, W3 and W4 share the watch-only database, the bundle format and
the signing adapter, so each is cheaper once the previous one exists. The
shortest route to "descriptors directly in waved, no lnd" for private keys is
Milestones 0 to 4 alone; for public keys it is W1, W2 and W4. W5 is mostly
validation, the manifest, the signer routing table and the per-slot probe,
all on top of W2 to W4; its largest cost is the backup and restore
documentation and tests, because a mistake there loses funds. W6 is small:
one read-only RPC over existing stores plus a CLI flag.


### Sample usage (proposed API)

Nothing below exists yet. It shows how W2 to W6 fit together for one
deployment, using the names this plan proposes. Keys are shortened with
`...` and the example network is regtest, so family paths use coin type
`1'` while the on-chain account path uses `0'` (btcwallet's fixed coin type;
see `Surprises & Discoveries`).

There are two hosts. The signer host holds every private key and runs
`waved --mode=signer` (W4). The watch-only host runs `waved` with the chain
backend and all Ark state (W2).

Step 1, on the signer host: name the key sources in a secret file, mode
0600, at `/secure/signer-keys.json`. `primary` and `cold-a` are root keys
with fingerprints `d34db33f` and `a1b2c3d4`; `cold-b` and `cold-c` are
account-level keys at arbitrary origin paths.

    {
      "sources": {
        "primary": "tprv8ZgxMBicQKsPe...",
        "cold-a":  "tprv8ZgxMBicQKsPf...",
        "cold-b":  "[b2c3d4e5/9000h/7h]tprv8e...",
        "cold-c":  "[e5f6a7b8/86h/0h/3h]tprv8f..."
      }
    }

Start the signer:

    waved --mode=signer --network=regtest \
      --signer.keysfile=/secure/signer-keys.json \
      --signer.listenaddr=0.0.0.0:10019

Step 2, on the signer host: have the signer write the manifest and the
authentication keys. Families without a `--slot` come from `--primary`;
families 21 and 43 always do.

    wavecli --rpcserver=localhost:10019 wallet export-watchonly --minimal \
      --primary primary \
      --slot 42=cold-a:m/1017h/1h/42h \
      --slot 202=cold-a:m/1017h/1h/202h \
      --slot 44=cold-b \
      --slot onchain=cold-c \
      --manifest-out manifest.json \
      --auth-keys-out auth-keys.json

`manifest.json` is public. It is the file to back up alongside every key
source, and the one `waved` stores and hashes:

    {
      "version": 1,
      "network": "regtest",
      "primary_fingerprint": "d34db33f",
      "onchain": "tr([e5f6a7b8/86h/0h/3h]tpubDC.../<0;1>/*)#k3l9x2qp",
      "families": {
        "6":   "[d34db33f/1017h/1h/6h]tpubDD.../0/*#7xq2m9ld",
        "42":  "[a1b2c3d4/1017h/1h/42h]tpubDE.../0/*#c4n8w2ra",
        "44":  "[b2c3d4e5/9000h/7h]tpubDF.../0/*#q7m2x9kd",
        "45":  "[d34db33f/1017h/1h/45h]tpubDG.../0/*#h3v6t0ps",
        "202": "[a1b2c3d4/1017h/1h/202h]tpubDH.../0/*#e9k1u5zy"
      }
    }

`auth-keys.json` is secret (mode 0600), and `waved` moves it into its
encrypted keystore:

    {
      "21": "[d34db33f/1017h/1h/21h]tprv8g.../0/*#m2p8d4qa",
      "43": "[d34db33f/1017h/1h/43h]tprv8h.../0/*#w6r3j7nc"
    }

Step 3, on the watch-only host: start `waved` pointing at the signer, then
create the wallet.

    waved --network=regtest --wallet.type=lwwallet \
      --wallet.esploraurl=http://localhost:3000 \
      --wallet.remotesigner.rpchost=signer.internal:10019 \
      --wallet.remotesigner.tlscertpath=/etc/wave/signer.cert \
      --wallet.remotesigner.macaroonpath=/etc/wave/signer.macaroon \
      --wallet.remotesigner.requesttimeout=20s

    wavecli create \
      --watch-only-manifest manifest.json \
      --auth-keys-file auth-keys.json \
      --birthday 2026-01-01 \
      --recover

Expected output, abbreviated. Every fund slot must report `"ok": true`, or
creation stops before any key is used:

    {
      "identity_pubkey": "02ab...",
      "manifest_hash": "5f1c...e9",
      "signer_probes": [
        {"slot": "onchain", "ok": true}, {"slot": "6", "ok": true},
        {"slot": "42", "ok": true}, {"slot": "44", "ok": true},
        {"slot": "45", "ok": true}, {"slot": "202", "ok": true}
      ],
      "recovery_ran": true,
      "recovered_vtxos": 0
    }

Had family 6 come from a source other than `primary`, the command would fail
unless `--override-identity` were added, and only on a fresh data directory.

The same from the Go embedding SDK. The optional `walletdesc.ParseManifest`
call runs the same validation `waved` will, without starting anything:

    manifest, err := os.ReadFile("manifest.json")
    if err != nil {
            return err
    }
    authKeys, err := os.ReadFile("auth-keys.json")
    if err != nil {
            return err
    }
    defer clear(authKeys)

    m, err := walletdesc.ParseManifest(manifest, &chaincfg.RegressionNetParams)
    if err != nil {
            // For example walletdesc.ErrAuthFamilyOverride,
            // ErrDuplicateKey, ErrScriptDescriptorSlot,
            // ErrIdentityOverride or ErrBadKeyExpressionChecksum.
            return err
    }

    client, res, err := wavewalletdk.StartWatchOnlyWallet(ctx,
            wavewalletdk.Config{
                    DataDir: "/var/lib/wave",
                    Network: "regtest",
            },
            wavewalletdk.WatchOnlyWalletRequest{
                    Manifest:             manifest,
                    AuthKeys:             authKeys,
                    ExpectedManifestHash: m.Hash(),
                    Birthday: time.Date(
                            2026, 1, 1, 0, 0, 0, 0, time.UTC,
                    ),
                    RemoteSigner: wavewalletdk.RemoteSignerConfig{
                            Host:           "signer.internal:10019",
                            TLSCertPath:    "/etc/wave/signer.cert",
                            MacaroonPath:   "/etc/wave/signer.macaroon",
                            RequestTimeout: 20 * time.Second,
                    },
                    RecoverState:   true,
                    RecoveryWindow: 200,
            },
    )
    if err != nil {
            return err
    }
    defer client.Stop()

    log.Printf("identity %s, manifest %s", res.IdentityPubKey,
            res.ManifestHash)

The same against a running `waved` over gRPC:

    resp, err := waverpc.NewDaemonServiceClient(conn).InitWallet(ctx,
            &waverpc.InitWalletRequest{
                    WalletPassword:    password,
                    WatchOnlyManifest: manifest,
                    AuthKeys:          authKeys,
                    BirthdayUnix: time.Date(
                            2026, 1, 1, 0, 0, 0, 0, time.UTC,
                    ).Unix(),
                    RecoverState:   true,
                    RecoveryWindow: 200,
            },
    )

Step 4, optional (W6): export Ark output descriptors and watch boarding funds
from Bitcoin Core.

    wavecli wallet descriptors --ark --kind boarding

    {
      "descriptors": [
        {
          "descriptor": "rawtr(9a1f...c03e)#p4u8k2wm",
          "kind": "BOARDING",
          "key_family": 42,
          "key_index": 0,
          "operator_pubkey": "03c7...",
          "exit_delay": 144,
          "created_height": 812
        }
      ]
    }

    bitcoin-cli -regtest createwallet arkwatch true true
    bitcoin-cli -regtest -rpcwallet=arkwatch importdescriptors \
      '[{"desc": "rawtr(9a1f...c03e)#p4u8k2wm", "timestamp": "now"}]'
    bitcoin-cli -regtest -rpcwallet=arkwatch listunspent 0

Core can only watch these outputs. Spending them still goes through
Wavelength, because only Wavelength can build the Ark leaf witness.

BIP39 mnemonic import becomes a small follow-up once `walletcore.Config.RootKey`
exists, since a BIP39 seed maps to a root key in one step.


Revision note (2026-11-02): initial version.

Revision note (2026-11-02, later): re-audited against HEAD `3b7ed47f` after a
pull of 149 commits. No milestone changed. The re-audit found that a
watch-only lnd with a remote signer is already supported, and that lnd's
`rpcwallet.RPCKeyRing` provides the remote-signing key ring. On that basis
the "future work" note was replaced with the W0 to W3 extension, and the
watch-only Decision Log entry was revised to match.

Revision note (2026-11-02, W2 detail): rewrote W2 with what the code
requires. lnd's `BtcWallet.Start` forces all 256 key-family accounts to exist,
so a watch-only bundle must carry every one. A remote signer must serve ten
specific `signrpc`/`walletrpc` requests. A watch-only wallet has no private
passphrase, so the user's password becomes the public passphrase. The TCP
gRPC signer client cannot run in the browser build. Added W4, a Wavelength
signer mode plus a bundle export command, so a watch-only deployment needs no
lnd at all.

Revision note (2026-11-02, coin type): while listing every key waved derives
from the master key, found that btcwallet's on-chain scopes use coin type
`0'` on every network. Corrected the path rule in Milestone 1, the
supported-descriptor decision, the test vectors, the Milestone 4 Core
interoperability test, Concrete Steps (which now build a coin-`0'` descriptor
from Core's root key, using `getdescriptorinfo`'s checksum so the private key
is kept), acceptance, and the W2 bundle example.

Revision note (2026-11-02, split signing): added split signing to W2.
Fund families and the `86'` account are signed remotely and authentication
families 21 and 43 locally. A minimal bundle uses placeholder accounts behind
a `splitKeyRing` guard, every family is classified in a `lib/keyfamily`
registry pinned by lint and tests, and W4 export gains `--minimal`. Also
corrected two facts: lnd's `InitAccounts` requires accounts 1 to 255 (not 0
to 255), and a watch-only wallet needs only the `86'` on-chain account. Added
family 21 and the identity key's swap-funds role to Context and Orientation.
Recorded the decision, including what split signing does not protect against.

Revision note (2026-11-02, overrides): added W5, per-family key overrides.
Fund slots may each come from their own key source, recorded in a manifest
that `waved` stores and shows by hash. Override rules cover which slots may
be overridden, single keys only, no duplicates and identity overrides only on
fresh wallets. The W4 and W3 signers translate logical key requests to each
source's real origin, because `rpcwallet.RPCKeyRing` names keys by family and
index. Every unlock probes each fund slot, which also rejects an lnd signer.
Backup and restore now need the manifest plus every source, and restore fails
loudly without them. W2's same-root rule now says W5 relaxes it, and Progress
and the Decision Log were updated.

Revision note (2026-11-02, key expressions, W6 and samples): bundle and
manifest family entries are now ranged key expressions
(`[fp/path]xpub/0/*#checksum`), and the manifest format and hash are defined.
Added W6, which exports Ark output descriptors as concrete `rawtr()` entries
from the stored pkScripts. It explains why the family keys cannot be output
descriptors, including the finding that the Ark exit leaf has no miniscript
form (recorded in `Surprises & Discoveries`). Added "Sample usage (proposed
API)", covering the signer key file, export command, manifest, auth keys,
CLI creation, Go SDK and gRPC calls, and Core watching, and listed the
proposed names in `Interfaces and Dependencies`. Renamed the extension
heading to cover W0 to W6.

Revision note (2026-11-02, implementation pass): implemented Milestones 0
to 7 and extensions W1 and W6 on the `descriptors` branch of this
repository and its three downstream repositories. Progress records each
milestone's evidence, deviation and remaining gap. New findings are in
Surprises & Discoveries (Neuter slice aliasing, SLIP-132 account keys, the
account-key public rendering bug), and new decisions are in the Decision
Log (Render instead of String(bool), fingerprint persistence, password-free
private export, the `wavecli descriptors` command placement).

Revision note (2026-11-03, W5): implemented per-family key overrides and
marked W5 done in Progress, with its deviations: an implicit signer
routing, no manifest on the in-process account-key path, a key-level
restore check, and no loud failure for a seed-only restore. Added two
findings to Surprises & Discoveries and the separate manifest and
auth-keys decision to the Decision Log, and listed the work still not
started.

Revision note (2026-11-03, follow-ups): implemented the work left after
W5 that this host can build: the manifest restore check, daemon-side
bundle export, SDK and mobile watch-only wallets, and inbound signer
connections. Recorded each in Progress with its deviations, added the
inbound-connection ownership decision, and listed what remains.

