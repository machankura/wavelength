# accountsigner

## Purpose

Signs for a self-managed wallet from account-level private keys held in the
daemon process, without the BIP32 master key. It serves the requests lnd's
`rpcwallet.RPCKeyRing` sends a remote signer, so an account-key wallet runs
on exactly the remote-signing path: a watch-only btcwallet tracks the chain
and derives public keys, and every signature becomes an in-process request
here instead of a gRPC call.

## Key Types

- `Signer` — implements `rpcwallet.RemoteSignerConnection` over
  `walletdesc.AccountKeys`: `SignPsbt`, `SignMessage` (ECDSA, compact,
  BIP340 with tag and taproot tweak), `DeriveSharedKey`, and the seven
  MuSig2 calls through lnd's `input.MusigSessionManager`. `Stop` wipes the
  keys; later requests fail with `ErrStopped`.
- `ErrUnknownKey` — a derivation path or locator no account key covers.

## Relationships

- **Depends on**: `walletdesc` (account keys), lnd `input`, `keychain`,
  `lnrpc/signrpc`, `lnrpc/walletrpc`, `lnwallet/btcwallet` (PSBT tweak
  keys) and `lnwallet/rpcwallet` (the connection interface).
- **Depended on by**: `walletcore` (account-key wallets).

## Invariants

- PSBT signing follows lnd's `BtcWallet.SignPsbt`: inputs without BIP32
  derivation info, already final, or for keys this signer does not hold
  are skipped, not failed, and a derived key must equal the public key the
  derivation info names. The RPC key ring then verifies every returned
  signature against the expected key.
- Message tags beginning with `BIP0340` or `TapSighash` are refused, as in
  lnd's signer, so a message signature cannot double as a transaction
  signature.
- Keys below an account are derived with non-hardened steps only, so
  btcwallet's legacy hardened derivation cannot make them differ.
- A key descriptor with a public key at index 0 is resolved by scanning its
  family up to `keychain.MaxKeyRangeScan`, as lnd's key ring does.
- MuSig2 key aggregation sorts signer keys, as lnd does; cosigners must too.

## Deep Docs

- [docs/descriptor-wallets-execplan.md](../docs/descriptor-wallets-execplan.md)
  — Milestone W3.
