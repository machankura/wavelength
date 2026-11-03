# signerserver

## Purpose

Serves a Wavelength wallet's private keys to a watch-only daemon over
gRPC, so a remote-signing deployment needs no lnd anywhere. It speaks lnd's
remote signer protocol, so a watch-only Wavelength daemon (or an lnd
watch-only node) uses it exactly as it would an lnd signer.

## Key Types

- `Config` — listen address, TLS pair (generated on first start, with
  optional extra IPs and domains), the client macaroon and its root key,
  the `walletdesc.AccountKeys` to sign with, and the network.
- `Server` — registers `signrpc.Signer` and `walletrpc.WalletKit`, answering
  only the calls lnd's RPC key ring makes (`SignMessage`, `DeriveSharedKey`,
  the seven `MuSig2*` calls, `SignPsbt`) through an `accountsigner.Signer`,
  plus `ListAccounts` so the account xpubs can be read in lnd's format.
  Every other call is unimplemented. `Serve`, `Stop` (wipes the keys),
  `Addr`.
- `CreateStore` / `OpenStore` — the signer's key store, `signer.db`, a
  bbolt wallet database holding the `accountsigner` keystore encrypted
  under the signer's password.
- `KeysFromDescriptors` / `KeysFromMnemonic` — account keys from
  master-key descriptors (as btcwallet would hold them), account-level
  keys, or a Wavelength aezeed mnemonic (entropy padded to 32 bytes, the
  Wavelength seed; an lnd wallet of the same mnemonic has other keys).
- `WriteBundle` — the full or minimal export; a minimal bundle is written
  owner-only and never over a file others can read.

## Relationships

- **Depends on**: `accountsigner` (signing), `walletdesc` (account keys),
  `rpcauth` (TLS), lnd's `signrpc`/`walletrpc` generated services,
  `gopkg.in/macaroon.v2`.
- **Depended on by**: `cmd/wavesigner`.

## Invariants

- Every unary and stream request needs TLS and a macaroon minted from the
  signer's root key with no caveats; anything else is `Unauthenticated`.
  Holding the macaroon means being allowed to ask for signatures, so it
  must only ever be given to the watch-only daemon.
- The signer only signs inside its own accounts: BIP86 and BIP84 account 0
  and the key families of its network's coin type. PSBT inputs with any
  other derivation path are left unsigned.
- The signer holds no chain state and runs no Ark logic; it cannot judge
  what it signs. Signer-side spending policy is future work.

## Deep Docs

- [docs/daemon_cli_guide.md](../docs/daemon_cli_guide.md) — running
  `wavesigner`.
