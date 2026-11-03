# cmd

## Purpose

Entry points for the daemon (`cmd/waved`), CLI client (`cmd/wavecli`),
the remote signer (`cmd/wavesigner`: `create` an encrypted key store from
descriptors, account keys or a Wavelength mnemonic, with `--override
SLOT=FILE` filling fund slots from other keys, `run` the `signerserver`
gRPC signer, `export-watchonly [--minimal]` the bundle a watch-only daemon
imports, or `--manifest-out --auth-keys-out` for a store with overrides),
and supporting build tools: `cmd/merge-sql-schemas` (concatenates sqlc
migration files for embedding), `cmd/protoc-gen-mailboxrpc` (protoc plugin
generating the mailbox-actor RPC glue), and `cmd/wavewalletdk-wasm` (js/wasm
build target exposing `sdk/wavewalletdk` to browser JS).

## Relationships

- **Depends on**: `waved` (daemon orchestrator), `waverpc` (gRPC API
  definitions), `sdk/wavewalletdk` (wasm target only).
- **Depended on by**: nothing (top-level binaries).

## Deep Docs

- [docs/daemon_cli_guide.md](../docs/daemon_cli_guide.md) — Installation and CLI reference.
