// Package signerserver serves a Wavelength wallet's private keys to a
// watch-only daemon over gRPC, so no lnd is needed anywhere in a
// remote-signing deployment.
//
// It speaks lnd's signer protocol: the signrpc.Signer and
// walletrpc.WalletKit calls lnd's RPC key ring makes of a remote signer,
// answered by an accountsigner.Signer, plus ListAccounts so the signer's
// account public keys can be read in lnd's format. Every other call of
// those services is unimplemented. Requests need TLS and the signer's own
// macaroon.
package signerserver
