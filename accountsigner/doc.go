// Package accountsigner signs for a wallet from account-level private keys
// held in the daemon's process, without the BIP32 master key.
//
// It answers the requests lnd's RPC key ring sends a remote signer (PSBT
// signing, message signing, ECDH and the MuSig2 session calls), so an
// account-key wallet reuses the remote-signing path unchanged: a watch-only
// btcwallet tracks the chain and derives public keys, and lnd's
// rpcwallet.RPCKeyRing turns every signature into a request that this
// package serves in process instead of over gRPC.
package accountsigner
