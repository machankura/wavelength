// Package callbacksigner serves a watch-only daemon's signing requests from
// its host application, in process, with no port and no TLS.
//
// It implements lnd's rpcwallet.RemoteSignerConnection, as accountsigner does,
// and turns each request into JSON for a Host to answer. The host may take its
// time and may refuse: it is expected to be a threshold group whose members
// check what they are asked to sign. So unlike the other signers this package
// sends the whole of what a signer needs to judge a request, the transaction
// and every prevout, the leaf being spent and any signctx note, and computes
// nothing the host has to take on trust. The digest it sends is for the host to
// compare with its own.
//
// It signs taproot only, and rejects any request it cannot describe.
package callbacksigner
