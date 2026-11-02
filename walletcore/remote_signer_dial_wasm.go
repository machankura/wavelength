//go:build js && wasm

package walletcore

import (
	"context"

	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
)

// DialRemoteSigner always fails in the browser, which cannot open the
// gRPC connection the signer serves.
func DialRemoteSigner(context.Context,
	RemoteSignerConfig) (rpcwallet.RemoteSignerConnection, error) {

	return nil, ErrRemoteSignerUnsupported
}
