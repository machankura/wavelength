//go:build !(js && wasm)

package walletcore

import (
	"context"
	"fmt"

	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
)

// DialRemoteSigner connects to the remote signer described by cfg, which
// must already be validated. The connection is outbound: the daemon dials
// the signer, as an lnd watch-only node does by default.
func DialRemoteSigner(ctx context.Context,
	cfg RemoteSignerConfig) (rpcwallet.RemoteSignerConnection, error) {

	conn, err := rpcwallet.NewOutboundConnection(ctx, lncfg.ConnectionCfg{
		RPCHost:                    cfg.RPCHost,
		MacaroonPath:               cfg.MacaroonPath,
		TLSCertPath:                cfg.TLSCertPath,
		Timeout:                    cfg.Timeout,
		ExperimentalRequestTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to remote signer: %w", err)
	}

	return conn, nil
}
