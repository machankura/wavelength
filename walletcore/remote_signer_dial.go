//go:build !(js && wasm)

package walletcore

import (
	"context"
	"fmt"
	"time"

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

	return &outboundConn{
		OutboundConnection: conn,
		requestTimeout:     cfg.RequestTimeout,
	}, nil
}

// outboundConn bounds each request by the configured request timeout.
// lnd's OutboundConnection answers RequestTimeout with its connection
// timeout and ignores ExperimentalRequestTimeout, and the RPC key ring
// reads RequestTimeout once to bound every signing call.
type outboundConn struct {
	*rpcwallet.OutboundConnection

	requestTimeout time.Duration
}

// RequestTimeout returns the configured per-request timeout.
func (c *outboundConn) RequestTimeout() time.Duration {
	return c.requestTimeout
}
