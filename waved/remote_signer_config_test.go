package waved

import (
	"testing"
	"time"

	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/stretchr/testify/require"
)

// TestValidateRemoteSigner checks the outbound and inbound signer configs
// and that defaults are filled in.
func TestValidateRemoteSigner(t *testing.T) {
	t.Parallel()

	outbound := RemoteSignerConfig{
		Enable: true, RPCHost: "h:1", MacaroonPath: "m",
		TLSCertPath: "c",
	}
	tests := []struct {
		name    string
		wallet  WalletConfig
		wantErr string
	}{
		{
			"disabled",
			WalletConfig{
				Type: WalletTypeLnd,
			},
			"",
		},
		{"outbound", WalletConfig{
			Type: WalletTypeLwwallet, RemoteSigner: outbound,
		}, ""},
		{"outbound without host", WalletConfig{
			Type: WalletTypeLwwallet,
			RemoteSigner: RemoteSignerConfig{
				Enable: true, MacaroonPath: "m",
				TLSCertPath: "c",
			},
		}, "rpchost is required"},
		{"inbound", WalletConfig{
			Type: WalletTypeBtcwallet,
			RemoteSigner: RemoteSignerConfig{
				Enable: true, AllowInbound: true,
			},
		}, ""},
		{"inbound with host", WalletConfig{
			Type: WalletTypeLwwallet,
			RemoteSigner: RemoteSignerConfig{
				Enable: true, AllowInbound: true,
				RPCHost: "h:1",
			},
		}, "takes no rpchost"},
		{"lnd backend", WalletConfig{
			Type: WalletTypeLnd, RemoteSigner: outbound,
		}, "not \"lnd\""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wallet := tc.wallet
			err := wallet.validateRemoteSigner()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}
			require.NoError(t, err)
			if !wallet.RemoteSigner.Enable {
				return
			}
			require.Equal(
				t, walletcore.DefaultRemoteSignerTimeout,
				wallet.RemoteSigner.Timeout,
			)
			require.Equal(
				t, walletcore.DefaultRemoteSignerRequestTimeout,
				wallet.RemoteSigner.RequestTimeout,
			)
		})
	}

	// The inbound connection reaches the wallet config only when
	// allowed.
	inbound := RemoteSignerConfig{
		Enable: true, AllowInbound: true, Timeout: time.Minute,
	}
	require.Nil(t, inbound.walletcoreConfig(nil).Inbound)
	require.Nil(t, RemoteSignerConfig{}.walletcoreConfig(nil))
}
