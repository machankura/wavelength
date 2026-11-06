//go:build mobile && wavewalletrpc && swapruntime

package mobile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestParseWatchOnlyWalletStartRequest verifies the private wire contract,
// including the remote signer config fields.
func TestParseWatchOnlyWalletStartRequest(t *testing.T) {
	cfg, req, err := parseWatchOnlyWalletStartRequest([]byte(`{
		"config": {
			"data_dir": "/tmp/wavelength-wallet",
			"network": "regtest",
			"wallet_type": "lwwallet",
			"remote_signer_rpc_host": "10.0.0.2:10019",
			"remote_signer_macaroon_path": "/keys/signer.macaroon",
			"remote_signer_tls_cert_path": "/keys/tls.cert",
			"remote_signer_request_timeout_seconds": 5
		},
		"manifest": "{}",
		"auth_keys": "keys",
		"override_identity": true,
		"wallet_password": "cGFzc3dvcmQ=",
		"birthday_unix": 1700000000,
		"recover_state": true
	}`), false)
	require.NoError(t, err)
	require.NotNil(t, cfg.RemoteSigner)
	require.Equal(t, "10.0.0.2:10019", cfg.RemoteSigner.RPCHost)
	require.Equal(t, "/keys/tls.cert", cfg.RemoteSigner.TLSCertPath)
	require.Equal(t, 5*time.Second, cfg.RemoteSigner.RequestTimeout)
	require.Zero(t, cfg.RemoteSigner.ConnectTimeout)
	require.Equal(t, []byte("{}"), req.Manifest)
	require.Equal(t, []byte("keys"), req.AuthKeys)
	require.True(t, req.OverrideIdentity)
	require.Equal(t, []byte("password"), req.WalletPassword)
	require.Equal(t, int64(1700000000), req.Birthday.Unix())
	require.True(t, req.RecoverState)
}

// TestParseWatchOnlyWalletStartRequestRejectsInvalid tests its wire shape.
func TestParseWatchOnlyWalletStartRequestRejectsInvalid(t *testing.T) {
	tests := []struct{ name, request string }{
		{
			"flat config",
			`{"data_dir": "/flat", "bundle": "x"}`,
		},
		{"no signer", `{
			"config": {"data_dir": "/tmp/wavelength-wallet"},
			"bundle": "x"
		}`},
		{"negative timeout", `{
			"config": {
				"data_dir": "/tmp/wavelength-wallet",
				"remote_signer_rpc_host": "h:1",
				"remote_signer_connect_timeout_seconds": -1
			},
			"bundle": "x"
		}`},
		{"negative birthday", `{
			"config": {
				"data_dir": "/tmp/wavelength-wallet",
				"remote_signer_rpc_host": "h:1"
			},
			"bundle": "x", "birthday_unix": -1
		}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseWatchOnlyWalletStartRequest(
				[]byte(test.request), false,
			)
			require.Error(t, err)
		})
	}
}

// TestStartWatchOnlyWalletRejectsBadRequestAndResets tests lifecycle reset.
func TestStartWatchOnlyWalletRejectsBadRequestAndResets(t *testing.T) {
	resetMobileState(t)
	_, err := StartWatchOnlyWallet([]byte(`{
		"config": {
			"data_dir": "/tmp/watch-only-wallet-test",
			"remote_signer_rpc_host": "127.0.0.1:1"
		},
		"bundle": "junk",
		"wallet_password": "cHc="
	}`))
	require.Error(t, err)
	require.False(t, IsRunning())
}

// TestParseWatchOnlyWalletHosted proves a wallet with its signer in process
// names no remote signer, and that a timeout still reaches the daemon.
func TestParseWatchOnlyWalletHosted(t *testing.T) {
	request := []byte(`{
		"config": {
			"data_dir": "/tmp/wavelength-wallet",
			"network": "regtest",
			"wallet_type": "lwwallet",
			"remote_signer_request_timeout_seconds": 90
		},
		"manifest": "{}",
		"auth_keys": "{}",
		"wallet_password": "cGFzc3dvcmQ="
	}`)

	_, _, err := parseWatchOnlyWalletStartRequest(request, false)
	require.Error(t, err, "without a host the signer has to be named")

	_, _, err = parseWatchOnlyWalletStartRequest(request, true)
	require.NoError(t, err)
	require.Equal(t, 90*time.Second, hostRequestTimeout(request))
}
