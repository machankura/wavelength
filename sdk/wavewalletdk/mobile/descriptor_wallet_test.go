//go:build mobile && wavewalletrpc && swapruntime

package mobile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseDescriptorWalletStartRequest verifies the private wire contract.
func TestParseDescriptorWalletStartRequest(t *testing.T) {
	cfg, req, err := parseDescriptorWalletStartRequest([]byte(`{
		"config": {
			"data_dir": "/tmp/wavelength-wallet",
			"network": "regtest",
			"wallet_type": "lwwallet"
		},
		"descriptors": ["tr(tprvA/86h/0h/0h/<0;1>/*)"],
		"birthday_unix": 1700000000,
		"expected_identity_pubkey": "02abcdef",
		"recover_state": true,
		"recovery_window": 144
	}`))
	require.NoError(t, err)
	require.Equal(t, "/tmp/wavelength-wallet", cfg.DataDir)
	require.Equal(t, "regtest", cfg.Network)
	require.Equal(
		t, []string{"tr(tprvA/86h/0h/0h/<0;1>/*)"}, req.Descriptors,
	)
	require.Equal(t, int64(1700000000), req.Birthday.Unix())
	require.Equal(t, "02abcdef", req.ExpectedIdentityPubKey)
	require.True(t, req.RecoverState)
	require.Equal(t, uint32(144), req.RecoveryWindow)

	// An omitted birthday stays zero, which scans from genesis.
	_, req, err = parseDescriptorWalletStartRequest([]byte(`{
		"config": {"data_dir": "/tmp/wavelength-wallet"},
		"descriptors": ["tr(x)"]
	}`))
	require.NoError(t, err)
	require.True(t, req.Birthday.IsZero())
}

// TestParseDescriptorWalletStartRequestRejectsInvalid tests its wire shape.
func TestParseDescriptorWalletStartRequestRejectsInvalid(t *testing.T) {
	tests := []struct{ name, request string }{
		{"flat config", `{
			"data_dir": "/flat", "descriptors": ["tr(x)"]
		}`},
		{"no data dir", `{
			"config": {"network": "regtest"},
			"descriptors": ["tr(x)"]
		}`},
		{"no descriptors", `{
			"config": {"data_dir": "/tmp/wavelength-wallet"}
		}`},
		{"negative birthday", `{
			"config": {"data_dir": "/tmp/wavelength-wallet"},
			"descriptors": ["tr(x)"], "birthday_unix": -1
		}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseDescriptorWalletStartRequest(
				[]byte(test.request),
			)
			require.Error(t, err)
		})
	}
}

// TestStartDescriptorWalletRejectsBadRequestAndResets tests lifecycle reset.
func TestStartDescriptorWalletRejectsBadRequestAndResets(t *testing.T) {
	resetMobileState(t)
	_, err := StartDescriptorWallet([]byte(`{
		"config": {"data_dir": "/tmp/descriptor-wallet-test"},
		"descriptors": ["sh(wpkh(x))"]
	}`))
	require.Error(t, err)
	require.False(t, IsRunning())
}
