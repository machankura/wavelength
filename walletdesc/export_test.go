package walletdesc

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestFormatBundle checks both bundle forms parse back to the keys they
// were rendered from.
func TestFormatBundle(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	keys, err := BtcwalletAccountKeys(bundleTestRoot(t), params)
	require.NoError(t, err)
	defer keys.Zero()
	want, err := keys.Bundle()
	require.NoError(t, err)

	text, err := FormatBundle(keys, false)
	require.NoError(t, err)
	require.NotContains(t, string(text), "tprv")

	full, minimal, err := ParseBundle(text, params)
	require.NoError(t, err)
	require.Nil(t, minimal)
	require.Equal(t, want.MasterFingerprint, full.MasterFingerprint)
	require.Len(t, full.Accounts, len(want.Accounts))
	for i := range want.Accounts {
		require.Equal(
			t, want.Accounts[i].Key.String(),
			full.Accounts[i].Key.String(),
		)
	}

	text, err = FormatBundle(keys, true)
	require.NoError(t, err)
	require.Contains(t, string(text), "tprv")

	full, minimal, err = ParseBundle(text, params)
	require.NoError(t, err)
	require.Nil(t, full)
	defer minimal.Zero()
	require.Len(t, minimal.Local.Accounts, 2)
	for _, acct := range minimal.Local.Accounts {
		own, ok := keys.Account(PurposeKeyFamily, acct.Account)
		require.True(t, ok)
		require.Equal(t, own.Key.String(), acct.Key.String())
	}
}
