package walletdesc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// derivePrivate derives the private key at a hardened path from root with
// standard BIP32.
func derivePrivate(t *testing.T, root *hdkeychain.ExtendedKey,
	path ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	key := root
	for _, step := range path {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}

	return key
}

// accountKeyTexts returns the account key entries for root: the BIP86
// account and either the coin-level key or every family key.
func accountKeyTexts(t *testing.T, root *hdkeychain.ExtendedKey,
	perFamily bool) []string {

	t.Helper()

	fp, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(fp)

	tr, err := AddChecksum(
		fmt.Sprintf(
			"tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			derivePrivate(t, root, 86, 0, 0),
		),
	)
	require.NoError(t, err)

	texts := []string{tr}
	if !perFamily {
		return append(
			texts,
			fmt.Sprintf(
				"[%s/1017h/1h]%s", origin,
				derivePrivate(t, root, 1017, 1),
			),
		)
	}

	for family := uint32(0); family <= 255; family++ {
		texts = append(
			texts,
			fmt.Sprintf(
				"[%s/1017h/1h/%dh]%s/0/*", origin, family,
				derivePrivate(t, root, 1017, 1, family),
			),
		)
	}

	return texts
}

// TestParseAccountKeys checks both family forms parse to the same keys,
// that the public half equals the watch-only bundle of the same root, and
// that Zero wipes the private keys but not a bundle taken earlier.
func TestParseAccountKeys(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams

	fromCoin, err := ParseAccountKeys(
		accountKeyTexts(t, root, false), params,
	)
	require.NoError(t, err)
	fromFamilies, err := ParseAccountKeys(
		accountKeyTexts(t, root, true), params,
	)
	require.NoError(t, err)

	require.Len(t, fromCoin.Accounts, 257)
	for i := range fromCoin.Accounts {
		require.Equal(
			t, fromFamilies.Accounts[i].Key.String(),
			fromCoin.Accounts[i].Key.String(),
		)
		require.True(t, fromCoin.Accounts[i].Key.IsPrivate())
	}

	bundle, err := fromCoin.Bundle()
	require.NoError(t, err)
	want, err := ParseWatchOnlyBundle(
		[]byte(
			bundleLines(t, root, nil, nil),
		),
		params,
	)
	require.NoError(t, err)
	require.Equal(t, want.MasterFingerprint, bundle.MasterFingerprint)
	require.Len(t, bundle.Accounts, len(want.Accounts))
	for i := range want.Accounts {
		require.Equal(
			t, want.Accounts[i].Key.String(),
			bundle.Accounts[i].Key.String(),
		)
	}

	require.NotContains(t, fromCoin.String(), "tprv")

	fromCoin.Zero()
	require.NotEqual(
		t, bundle.Accounts[0].Key.String(),
		fromCoin.Accounts[0].Key.String(),
	)
	identity, err := bundle.IdentityKey()
	require.NoError(t, err)
	require.NotNil(t, identity)

	fromFamilies.Zero()
}

// leadingZeroCoinRoot returns a regtest master key whose coin-level key at
// 1017'/1' has a private scalar with a leading zero byte.
func leadingZeroCoinRoot(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	for i := 0; i < 20_000; i++ {
		seed := make([]byte, 32)
		seed[0], seed[1] = byte(i), byte(i>>8)
		root, err := hdkeychain.NewMaster(
			seed, &chaincfg.RegressionNetParams,
		)
		require.NoError(t, err)

		coin := derivePrivate(t, root, 1017, 1)
		priv, err := coin.ECPrivKey()
		require.NoError(t, err)
		if priv.Key.Bytes()[0] == 0 {
			return root
		}
	}

	t.Fatal("no coin-level key with a leading zero byte found")

	return nil
}

// TestParseAccountKeysRefusals covers every refusal and checks no error
// echoes key material.
func TestParseAccountKeysRefusals(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams
	fp, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(fp)

	coinTexts := accountKeyTexts(t, root, false)
	familyTexts := accountKeyTexts(t, root, true)

	publicCoin := fmt.Sprintf("[%s/1017h/1h]%s", origin,
		accountXpub(t, root, 1017, 1, 0))
	_, err = hdkeychain.NewKeyFromString(
		strings.TrimPrefix(publicCoin, "["+origin+"/1017h/1h]"),
	)
	require.NoError(t, err)

	mainnetRoot, err := hdkeychain.NewMaster(
		make([]byte, 32), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	tests := []struct {
		name  string
		texts []string
		want  error
	}{
		{
			name: "public coin-level key",
			texts: []string{
				coinTexts[0], fmt.Sprintf(
					"[%s/1017h/1h/7h]%s/0/*", origin,
					accountXpub(t, root, 1017, 1, 7)),
			},
			want: ErrAccountKeyPublic,
		},
		{
			name:  "coin-level and family keys",
			texts: append(coinTexts[:2:2], familyTexts[5]),
			want:  ErrMixedFamilyKeys,
		},
		{
			name: "missing family",
			texts: append(
				familyTexts[:45:45], familyTexts[46:]...,
			),
			want: ErrBundleIncomplete,
		},
		{
			name:  "missing on-chain account",
			texts: coinTexts[1:],
			want:  ErrBundleIncomplete,
		},
		{
			name: "coin-level key at the wrong path",
			texts: []string{
				coinTexts[0], fmt.Sprintf("[%s/1017h/1h]%s",
					origin,
					derivePrivate(t, root, 1017, 0)),
			},
			want: ErrBundleAccountPath,
		},
		{
			name: "mainnet key on regtest",
			texts: []string{
				coinTexts[0], fmt.Sprintf("[%s/1017h/1h]%s",
					origin,
					derivePrivate(t, mainnetRoot, 1017, 1)),
			},
			want: ErrNetworkMismatch,
		},
		{
			name: "suffix on a coin-level key",
			texts: []string{
				coinTexts[0], coinTexts[1] + "/0/*",
			},
			want: ErrUnsupportedPath,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseAccountKeys(test.texts, params)
			require.ErrorIs(t, err, test.want)
			require.NotContains(t, err.Error(), "tprv")
			require.NotContains(t, err.Error(), "tpub")
			require.NotContains(t, err.Error(), "xprv")
		})
	}
}

// TestHasAccountKeys checks the router between master-key descriptors and
// account keys.
func TestHasAccountKeys(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)

	require.False(
		t,
		HasAccountKeys(
			[]string{
				"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
			},
		),
	)
	require.True(t, HasAccountKeys(accountKeyTexts(t, root, false)[:1]))
	require.True(t, HasAccountKeys([]string{"[deadbeef/1017h/1h]tprv"}))
	require.False(t, HasAccountKeys(nil))
}

// TestParseAccountKeysLeadingZeroCoinKey checks a coin-level key with a
// leading zero byte is accepted: btcwallet only derives family 0 from it
// differently, and Wavelength never uses family 0.
func TestParseAccountKeysLeadingZeroCoinKey(t *testing.T) {
	t.Parallel()

	keys, err := ParseAccountKeys(
		accountKeyTexts(
			t, leadingZeroCoinRoot(t), false,
		),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	keys.Zero()
}
