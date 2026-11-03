package walletdesc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// minimalLines returns a minimal bundle for root: the BIP86 account and
// the fund families as public keys, the authentication families as
// private keys. edit may rewrite or drop (by returning "") any family line.
func minimalLines(t *testing.T, root *hdkeychain.ExtendedKey,
	edit func(family uint32, line string) string) string {

	t.Helper()

	fp, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(fp)

	lines := []string{fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
		accountXpub(t, root, 86, 0, 0))}
	for _, family := range []uint32{6, 42, 44, 45, 202} {
		line := fmt.Sprintf("[%s/1017h/1h/%dh]%s/0/*", origin, family,
			accountXpub(t, root, 1017, 1, family))
		if edit != nil {
			line = edit(family, line)
		}
		lines = append(lines, line)
	}
	for _, family := range []uint32{21, 43} {
		line := fmt.Sprintf("[%s/1017h/1h/%dh]%s/0/*", origin, family,
			accountXprv(t, root, family))
		if edit != nil {
			line = edit(family, line)
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

// TestParseMinimalBundle checks a minimal bundle splits into its public and
// local halves, and that placeholders complete it for import with keys no
// one holds.
func TestParseMinimalBundle(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams

	full, minimal, err := ParseBundle(
		[]byte(
			minimalLines(t, root, nil),
		),
		params,
	)
	require.NoError(t, err)
	require.Nil(t, full)
	require.NotNil(t, minimal)
	defer minimal.Zero()

	require.Equal(
		t, []keychain.KeyFamily{6, 21, 42, 43, 44, 45, 202},
		minimal.Supplied(),
	)
	require.Len(t, minimal.Local.Accounts, 2)
	for _, acct := range minimal.Local.Accounts {
		require.True(t, acct.Key.IsPrivate())
	}
	require.NotContains(t, minimal.String(), "tprv")

	complete, err := minimal.WithPlaceholders(params)
	require.NoError(t, err)
	require.Len(t, complete.Accounts, 257)
	for i, acct := range complete.Accounts[1:] {
		require.Equal(t, uint32(i), acct.Account)
		require.False(t, acct.Key.IsPrivate())

		supplied := accountXpub(t, root, 1017, 1, uint32(i)).String()
		switch i {
		case 6, 21, 42, 43, 44, 45, 202:
			require.Equal(
				t, supplied, acct.Key.String(),
				"family %d", i,
			)

		default:
			require.NotEqual(
				t, supplied, acct.Key.String(),
				"family %d", i,
			)
		}
	}

	// Placeholders are fresh on every import.
	again, err := minimal.WithPlaceholders(params)
	require.NoError(t, err)
	require.NotEqual(
		t, complete.Accounts[1].Key.String(),
		again.Accounts[1].Key.String(),
	)

	// A bundle of public keys only is still a full bundle.
	full, minimal, err = ParseBundle(
		[]byte(
			bundleLines(t, root, nil, nil),
		),
		params,
	)
	require.NoError(t, err)
	require.NotNil(t, full)
	require.Nil(t, minimal)
}

// TestParseMinimalBundleRefusals covers the family rules and checks no
// error echoes key material.
func TestParseMinimalBundleRefusals(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams
	fp, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(fp)

	replace := func(target uint32,
		with string) func(uint32, string) string {

		return func(family uint32, line string) string {
			if family == target {
				return with
			}

			return line
		}
	}

	tests := []struct {
		name string
		text string
		want error
	}{
		{
			name: "authentication family as a public key",
			text: minimalLines(
				t, root,
				replace(
					43,
					fmt.Sprintf(
						"[%s/1017h/1h/43h]%s/0/*",
						origin, accountXpub(
							t, root, 1017, 1, 43,
						),
					),
				),
			),
			want: ErrMinimalBundleFamilies,
		},
		{
			name: "fund family as a private key",
			text: minimalLines(
				t, root,
				replace(
					44,
					fmt.Sprintf(
						"[%s/1017h/1h/44h]%s/0/*",
						origin,
						accountXprv(t, root, 44),
					),
				),
			),
			want: ErrMinimalBundleFamilies,
		},
		{
			name: "family outside the registry",
			text: minimalLines(t, root, nil) + "\n" + fmt.Sprintf(
				"[%s/1017h/1h/7h]%s/0/*", origin,
				accountXpub(t, root, 1017, 1, 7)),
			want: ErrMinimalBundleFamilies,
		},
		{
			name: "missing fund family",
			text: minimalLines(t, root, replace(44, "")),
			want: ErrMinimalBundleFamilies,
		},
		{
			name: "missing authentication family",
			text: minimalLines(t, root, replace(21, "")),
			want: ErrMinimalBundleFamilies,
		},
		{
			name: "mixed fingerprints",
			text: minimalLines(
				t, root,
				replace(
					45,
					fmt.Sprintf(
						"[deadbeef/1017h/1h/45h]%s/0/*",
						accountXpub(
							t, root, 1017, 1, 45,
						),
					),
				),
			),
			want: ErrMixedFingerprints,
		},
		{
			name: "missing on-chain account",
			text: strings.Join(
				strings.Split(
					minimalLines(t, root, nil),
					"\n",
				)[1:], "\n",
			),
			want: ErrBundleIncomplete,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := ParseBundle([]byte(test.text), params)
			require.ErrorIs(t, err, test.want)
			require.NotContains(t, err.Error(), "tprv")
			require.NotContains(t, err.Error(), "tpub")
		})
	}
}
