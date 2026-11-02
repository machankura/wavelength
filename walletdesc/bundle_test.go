package walletdesc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// bundleTestRoot returns a fixed regtest master key.
func bundleTestRoot(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// accountXpub derives the standard-version account public key at
// purpose'/coin'/account' from root.
func accountXpub(t *testing.T, root *hdkeychain.ExtendedKey, purpose, coin,
	account uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	key := root
	for _, step := range []uint32{purpose, coin, account} {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}

	pub, err := StandardAccountPublicKey(
		key, &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	return pub
}

// accountXprv derives the private key-family account key for family from
// root, as a bundle entry that wrongly carries a private key would.
func accountXprv(t *testing.T, root *hdkeychain.ExtendedKey,
	family uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	key := root
	for _, step := range []uint32{1017, 1, family} {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}

	return key
}

// bundleLines returns the text form of a full bundle for root. skip names
// key families to leave out, and edit may rewrite any line.
func bundleLines(t *testing.T, root *hdkeychain.ExtendedKey,
	skip map[uint32]bool,
	edit func(family int, line string) string) string {

	t.Helper()

	fp, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(fp)

	trKey := accountXpub(t, root, 86, 0, 0)
	trText, err := AddChecksum(
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin, trKey),
	)
	require.NoError(t, err)

	lines := []string{"// regtest bundle", trText, ""}
	for family := uint32(0); family <= 255; family++ {
		if skip[family] {
			continue
		}

		key := accountXpub(t, root, 1017, 1, family)
		line, err := AddChecksum(
			fmt.Sprintf("[%s/1017h/1h/%dh]%s/0/*", origin, family,
				key),
		)
		require.NoError(t, err)
		if edit != nil {
			line = edit(int(family), line)
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

// TestParseWatchOnlyBundleText checks a full text bundle: accounts come back
// in import order with standard keys, and the identity key is index 0 of
// family 6.
func TestParseWatchOnlyBundleText(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams

	bundle, err := ParseWatchOnlyBundle(
		[]byte(
			bundleLines(t, root, nil, nil),
		),
		params,
	)
	require.NoError(t, err)

	fp, err := Fingerprint(root)
	require.NoError(t, err)
	require.Equal(t, fp, bundle.MasterFingerprint)
	require.Len(t, bundle.Accounts, 257)
	require.Equal(t, uint32(86), bundle.Accounts[0].Purpose)
	for i, acct := range bundle.Accounts[1:] {
		require.Equal(t, PurposeKeyFamily, acct.Purpose)
		require.Equal(t, uint32(i), acct.Account)
		require.Equal(
			t, accountXpub(t, root, 1017, 1, uint32(i)).String(),
			acct.Key.String(),
		)
	}

	identity, err := bundle.IdentityKey()
	require.NoError(t, err)
	want, err := accountXpub(t, root, 1017, 1, 6).Derive(0)
	require.NoError(t, err)
	want, err = want.Derive(0)
	require.NoError(t, err)
	require.Equal(t, want.String(), identity.String())

	// Nothing safe to log carries a key.
	require.NotContains(t, bundle.String(), "tpub")
}

// TestParseWatchOnlyBundleLndJSON checks lnd's account list JSON yields the
// same bundle as the text form, including a SLIP-132 BIP84 key and the
// imported pseudo-accounts lnd lists without keys.
func TestParseWatchOnlyBundleLndJSON(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams
	fp, err := Fingerprint(root)
	require.NoError(t, err)

	type account struct {
		Name        string `json:"name"`
		XPub        string `json:"extended_public_key"`
		Fingerprint string `json:"master_key_fingerprint,omitempty"`
		Path        string `json:"derivation_path"`
	}
	vpub, err := accountXpub(t, root, 84, 0, 0).CloneWithVersion(
		[]byte{0x04, 0x5f, 0x1c, 0xf6},
	)
	require.NoError(t, err)

	accounts := []account{
		{
			Name: "default",
			Path: "m/84'/0'/0'",
			XPub: vpub.String(),
		},
		{
			Name: "imported",
		},
		{
			Name: "default", Path: "m/86'/0'/0'",
			XPub: accountXpub(t, root, 86, 0, 0).String(),
			Fingerprint: hex.EncodeToString([]byte{
				byte(fp >> 24), byte(fp >> 16), byte(fp >> 8),
				byte(fp),
			}),
		},
	}
	// lnd lists families in its own order; parsing must sort them.
	for family := 255; family >= 0; family-- {
		accounts = append(accounts, account{
			Name: fmt.Sprintf("act:%d", family),
			Path: fmt.Sprintf("m/1017'/1'/%d'", family),
			XPub: accountXpub(
				t, root, 1017, 1, uint32(family),
			).String(),
		})
	}
	data, err := json.Marshal(map[string]any{"accounts": accounts})
	require.NoError(t, err)

	fromJSON, err := ParseWatchOnlyBundle(data, params)
	require.NoError(t, err)
	fromText, err := ParseWatchOnlyBundle(
		[]byte(
			bundleLines(t, root, nil, nil),
		),
		params,
	)
	require.NoError(t, err)

	require.Equal(t, fp, fromJSON.MasterFingerprint)
	require.Len(t, fromJSON.Accounts, 258)
	require.Equal(t, uint32(84), fromJSON.Accounts[0].Purpose)
	require.Equal(
		t, accountXpub(t, root, 84, 0, 0).String(),
		fromJSON.Accounts[0].Key.String(),
	)
	for i, acct := range fromJSON.Accounts[1:] {
		require.Equal(t, fromText.Accounts[i], acct)
	}
}

// TestParseWatchOnlyBundleRefusals covers every refusal, and checks no error
// echoes key material.
func TestParseWatchOnlyBundleRefusals(t *testing.T) {
	t.Parallel()

	root := bundleTestRoot(t)
	params := &chaincfg.RegressionNetParams
	other, err := hdkeychain.NewMaster(
		make([]byte, 32), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	replaceFamily := func(target int,
		replacement func() string) func(int, string) string {

		return func(family int, line string) string {
			if family == target {
				return replacement()
			}

			return line
		}
	}
	keyLine := func(fp string, path string, key fmt.Stringer,
		suffix string) string {

		return fmt.Sprintf("[%s/%s]%s%s", fp, path, key, suffix)
	}
	rootFP, err := Fingerprint(root)
	require.NoError(t, err)
	origin := FormatFingerprint(rootFP)

	tests := []struct {
		name string
		text string
		want error
	}{
		{
			name: "missing family",
			text: bundleLines(
				t, root, map[uint32]bool{
					44: true,
				},
				nil,
			),
			want: ErrBundleIncomplete,
		},
		{
			name: "missing on-chain account",
			text: strings.Join(
				strings.Split(
					bundleLines(t, root, nil, nil),
					"\n",
				)[3:], "\n",
			),
			want: ErrBundleIncomplete,
		},
		{
			name: "mixed fingerprints",
			text: bundleLines(
				t, root, nil, replaceFamily(
					7, func() string {
						return keyLine(
							"deadbeef",
							"1017h/1h/7h",
							accountXpub(
								t, root, 1017,
								1, 7,
							),
							"/0/*",
						)
					},
				),
			),
			want: ErrMixedFingerprints,
		},
		{
			name: "wrong coin type",
			text: bundleLines(
				t, root, nil, replaceFamily(
					7, func() string {
						return keyLine(
							origin, "1017h/0h/7h",
							accountXpub(
								t, root, 1017,
								0, 7,
							),
							"/0/*",
						)
					},
				),
			),
			want: ErrNetworkMismatch,
		},
		{
			name: "key for another account",
			text: bundleLines(
				t, root, nil, replaceFamily(
					6, func() string {
						return keyLine(
							origin, "1017h/1h/6h",
							accountXpub(
								t, root, 1017,
								1, 7,
							),
							"/0/*",
						)
					},
				),
			),
			want: ErrBundleAccountPath,
		},
		{
			name: "private key",
			text: bundleLines(
				t, root, nil, replaceFamily(
					43, func() string {
						return keyLine(
							origin, "1017h/1h/43h",
							accountXprv(
								t, other, 43,
							),
							"/0/*",
						)
					},
				),
			),
			want: ErrBundlePrivateKey,
		},
		{
			name: "duplicate",
			text: bundleLines(t, root, nil, nil) + "\n" + keyLine(
				origin, "1017h/1h/5h",
				accountXpub(t, root, 1017, 1, 5),
				"/0/*",
			),
			want: ErrBundleDuplicate,
		},
		{
			name: "change branch on a family",
			text: bundleLines(
				t, root, nil, replaceFamily(
					5, func() string {
						return keyLine(
							origin, "1017h/1h/5h",
							accountXpub(
								t, root, 1017,
								1, 5,
							),
							"/1/*",
						)
					},
				),
			),
			want: ErrUnsupportedPath,
		},
		{
			name: "family above 255",
			text: bundleLines(t, root, nil, nil) + "\n" + keyLine(
				origin, "1017h/1h/256h",
				accountXpub(t, root, 1017, 1, 256),
				"/0/*",
			),
			want: ErrUnsupportedPath,
		},
		{
			name: "bad checksum",
			text: bundleLines(t, root, nil, func(family int,
				line string) string {

				if family != 5 {
					return line
				}

				// Corrupt one checksum character.
				last := line[len(line)-1]
				flip := byte('q')
				if last == 'q' {
					flip = 'p'
				}

				return line[:len(line)-1] + string(flip)
			}),
			want: ErrBadChecksum,
		},
		{
			name: "garbage",
			text: "{not json",
			want: ErrMalformedBundle,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseWatchOnlyBundle(
				[]byte(test.text), params,
			)
			require.ErrorIs(t, err, test.want)
			require.NotContains(t, err.Error(), "tpub")
			require.NotContains(t, err.Error(), "tprv")
		})
	}

	// A mainnet bundle does not parse on regtest.
	_, err = ParseWatchOnlyBundle(
		[]byte(
			bundleLines(t, root, nil, nil),
		),
		&chaincfg.MainNetParams,
	)
	require.ErrorIs(t, err, ErrNetworkMismatch)
}
