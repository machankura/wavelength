package walletdesc

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// testSourceRoot returns a regtest master key from a seed byte.
func testSourceRoot(t *testing.T, b byte) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// overriddenKeys returns a primary root's account keys with the on-chain
// account and families 42, 44 and 202 replaced by keys from three other
// sources, each carrying its real origin.
func overriddenKeys(t *testing.T) *AccountKeys {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	keys, err := BtcwalletAccountKeys(testSourceRoot(t, 1), params)
	require.NoError(t, err)

	override := func(purpose, account uint32, root *hdkeychain.ExtendedKey,
		path ...uint32) {

		key := root
		var origin []uint32
		for _, step := range path {
			key, err = key.Derive(hardened(step))
			require.NoError(t, err)
			origin = append(origin, hardened(step))
		}
		fp, err := Fingerprint(root)
		require.NoError(t, err)

		for i, acct := range keys.Accounts {
			if acct.Purpose == purpose && acct.Account == account {
				keys.Accounts[i].Key = key
				keys.Accounts[i].Origin = &KeyOrigin{
					Fingerprint: fp, Path: origin,
				}
			}
		}
	}

	coldA := testSourceRoot(t, 50)
	override(PurposeKeyFamily, 42, coldA, 1017, 1, 42)
	override(PurposeKeyFamily, 202, coldA, 1017, 1, 202)
	override(PurposeKeyFamily, 44, testSourceRoot(t, 90), 9000, 7)
	override(86, 0, testSourceRoot(t, 130), 86, 0, 3)

	return keys
}

// editManifest unmarshals a manifest, lets edit change it, and returns it
// re-encoded.
func editManifest(t *testing.T, data []byte, edit func(map[string]any)) []byte {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	edit(doc)
	out, err := json.Marshal(doc)
	require.NoError(t, err)

	return out
}

// TestManifest checks a manifest with overridden slots round-trips, names
// its overrides, hashes stably, and becomes a bundle whose slots hold the
// overriding keys.
func TestManifest(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	keys := overriddenKeys(t)
	defer keys.Zero()

	data, err := FormatManifest(keys, params)
	require.NoError(t, err)

	m, err := ParseManifest(data, params)
	require.NoError(t, err)
	require.Equal(t, keys.MasterFingerprint, m.PrimaryFingerprint)
	require.Equal(
		t, []string{"onchain", "42", "44", "202"}, m.Overrides(params),
	)
	require.NoError(t, m.CheckIdentity(false, params))

	// The on-chain descriptor names the overriding key's real origin.
	onChain, err := m.OnChainDescriptor()
	require.NoError(t, err)
	require.Contains(
		t, onChain, FormatFingerprint(m.OnChain.Origin.Fingerprint),
	)
	require.Contains(t, onChain, "/86h/0h/3h]")
	body, sum, ok := strings.Cut(onChain, "#")
	require.True(t, ok)
	want, err := Checksum(body)
	require.NoError(t, err)
	require.Equal(t, want, sum)

	// Reformatting does not change the hash.
	var pretty map[string]any
	require.NoError(t, json.Unmarshal(data, &pretty))
	indented, err := json.MarshalIndent(pretty, "", "    ")
	require.NoError(t, err)
	again, err := ParseManifest(indented, params)
	require.NoError(t, err)
	require.Equal(t, m.HashHex(), again.HashHex())
	require.Equal(t, data, again.Canonical())

	authText, err := FormatAuthKeys(keys)
	require.NoError(t, err)
	auth, err := ParseAuthKeys(authText, params)
	require.NoError(t, err)
	defer auth.Zero()

	minimal, err := m.MinimalBundle(auth, params)
	require.NoError(t, err)
	complete, err := minimal.WithPlaceholders(params)
	require.NoError(t, err)
	require.Len(t, complete.Accounts, 257)

	for _, slot := range []struct {
		purpose, account uint32
	}{{
		86,
		0,
	}, {
		PurposeKeyFamily,
		42,
	}, {
		PurposeKeyFamily,
		44,
	},
		{
			PurposeKeyFamily,
			202,
		}, {
			PurposeKeyFamily,
			6,
		}} {

		want, ok := keys.Account(slot.purpose, slot.account)
		require.True(t, ok)
		wantPub, err := want.Key.Neuter()
		require.NoError(t, err)

		got, ok := complete.Account(slot.purpose, slot.account)
		require.True(t, ok)
		require.Equal(t, wantPub.String(), got.Key.String())
		require.NotNil(t, got.Origin)
	}
}

// TestManifestRefusals covers each override rule.
func TestManifestRefusals(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	keys := overriddenKeys(t)
	defer keys.Zero()
	data, err := FormatManifest(keys, params)
	require.NoError(t, err)

	families := func(doc map[string]any) map[string]any {
		f, ok := doc["families"].(map[string]any)
		require.True(t, ok)

		return f
	}
	auth, ok := keys.Account(PurposeKeyFamily, 21)
	require.True(t, ok)
	authPub, err := auth.Key.Neuter()
	require.NoError(t, err)
	origin := FormatFingerprint(keys.MasterFingerprint)

	// The subtests run after this function returns and wipes keys, so
	// every key text they use is rendered now.
	authEntry := fmt.Sprintf("[%s/1017h/1h/21h]%s/0/*", origin, authPub)
	treeEntry := fmt.Sprintf("tr(%s,{pk(%s)})", authPub, authPub)
	privateEntry := fmt.Sprintf("[%s/1017h/1h/45h]%s/0/*", origin, auth.Key)

	tests := []struct {
		name string
		edit func(map[string]any)
		want error
	}{
		{
			name: "authentication family",
			edit: func(doc map[string]any) {
				families(doc)["21"] = authEntry
			},
			want: ErrAuthFamilyOverride,
		},
		{
			name: "script descriptor family",
			edit: func(doc map[string]any) {
				families(doc)["44"] = "multi(1,tpubA,tpubB)"
			},
			want: ErrScriptDescriptorSlot,
		},
		{
			name: "on-chain script tree",
			edit: func(doc map[string]any) {
				doc["onchain"] = treeEntry
			},
			want: ErrScriptDescriptorSlot,
		},
		{
			name: "duplicate key",
			edit: func(doc map[string]any) {
				f := families(doc)
				f["44"] = f["42"]
			},
			want: ErrDuplicateKey,
		},
		{
			name: "missing fund family",
			edit: func(doc map[string]any) {
				delete(families(doc), "45")
			},
			want: ErrManifestIncomplete,
		},
		{
			name: "wrong network",
			edit: func(doc map[string]any) {
				doc["network"] = "mainnet"
			},
			want: ErrNetworkMismatch,
		},
		{
			name: "private key",
			edit: func(doc map[string]any) {
				families(doc)["45"] = privateEntry
			},
			want: ErrBundlePrivateKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseManifest(
				editManifest(t, data, test.edit), params,
			)
			require.ErrorIs(t, err, test.want)
			require.NotContains(t, err.Error(), "tprv")
		})
	}

	// Overriding the identity family needs explicit consent.
	identityKeys := overriddenKeys(t)
	defer identityKeys.Zero()
	for i, acct := range identityKeys.Accounts {
		if acct.Purpose == PurposeKeyFamily && acct.Account == 6 {
			other := testSourceRoot(t, 170)
			key, err := other.Derive(hardened(6000))
			require.NoError(t, err)
			fp, err := Fingerprint(other)
			require.NoError(t, err)
			identityKeys.Accounts[i].Key = key
			identityKeys.Accounts[i].Origin = &KeyOrigin{
				Fingerprint: fp, Path: []uint32{
					hardened(6000),
				},
			}
		}
	}
	data, err = FormatManifest(identityKeys, params)
	require.NoError(t, err)
	m, err := ParseManifest(data, params)
	require.NoError(t, err)
	require.ErrorIs(t, m.CheckIdentity(false, params), ErrIdentityOverride)
	require.NoError(t, m.CheckIdentity(true, params))

	// Authentication keys from another root do not fit the manifest.
	otherKeys, err := BtcwalletAccountKeys(testSourceRoot(t, 200), params)
	require.NoError(t, err)
	defer otherKeys.Zero()
	otherAuthText, err := FormatAuthKeys(otherKeys)
	require.NoError(t, err)
	otherAuth, err := ParseAuthKeys(otherAuthText, params)
	require.NoError(t, err)
	defer otherAuth.Zero()
	_, err = m.MinimalBundle(otherAuth, params)
	require.ErrorIs(t, err, ErrMixedFingerprints)
}

// TestParseKeySource checks both key source forms give the slot key and
// its origin, and refuses public keys and non-hardened paths.
func TestParseKeySource(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testSourceRoot(t, 60)
	fp, err := Fingerprint(root)
	require.NoError(t, err)

	want := root
	for _, step := range []uint32{9000, 7} {
		want, err = want.Derive(hardened(step))
		require.NoError(t, err)
	}
	wantOrigin := KeyOrigin{
		Fingerprint: fp, Path: []uint32{
			hardened(9000),
			hardened(7),
		},
	}

	key, origin, err := ParseKeySource(root.String()+"/9000h/7'", params)
	require.NoError(t, err)
	require.Equal(t, want.String(), key.String())
	require.Equal(t, wantOrigin, origin)

	account := fmt.Sprintf("[%s/9000h/7h]%s", FormatFingerprint(fp), want)
	key, origin, err = ParseKeySource(account, params)
	require.NoError(t, err)
	require.Equal(t, want.String(), key.String())
	require.Equal(t, wantOrigin, origin)

	pub, err := want.Neuter()
	require.NoError(t, err)
	_, _, err = ParseKeySource(
		fmt.Sprintf(
			"[%s/9000h/7h]%s", FormatFingerprint(fp), pub,
		),
		params,
	)
	require.ErrorIs(t, err, ErrAccountKeyPublic)

	_, _, err = ParseKeySource(root.String()+"/9000h/7", params)
	require.ErrorIs(t, err, ErrBundleAccountPath)

	_, _, err = ParseKeySource(
		fmt.Sprintf(
			"[%s/9000h/8h]%s", FormatFingerprint(fp), want,
		),
		params,
	)
	require.ErrorIs(t, err, ErrBundleAccountPath)
}
