package walletcore_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/stretchr/testify/require"
)

// sourceRoot returns a regtest master key from a seed byte.
func sourceRoot(t *testing.T, b byte) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// overrideSlot replaces keys' slot with root's key at path, keeping its
// real origin.
func overrideSlot(t *testing.T, keys *walletdesc.AccountKeys, purpose,
	account uint32, root *hdkeychain.ExtendedKey, path ...uint32) {

	t.Helper()

	key := root
	var origin []uint32
	for _, step := range path {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
		origin = append(origin, hdkeychain.HardenedKeyStart+step)
	}
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)

	for i, acct := range keys.Accounts {
		if acct.Purpose == purpose && acct.Account == account {
			keys.Accounts[i].Key = key
			keys.Accounts[i].Origin = &walletdesc.KeyOrigin{
				Fingerprint: fp, Path: origin,
			}
		}
	}
}

// TestProbeSignerAndManifest creates a wallet from a manifest whose
// on-chain account and families 42, 44 and 202 come from three other
// roots. The right signer passes every slot probe; a single-root signer,
// as lnd is, fails exactly the overridden slots; reopening checks the
// stored manifest, and a manifest that no longer matches is refused.
func TestProbeSignerAndManifest(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	primary := sourceRoot(t, 1)
	keys, err := walletdesc.BtcwalletAccountKeys(primary, params)
	require.NoError(t, err)
	defer keys.Zero()

	coldA := sourceRoot(t, 50)
	overrideSlot(
		t, keys, walletdesc.PurposeKeyFamily, 42, coldA, 1017, 1, 42,
	)
	overrideSlot(
		t, keys, walletdesc.PurposeKeyFamily, 202, coldA, 1017, 1, 202,
	)
	overrideSlot(
		t, keys, walletdesc.PurposeKeyFamily, 44, sourceRoot(t, 90),
		9000, 7,
	)
	overrideSlot(t, keys, 86, 0, sourceRoot(t, 130), 86, 0, 3)

	manifestText, err := walletdesc.FormatManifest(keys, params)
	require.NoError(t, err)
	manifest, err := walletdesc.ParseManifest(manifestText, params)
	require.NoError(t, err)
	authText, err := walletdesc.FormatAuthKeys(keys)
	require.NoError(t, err)
	auth, err := walletdesc.ParseAuthKeys(authText, params)
	require.NoError(t, err)
	defer auth.Zero()
	minimal, err := manifest.MinimalBundle(auth, params)
	require.NoError(t, err)

	signerFor := func(keys *walletdesc.AccountKeys) *accountsigner.Signer {
		clone, err := keys.Clone()
		require.NoError(t, err)

		return accountsigner.New(clone, params)
	}

	dir := t.TempDir()
	cfg := watchOnlyConfig(params, dir, watchOnlyPassword)
	cache := blockcache.NewBlockCache(10)

	signing, err := walletcore.OpenWithSigner(
		cfg, nil, minimal, manifest, signerFor(keys), cache,
	)
	require.NoError(t, err)
	require.Equal(t, manifest.HashHex(), signing.ManifestHash)

	probes, err := walletcore.ProbeSigner(
		signing.KeyRing, signing.BtcWallet, params,
	)
	require.NoError(t, err)
	require.Len(t, probes, 6)
	for _, probe := range probes {
		require.True(t, probe.OK, probe.Slot)
	}
	signing.Conn.Stop()
	closeBtcWallet(t, signing.BtcWallet)

	// A signer deriving every slot from the primary root, as an lnd
	// signer would, fails the overridden slots and only those.
	singleRoot, err := walletdesc.BtcwalletAccountKeys(primary, params)
	require.NoError(t, err)
	defer singleRoot.Zero()

	wrong, err := walletcore.OpenWithSigner(
		watchOnlyConfig(
			params, t.TempDir(), watchOnlyPassword,
		),
		nil,
		minimal,
		manifest,
		signerFor(singleRoot),
		cache,
	)
	require.NoError(t, err)
	probes, err = walletcore.ProbeSigner(
		wrong.KeyRing, wrong.BtcWallet, params,
	)
	require.ErrorIs(t, err, walletcore.ErrSlotProbeFailed)
	failed := make(map[string]bool)
	for _, probe := range probes {
		failed[probe.Slot] = !probe.OK
	}
	require.Equal(t, map[string]bool{
		"onchain": true, "6": false, "42": true, "44": true,
		"45": false, "202": true,
	}, failed)
	wrong.Conn.Stop()
	closeBtcWallet(t, wrong.BtcWallet)

	// Reopening checks the stored manifest and reports its hash.
	reopened, err := walletcore.OpenWithSigner(
		cfg, nil, nil, nil, signerFor(keys), cache,
	)
	require.NoError(t, err)
	require.Equal(t, manifest.HashHex(), reopened.ManifestHash)

	// A stored manifest the accounts no longer match is refused.
	otherText, err := walletdesc.FormatManifest(singleRoot, params)
	require.NoError(t, err)
	require.NoError(
		t,
		accountsigner.StoreManifest(
			reopened.BtcWallet.InternalWallet().Database(),
			otherText,
		),
	)
	reopened.Conn.Stop()
	closeBtcWallet(t, reopened.BtcWallet)

	_, err = walletcore.OpenWithSigner(
		cfg, nil, nil, nil, signerFor(keys), cache,
	)
	require.ErrorIs(t, err, walletcore.ErrManifestMismatch)
}
