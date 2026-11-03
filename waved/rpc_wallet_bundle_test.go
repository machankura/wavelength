//go:build !test_postgres

package waved

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestExportWatchOnlyBundle exports a seed wallet's full and minimal
// bundles, authorized by its mnemonic or by account keys of the same root,
// and checks the refusals.
func TestExportWatchOnlyBundle(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	esplora := newDescriptorTestEsplora(t)
	mnemonic, root := compatibleTestMnemonic(t)
	seed, birthday, err := MnemonicToSeedWithBirthday(mnemonic, nil)
	require.NoError(t, err)

	server := startDescriptorTestWallet(t, esplora.URL, walletCreateInput{
		seed: seed[:], birthday: birthday,
	})
	ctx := t.Context()

	info, err := server.GetInfo(ctx, &waverpc.GetInfoRequest{})
	require.NoError(t, err)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)

	// The full bundle holds public keys only and names the wallet's
	// identity.
	full, err := server.ExportWatchOnlyBundle(
		ctx, &waverpc.ExportWatchOnlyBundleRequest{
			Mnemonic: mnemonic[:],
		},
	)
	require.NoError(t, err)
	require.False(t, full.GetMinimal())
	require.Equal(t, FormatFingerprint(fp), full.GetRootFingerprint())
	require.NotContains(t, full.GetBundle(), "prv")

	bundle, minimal, err := walletdesc.ParseBundle(
		[]byte(
			full.GetBundle(),
		),
		params,
	)
	require.NoError(t, err)
	require.Nil(t, minimal)
	identity, err := bundle.IdentityKey()
	require.NoError(t, err)
	identityPub, err := identity.ECPubKey()
	require.NoError(t, err)
	require.Equal(
		t, info.GetIdentityPubkey(),
		fmt.Sprintf(
			"%x", identityPub.SerializeCompressed(),
		),
	)

	// The minimal bundle carries the authentication keys.
	split, err := server.ExportWatchOnlyBundle(
		ctx, &waverpc.ExportWatchOnlyBundleRequest{
			Mnemonic: mnemonic[:], Minimal: true,
		},
	)
	require.NoError(t, err)
	require.True(t, split.GetMinimal())
	_, minimal, err = walletdesc.ParseBundle(
		[]byte(
			split.GetBundle(),
		),
		params,
	)
	require.NoError(t, err)
	require.NotNil(t, minimal)
	minimal.Zero()

	// Account keys of the same root authorize the export too.
	derive := func(path ...uint32) *hdkeychain.ExtendedKey {
		key := root
		for _, step := range path {
			key, err = key.Derive(
				hdkeychain.HardenedKeyStart + step,
			)
			require.NoError(t, err)
		}

		return key
	}
	origin := FormatFingerprint(fp)
	accountKeys := []string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			derive(86, 0, 0)),
		fmt.Sprintf("wpkh([%s/84h/0h/0h]%s/<0;1>/*)", origin,
			derive(84, 0, 0)),
		fmt.Sprintf("[%s/1017h/1h]%s", origin, derive(1017, 1)),
	}
	fromKeys, err := server.ExportWatchOnlyBundle(
		ctx, &waverpc.ExportWatchOnlyBundleRequest{
			Descriptors: accountKeys,
		},
	)
	require.NoError(t, err)
	require.Equal(t, full.GetBundle(), fromKeys.GetBundle())

	// Missing, mixed or foreign seed material is refused.
	otherMnemonic, err := GenerateSeed(nil)
	require.NoError(t, err)
	for _, req := range []*waverpc.ExportWatchOnlyBundleRequest{
		{},
		{
			Mnemonic:    mnemonic[:],
			Descriptors: accountKeys,
		},
		{
			SeedPassphrase: []byte("p"),
			Descriptors:    accountKeys,
		},
		{
			Mnemonic: otherMnemonic[:],
		},
	} {
		_, err := server.ExportWatchOnlyBundle(ctx, req)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}
