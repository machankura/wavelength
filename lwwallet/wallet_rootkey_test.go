package lwwallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestWalletCreateFromRootKey verifies that a wallet created from a BIP32
// master key behaves like one created from the seed that key came from:
// same identity key, same first taproot address. It also checks the
// root key obeys the same create/open invariants as the seed.
func TestWalletCreateFromRootKey(t *testing.T) {
	t.Parallel()

	esplora := newTestEsplora(t)
	password := []byte("rootkey-password")

	var seed [32]byte
	for i := 0; i < 16; i++ {
		seed[i] = byte(0x40 + i)
	}

	rootKey, err := hdkeychain.NewMaster(
		seed[:], &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	identityLoc := keychain.KeyLocator{
		Family: keychain.KeyFamilyNodeKey,
	}

	// Reference wallet from the seed.
	seedWallet, err := New(
		testWalletConfig(
			esplora.URL, t.TempDir(), seed[:], password,
		),
	)
	require.NoError(t, err)
	require.NoError(t, seedWallet.Start())
	t.Cleanup(seedWallet.Stop)

	wantIdentity, err := seedWallet.DeriveKey(t.Context(), identityLoc)
	require.NoError(t, err)
	wantAddr, err := seedWallet.NewAddress(t.Context())
	require.NoError(t, err)

	// Wallet from the master key, in its own directory.
	dbDir := t.TempDir()
	cfg := testWalletConfig(esplora.URL, dbDir, nil, password)
	cfg.RootKey = rootKey

	rootWallet, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, rootWallet.Start())

	gotIdentity, err := rootWallet.DeriveKey(t.Context(), identityLoc)
	require.NoError(t, err)
	require.True(t, wantIdentity.PubKey.IsEqual(gotIdentity.PubKey))

	gotAddr, err := rootWallet.NewAddress(t.Context())
	require.NoError(t, err)
	require.Equal(t, wantAddr.String(), gotAddr.String())

	rootWallet.Stop()

	// The root key must be refused over an existing database, just
	// like a seed, because btcwallet would silently ignore it.
	_, err = New(cfg)
	require.ErrorIs(t, err, ErrWalletExists)

	// Reopening needs only the password and yields the same wallet.
	reopened, err := New(
		testWalletConfig(esplora.URL, dbDir, nil, password),
	)
	require.NoError(t, err)
	require.NoError(t, reopened.Start())
	t.Cleanup(reopened.Stop)

	again, err := reopened.DeriveKey(t.Context(), identityLoc)
	require.NoError(t, err)
	require.True(t, wantIdentity.PubKey.IsEqual(again.PubKey))
}

// TestWalletRootKeyInvariants checks the inputs a root-key wallet is refused
// with before any database is touched.
func TestWalletRootKeyInvariants(t *testing.T) {
	t.Parallel()

	esplora := newTestEsplora(t)
	password := []byte("rootkey-password")
	seed := make([]byte, walletcore.SeedLen)
	seed[0] = 1

	rootKey, err := hdkeychain.NewMaster(
		seed, &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	child, err := rootKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)

	public, err := rootKey.Neuter()
	require.NoError(t, err)

	mainnet, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	tests := []struct {
		name string
		seed []byte
		key  *hdkeychain.ExtendedKey
		want error
	}{
		{
			"seed and root key",
			seed,
			rootKey,
			walletcore.ErrSeedAndRootKey,
		},
		{
			"account-level key",
			nil,
			child,
			walletcore.ErrInvalidRootKey,
		},
		{
			"public key",
			nil,
			public,
			walletcore.ErrInvalidRootKey,
		},
		{
			"other network",
			nil,
			mainnet,
			walletcore.ErrInvalidRootKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbDir := t.TempDir()
			cfg := testWalletConfig(
				esplora.URL, dbDir, tc.seed, password,
			)
			cfg.RootKey = tc.key

			_, err := New(cfg)
			require.ErrorIs(t, err, tc.want)

			exists, err := WalletExists(cfg)
			require.NoError(t, err)
			require.False(t, exists)
		})
	}
}
