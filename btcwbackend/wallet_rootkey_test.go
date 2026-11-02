package btcwbackend

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/stretchr/testify/require"
)

// TestCheckWalletInvariantsRootKey checks the neutrino backend applies the
// same root-key creation rules as the seed path before touching neutrino.
func TestCheckWalletInvariantsRootKey(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	seed := make([]byte, walletcore.SeedLen)
	seed[0] = 7

	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	child, err := root.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)

	cfg := func(seed []byte, key *hdkeychain.ExtendedKey) Config {
		return Config{Config: walletcore.Config{
			Seed:           seed,
			RootKey:        key,
			WalletPassword: []byte("password"),
			ChainParams:    params,
			DBDir:          t.TempDir(),
		}}
	}

	require.NoError(t, checkWalletInvariants(cfg(nil, root)))

	err = checkWalletInvariants(cfg(seed, root))
	require.ErrorIs(t, err, walletcore.ErrSeedAndRootKey)

	err = checkWalletInvariants(cfg(nil, child))
	require.ErrorIs(t, err, walletcore.ErrInvalidRootKey)

	err = checkWalletInvariants(cfg(nil, nil))
	require.ErrorIs(t, err, ErrWalletNotFound)
}
