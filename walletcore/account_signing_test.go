package walletcore_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/require"
)

// accountPassword is the wallet password of the test account-key wallets.
var accountPassword = []byte("account-key-test-password")

// seedAccountKeys returns the account keys of seed's master key, exported
// with standard BIP32 the way other wallet software would.
func seedAccountKeys(t *testing.T, params *chaincfg.Params,
	seed []byte) *walletdesc.AccountKeys {

	t.Helper()

	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)
	coin := walletcore.CoinTypeForNet(params)

	keys, err := walletdesc.ParseAccountKeys([]string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			standardChild(t, root, 86, 0, 0)),
		fmt.Sprintf("[%s/1017h/%dh]%s", origin, coin,
			standardChild(t, root, 1017, coin)),
	}, params)
	require.NoError(t, err)

	return keys
}

// accountWalletConfig returns a btcwallet config for a wallet in dir with
// the static public passphrase, as the backends build it.
func accountWalletConfig(params *chaincfg.Params, dir string) btcwallet.Config {
	return btcwallet.Config{
		PrivatePass: accountPassword,
		PublicPass:  walletcore.PublicWalletPassphrase,
		NetParams:   params,
		CoinType:    walletcore.CoinTypeForNet(params),
		LoaderOptions: []btcwallet.LoaderOption{
			btcwallet.LoaderWithLocalWalletDB(
				dir, false, time.Minute,
			),
		},
	}
}

// requireMatchesSeedWallet checks ring derives the seed wallet's keys and
// that its signer holds them.
func requireMatchesSeedWallet(t *testing.T, ring keychain.SecretKeyRing,
	signer *seedSigner) {

	t.Helper()

	for _, family := range testFamilies {
		for _, index := range testIndexes {
			loc := keychain.KeyLocator{Family: family, Index: index}
			want, err := signer.ring.DeriveKey(loc)
			require.NoError(t, err)
			got, err := ring.DeriveKey(loc)
			require.NoError(t, err)
			require.True(
				t, want.PubKey.IsEqual(got.PubKey),
				"family %d index %d", family, index,
			)
		}
	}

	remote, ok := ring.(walletcore.RemoteKeyRing)
	require.True(t, ok)
	require.NoError(t, walletcore.VerifyRemoteSigner(remote))
}

// TestAccountKeyWallet creates a wallet from account keys and reopens it:
// its keys match a seed wallet of the same master key, the password opens
// the keystore and a wrong one does not, and the generic open path tells a
// key-holding wallet, an account-key wallet and a bare watch-only wallet
// apart.
func TestAccountKeyWallet(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	seed := testSeed()
	signer := newSeedSigner(t, params, seed)
	dir := t.TempDir()
	cache := blockcache.NewBlockCache(10)

	created, err := walletcore.CreateAccountSigning(
		accountWalletConfig(params, dir),
		seedAccountKeys(t, params, seed), accountPassword, cache,
	)
	require.NoError(t, err)
	require.NotNil(t, created.KeyRing)
	requireMatchesSeedWallet(t, created.KeyRing, signer)
	created.Conn.Stop()
	closeBtcWallet(t, created.BtcWallet)

	reopened, err := walletcore.OpenExisting(
		accountWalletConfig(params, dir), accountPassword, cache,
	)
	require.NoError(t, err)
	require.NotNil(t, reopened.KeyRing)
	requireMatchesSeedWallet(t, reopened.KeyRing, signer)
	reopened.Conn.Stop()
	closeBtcWallet(t, reopened.BtcWallet)

	_, err = walletcore.OpenExisting(
		accountWalletConfig(params, dir), []byte("wrong"), cache,
	)
	require.ErrorIs(t, err, accountsigner.ErrWrongPassword)

	// A seed wallet opens as before, signing through btcwallet.
	seedDir := t.TempDir()
	seedCfg := accountWalletConfig(params, seedDir)
	seedCfg.HdSeed = seed
	seedWallet, err := btcwallet.New(seedCfg, cache)
	require.NoError(t, err)
	closeBtcWallet(t, seedWallet)

	keyHolding, err := walletcore.OpenExisting(
		accountWalletConfig(params, seedDir), accountPassword, cache,
	)
	require.NoError(t, err)
	require.Nil(t, keyHolding.KeyRing)
	closeBtcWallet(t, keyHolding.BtcWallet)

	// A watch-only wallet without account keys needs its remote signer.
	bareDir := t.TempDir()
	bare, err := walletcore.NewWatchOnlyBtcWallet(
		accountWalletConfig(params, bareDir), signer.bundle(t, params),
		cache,
	)
	require.NoError(t, err)
	closeBtcWallet(t, bare)

	_, err = walletcore.OpenExisting(
		accountWalletConfig(params, bareDir), accountPassword, cache,
	)
	require.ErrorIs(t, err, walletcore.ErrWatchOnlyWithoutSigner)

	// A remote-signing wallet, whose public data uses the user's
	// password, says what it is missing.
	remoteDir := t.TempDir()
	remote, err := walletcore.NewWatchOnlyBtcWallet(
		watchOnlyConfig(params, remoteDir, watchOnlyPassword),
		signer.bundle(t, params), cache,
	)
	require.NoError(t, err)
	closeBtcWallet(t, remote)

	_, err = walletcore.OpenExisting(
		accountWalletConfig(params, remoteDir), watchOnlyPassword,
		cache,
	)
	require.ErrorContains(t, err, "remote signer configured")

}
