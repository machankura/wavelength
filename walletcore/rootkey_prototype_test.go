package walletcore_test

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/require"
)

var (
	prototypePrivPass = []byte("prototype-password")

	// prototypeFamilies are the key families Wavelength derives today.
	prototypeFamilies = []keychain.KeyFamily{6, 21, 42, 43, 44, 45, 202}

	// prototypeIndexes cover the first key, the next one and a far one.
	prototypeIndexes = []uint32{0, 1, 99}

	// prototypeChainScopes are the on-chain scopes the wallet watches.
	prototypeChainScopes = []waddrmgr.KeyScope{
		waddrmgr.KeyScopeBIP0086, waddrmgr.KeyScopeBIP0084,
	}
)

// prototypeSeed mirrors the daemon's aezeed seed layout: 16 bytes of
// entropy followed by 16 zero bytes.
func prototypeSeed() []byte {
	seed := make([]byte, walletcore.SeedLen)
	for i := 0; i < 16; i++ {
		seed[i] = byte(0xa0 + i)
	}

	return seed
}

// createPrototypeWallet creates and unlocks a btcwallet in its own
// temporary directory using the supplied creation function, then adds the
// lnd key scope the same way lnd's btcwallet.Start does.
func createPrototypeWallet(t *testing.T, params *chaincfg.Params,
	create func(*wallet.Loader) (*wallet.Wallet, error)) (*wallet.Wallet,
	keychain.SecretKeyRing) {

	t.Helper()

	loader, err := btcwallet.NewWalletLoader(
		params, 0,
		btcwallet.LoaderWithLocalWalletDB(
			t.TempDir(), false, time.Minute,
		),
	)
	require.NoError(t, err)

	w, err := create(loader)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = loader.UnloadWallet()
	})

	require.NoError(t, w.Unlock(prototypePrivPass, nil))

	coinType := walletcore.CoinTypeForNet(params)
	_, err = w.AddScopeManager(waddrmgr.KeyScope{
		Purpose: keychain.BIP0043Purpose,
		Coin:    coinType,
	}, waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	})
	require.NoError(t, err)

	return w, keychain.NewBtcWalletKeyRing(w, coinType)
}

// TestRootKeyWalletMatchesSeedWallet proves that a wallet created from the
// BIP32 master key derives exactly the same keys as one created from the
// seed that master key came from. This is the premise every descriptor
// import path in this package builds on.
func TestRootKeyWalletMatchesSeedWallet(t *testing.T) {
	t.Parallel()

	networks := map[string]*chaincfg.Params{
		"regtest": &chaincfg.RegressionNetParams,
		"mainnet": &chaincfg.MainNetParams,
	}

	for name, params := range networks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			seed := prototypeSeed()
			birthday := time.Unix(1_700_000_000, 0)
			pubPass := walletcore.PublicWalletPassphrase

			seedWallet, seedRing := createPrototypeWallet(
				t, params, func(l *wallet.Loader) (
					*wallet.Wallet, error) {

					return l.CreateNewWallet(
						pubPass, prototypePrivPass,
						seed, birthday,
					)
				},
			)

			rootKey, err := hdkeychain.NewMaster(seed, params)
			require.NoError(t, err)

			rootWallet, rootRing := createPrototypeWallet(
				t, params, func(l *wallet.Loader) (
					*wallet.Wallet, error) {

					return l.CreateNewWalletExtendedKey(
						pubPass, prototypePrivPass,
						rootKey, birthday,
					)
				},
			)

			// Every Ark key family must agree at every index.
			for _, family := range prototypeFamilies {
				for _, index := range prototypeIndexes {
					loc := keychain.KeyLocator{
						Family: family,
						Index:  index,
					}

					want, err := seedRing.DeriveKey(loc)
					require.NoError(t, err)

					got, err := rootRing.DeriveKey(loc)
					require.NoError(t, err)

					require.True(
						t,
						want.PubKey.IsEqual(got.PubKey),
						"family %d index %d", family,
						index,
					)
				}
			}

			// The on-chain account keys must agree, which makes
			// every address under them agree too.
			for _, scope := range prototypeChainScopes {
				want, err := seedWallet.AccountProperties(
					scope, 0,
				)
				require.NoError(t, err)

				got, err := rootWallet.AccountProperties(
					scope, 0,
				)
				require.NoError(t, err)

				require.Equal(
					t, want.AccountPubKey.String(),
					got.AccountPubKey.String(),
					"scope %v", scope,
				)

				t.Logf(
					"scope %v: master fingerprint "+
						"seed=%08x root=%08x", scope,
					want.MasterKeyFingerprint,
					got.MasterKeyFingerprint,
				)
			}

			// The offline identity derivation must agree with the
			// key ring's family 6, index 0 key.
			var rawSeed [walletcore.SeedLen]byte
			copy(rawSeed[:], seed)
			identity, err := waved.WalletIdentityPubKeyFromSeed(
				rawSeed, name,
			)
			require.NoError(t, err)

			identityKey, err := rootRing.DeriveKey(
				keychain.KeyLocator{
					Family: keychain.KeyFamilyNodeKey,
				},
			)
			require.NoError(t, err)
			require.Equal(
				t, identity,
				encodeHex(
					identityKey.PubKey.
						SerializeCompressed(),
				),
			)
		})
	}
}

// encodeHex renders bytes as lowercase hex without importing encoding/hex
// for a single call site.
func encodeHex(b []byte) string {
	const digits = "0123456789abcdef"

	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}

	return string(out)
}
