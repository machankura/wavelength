package walletcore_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// watchOnlyPassword is the user password of the test watch-only wallets.
var watchOnlyPassword = []byte("watch-only-test-password")

// seedSigner is a seed wallet standing in for a remote signer: its key
// ring signs and its accounts are exported as a bundle.
type seedSigner struct {
	wallet *wallet.Wallet
	ring   keychain.SecretKeyRing
	root   *hdkeychain.ExtendedKey
}

// newSeedSigner creates a key-holding wallet from seed with every key
// family account provisioned, as an lnd signer has.
func newSeedSigner(t *testing.T, params *chaincfg.Params,
	seed []byte) *seedSigner {

	t.Helper()

	w, ring := createTestWallet(
		t, params, func(l *wallet.Loader) (*wallet.Wallet, error) {
			return l.CreateNewWallet(
				walletcore.PublicWalletPassphrase, testPrivPass,
				seed, time.Unix(1_700_000_000, 0),
			)
		},
	)

	scope, err := w.AddrManager().FetchScopedKeyManager(familyScope(params))
	require.NoError(t, err)
	require.NoError(t, w.InitAccounts(scope, false, 255))

	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)

	return &seedSigner{wallet: w, ring: ring, root: root}
}

// familyScope returns lnd's key family scope for params.
func familyScope(params *chaincfg.Params) waddrmgr.KeyScope {
	return waddrmgr.KeyScope{
		Purpose: keychain.BIP0043Purpose,
		Coin:    walletcore.CoinTypeForNet(params),
	}
}

// bundle exports the signer's account public keys in the text bundle form
// and parses it back.
func (s *seedSigner) bundle(t *testing.T,
	params *chaincfg.Params) *walletdesc.WatchOnlyBundle {

	t.Helper()

	fp, err := walletdesc.Fingerprint(s.root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	accountKey := func(scope waddrmgr.KeyScope,
		account uint32) *hdkeychain.ExtendedKey {

		props, err := s.wallet.AccountProperties(scope, account)
		require.NoError(t, err)
		key, err := walletdesc.StandardAccountPublicKey(
			props.AccountPubKey, params,
		)
		require.NoError(t, err)

		return key
	}

	lines := []string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			accountKey(waddrmgr.KeyScopeBIP0086, 0)),
		fmt.Sprintf("wpkh([%s/84h/0h/0h]%s/<0;1>/*)", origin,
			accountKey(waddrmgr.KeyScopeBIP0084, 0)),
	}
	scope := familyScope(params)
	for family := uint32(0); family <= 255; family++ {
		lines = append(
			lines,
			fmt.Sprintf(
				"[%s/1017h/%dh/%dh]%s/0/*", origin, scope.Coin,
				family, accountKey(scope, family),
			),
		)
	}

	bundle, err := walletdesc.ParseWatchOnlyBundle(
		[]byte(
			strings.Join(lines, "\n"),
		),
		params,
	)
	require.NoError(t, err)

	return bundle
}

// watchOnlyConfig returns a btcwallet config for a watch-only wallet in dir.
func watchOnlyConfig(params *chaincfg.Params, dir string,
	password []byte) btcwallet.Config {

	return btcwallet.Config{
		PublicPass: password,
		NetParams:  params,
		CoinType:   walletcore.CoinTypeForNet(params),
		LoaderOptions: []btcwallet.LoaderOption{
			btcwallet.LoaderWithLocalWalletDB(
				dir, false, time.Minute,
			),
		},
	}
}

// closeBtcWallet releases a wallet that was never started.
func closeBtcWallet(t *testing.T, btcw *btcwallet.BtcWallet) {
	t.Helper()

	require.NoError(t, btcw.InternalWallet().Database().Close())
}

// TestWatchOnlyWalletFillsEmptyScopes checks that a wallet created from a
// bundle holds account 0 in every default on-chain scope, which btcwallet's
// recovery reads on every sync, and that only scopes the bundle left empty
// get a placeholder. Descriptor export finds an account by the name "default",
// so a placeholder must not answer to it.
func TestWatchOnlyWalletFillsEmptyScopes(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	signer := newSeedSigner(t, params, testSeed())
	full := signer.bundle(t, params)

	withoutWpkh := *full
	withoutWpkh.Accounts = slices.DeleteFunc(
		slices.Clone(full.Accounts),
		func(a walletdesc.WatchOnlyAccount) bool {
			return a.Purpose == waddrmgr.KeyScopeBIP0084.Purpose
		},
	)

	tests := []struct {
		name        string
		bundle      *walletdesc.WatchOnlyBundle
		placeholder []waddrmgr.KeyScope
		real        []waddrmgr.KeyScope
	}{{
		name:   "with wpkh",
		bundle: full,
		placeholder: []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0049Plus,
		},
		real: []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScopeBIP0086,
		},
	}, {
		name:   "without wpkh",
		bundle: &withoutWpkh,
		placeholder: []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0084,
		},
		real: []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0086,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			btcw, err := walletcore.NewWatchOnlyBtcWallet(
				watchOnlyConfig(
					params, t.TempDir(), watchOnlyPassword,
				),
				test.bundle,
				blockcache.NewBlockCache(10),
			)
			require.NoError(t, err)
			defer closeBtcWallet(t, btcw)

			w := btcw.InternalWallet()
			for _, scope := range test.placeholder {
				props, err := w.AccountProperties(scope, 0)
				require.NoError(t, err)
				require.NotEqual(
					t, "default", props.AccountName,
				)

				_, err = btcw.ListAccounts("default", &scope)
				require.Error(t, err)
			}
			for _, scope := range test.real {
				props, err := w.AccountProperties(scope, 0)
				require.NoError(t, err)
				require.Equal(t, "default", props.AccountName)

				accounts, err := btcw.ListAccounts(
					"default", &scope,
				)
				require.NoError(t, err)
				require.Len(t, accounts, 1)
			}
		})
	}
}

// TestWatchOnlyWalletMatchesSigner proves a watch-only wallet built from a
// signer's exported accounts derives the signer's keys and addresses, that
// it satisfies the account setup btcwallet runs on start, and that it
// reopens under the same password and refuses another.
func TestWatchOnlyWalletMatchesSigner(t *testing.T) {
	t.Parallel()

	for name, params := range map[string]*chaincfg.Params{
		"regtest": &chaincfg.RegressionNetParams,
		"mainnet": &chaincfg.MainNetParams,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signer := newSeedSigner(t, params, testSeed())
			dir := t.TempDir()
			cfg := watchOnlyConfig(params, dir, watchOnlyPassword)

			btcw, err := walletcore.NewWatchOnlyBtcWallet(
				cfg, signer.bundle(t, params),
				blockcache.NewBlockCache(10),
			)
			require.NoError(t, err)

			w, ok := btcw.InternalWallet().(*wallet.Wallet)
			require.True(t, ok)
			require.True(t, w.AddrManager().WatchOnly())

			// btcwallet.Start ensures every key family account
			// exists, which must not need the master key the wallet
			// does not have. It would also add a missing default
			// scope, but creation already filled them all.
			scope, err := w.AddrManager().FetchScopedKeyManager(
				familyScope(params),
			)
			require.NoError(t, err)
			require.NoError(t, w.InitAccounts(scope, false, 255))

			ring := keychain.NewBtcWalletKeyRing(
				w, walletcore.CoinTypeForNet(params),
			)
			for _, family := range testFamilies {
				for _, index := range testIndexes {
					loc := keychain.KeyLocator{
						Family: family,
						Index:  index,
					}
					want, err := signer.ring.DeriveKey(loc)
					require.NoError(t, err)
					got, err := ring.DeriveKey(loc)
					require.NoError(t, err)
					require.True(
						t,
						want.PubKey.IsEqual(got.PubKey),
						"family %d index %d", family,
						index,
					)
				}
			}

			// Addresses need a chain client to issue, so compare
			// what they are built from: each on-chain account's key
			// and address schema.
			for _, chainScope := range testChainScopes {
				want, err := signer.wallet.AccountProperties(
					chainScope, 0,
				)
				require.NoError(t, err)
				got, err := w.AccountProperties(chainScope, 0)
				require.NoError(t, err)

				wantKey, err := walletdesc.
					StandardAccountPublicKey(
						want.AccountPubKey, params,
					)
				require.NoError(t, err)
				require.Equal(
					t, wantKey.String(),
					got.AccountPubKey.String(),
				)
				require.Equal(t, "default", got.AccountName)
				require.Equal(
					t, waddrmgr.ScopeAddrMap[chainScope],
					*got.AddrSchema,
				)
			}
			closeBtcWallet(t, btcw)

			// Reopen with the password, then refuse another.
			btcw, err = walletcore.NewWatchOnlyBtcWallet(
				cfg, nil, blockcache.NewBlockCache(10),
			)
			require.NoError(t, err)
			closeBtcWallet(t, btcw)

			_, err = walletcore.NewWatchOnlyBtcWallet(
				watchOnlyConfig(
					params, dir, []byte("wrong"),
				),
				nil,
				blockcache.NewBlockCache(10),
			)
			require.Error(t, err)

			// Opening with no database never creates one.
			_, err = walletcore.NewWatchOnlyBtcWallet(
				watchOnlyConfig(
					params, t.TempDir(), watchOnlyPassword,
				),
				nil,
				blockcache.NewBlockCache(10),
			)
			require.ErrorContains(t, err, "no watch-only wallet")
		})
	}
}

// fakeSignerConn answers the remote signer's SignMessage call from a seed
// wallet's key ring.
type fakeSignerConn struct {
	rpcwallet.RemoteSignerConnection

	ring keychain.MessageSignerRing
}

// RequestTimeout bounds each request.
func (f *fakeSignerConn) RequestTimeout() time.Duration {
	return time.Second
}

// SignMessage signs with the seed wallet's key at the requested locator.
func (f *fakeSignerConn) SignMessage(_ context.Context,
	in *signrpc.SignMessageReq, _ ...grpc.CallOption) (
	*signrpc.SignMessageResp, error) {

	sig, err := f.ring.SignMessageSchnorr(
		keychain.KeyLocator{
			Family: keychain.KeyFamily(in.KeyLoc.KeyFamily),
			Index:  uint32(in.KeyLoc.KeyIndex),
		},
		in.Msg, in.DoubleHash, in.SchnorrSigTapTweak, in.Tag,
	)
	if err != nil {
		return nil, err
	}

	return &signrpc.SignMessageResp{Signature: sig.Serialize()}, nil
}

// TestVerifyRemoteSigner checks the start-up challenge passes against the
// signer the bundle came from and fails against any other.
func TestVerifyRemoteSigner(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	signer := newSeedSigner(t, params, testSeed())

	otherSeed := testSeed()
	otherSeed[0] ^= 0xff
	other := newSeedSigner(t, params, otherSeed)

	btcw, err := walletcore.NewWatchOnlyBtcWallet(
		watchOnlyConfig(
			params, t.TempDir(), watchOnlyPassword,
		),
		signer.bundle(t, params),
		blockcache.NewBlockCache(10),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeBtcWallet(t, btcw)
	})

	coinType := walletcore.CoinTypeForNet(params)
	ring, err := walletcore.NewRemoteKeyRing(
		btcw, coinType, &fakeSignerConn{
			ring: signer.ring,
		}, params,
	)
	require.NoError(t, err)
	require.NoError(t, walletcore.VerifyRemoteSigner(ring))

	wrong, err := walletcore.NewRemoteKeyRing(
		btcw, coinType, &fakeSignerConn{
			ring: other.ring,
		}, params,
	)
	require.NoError(t, err)
	require.ErrorIs(
		t, walletcore.VerifyRemoteSigner(wrong),
		walletcore.ErrWrongRemoteSigner,
	)
}

// TestValidateWalletSource pins which creation inputs combine: a bundle
// creates a remote-signing wallet, needs a signer, and never mixes with a
// seed or root key; a signer alone opens an existing watch-only wallet.
func TestValidateWalletSource(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	remote := &walletcore.RemoteSignerConfig{}

	create, err := walletcore.ValidateWalletSource(
		nil, nil, true, nil, remote, params,
	)
	require.NoError(t, err)
	require.True(t, create)

	create, err = walletcore.ValidateWalletSource(
		nil, nil, false, nil, remote, params,
	)
	require.NoError(t, err)
	require.False(t, create)

	_, err = walletcore.ValidateWalletSource(
		testSeed(), nil, true, nil, remote, params,
	)
	require.ErrorIs(t, err, walletcore.ErrBundleAndSeed)

	_, err = walletcore.ValidateWalletSource(
		nil, nil, true, nil, nil, params,
	)
	require.ErrorContains(t, err, "needs a remote signer")

	_, err = walletcore.ValidateWalletSource(
		testSeed(), nil, false, nil, remote, params,
	)
	require.ErrorContains(t, err, "created from a watch-only bundle")
}
