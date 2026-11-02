package waved

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/db"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testDescriptorPassword = "descriptor-password"

// testDescriptorRoot returns the master key of a fixed aezeed-shaped seed
// on regtest, so the mnemonic and descriptor paths can be compared.
func testDescriptorRoot(t *testing.T, seed []byte) *hdkeychain.ExtendedKey {
	t.Helper()

	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// compatibleTestMnemonic returns the first deterministic aezeed mnemonic
// whose BIP86 account path is not affected by the legacy derivation edge
// case, with its regtest master key.
func compatibleTestMnemonic(t *testing.T) (aezeed.Mnemonic,
	*hdkeychain.ExtendedKey) {

	t.Helper()

	birthday := time.Unix(1_700_000_000, 0)
	for i := 0; i < 256; i++ {
		var entropy [aezeed.EntropySize]byte
		entropy[0] = byte(i)

		cipherSeed, err := aezeed.New(
			aezeed.CipherSeedVersion, &entropy, birthday,
		)
		require.NoError(t, err)
		mnemonic, err := cipherSeed.ToMnemonic(nil)
		require.NoError(t, err)

		seed, _, err := MnemonicToSeedWithBirthday(mnemonic, nil)
		require.NoError(t, err)
		root := testDescriptorRoot(t, seed[:])

		_, err = walletdesc.Parse([]string{
			"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
		}, &chaincfg.RegressionNetParams)
		if err == nil {
			return mnemonic, root
		}
	}

	t.Fatal("no compatible mnemonic found")

	return aezeed.Mnemonic{}, nil
}

// TestValidateInitWalletSource covers the request shapes rejected before
// any wallet state is claimed.
func TestValidateInitWalletSource(t *testing.T) {
	t.Parallel()

	bundle := []byte("[00000000/1017h/1h/0h]tpub/0/*")
	tests := []struct {
		name    string
		req     *waverpc.InitWalletRequest
		remote  bool
		wantErr string
	}{
		{"mnemonic", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			},
		}, false, ""},
		{"descriptors", &waverpc.InitWalletRequest{
			Descriptors: []string{
				"tr(x)",
			}, BirthdayUnix: 1,
		}, false, ""},
		{"both", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			}, Descriptors: []string{
				"tr(x)",
			},
		}, false, "mutually exclusive"},
		{"descriptors with passphrase", &waverpc.InitWalletRequest{
			Descriptors: []string{
				"tr(x)",
			},
			SeedPassphrase: []byte("pass"),
		}, false, "seed_passphrase"},
		{"birthday with mnemonic", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			}, BirthdayUnix: 5,
		}, false, "birthday_unix"},
		{"bundle with signer", &waverpc.InitWalletRequest{
			WatchOnlyBundle: bundle, BirthdayUnix: 5,
		}, true, ""},
		{"bundle without signer", &waverpc.InitWalletRequest{
			WatchOnlyBundle: bundle,
		}, false, "needs wallet.remotesigner"},
		{"mnemonic with signer", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			},
		}, true, "must be created from a watch-only bundle"},
		{"bundle and descriptors", &waverpc.InitWalletRequest{
			WatchOnlyBundle: bundle, Descriptors: []string{
				"tr(x)",
			},
		}, true, "mutually exclusive"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateInitWalletSource(tc.req, tc.remote)
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestPrepareWalletCreateInputPaths checks that a mnemonic and the
// descriptors of the same master key prepare equivalent wallets: the
// descriptor path yields the root key, the mnemonic path the seed, and both
// report the same public descriptors and fingerprint.
func TestPrepareWalletCreateInputPaths(t *testing.T) {
	t.Parallel()

	mnemonic, root := compatibleTestMnemonic(t)

	seed, birthday, err := MnemonicToSeedWithBirthday(mnemonic, nil)
	require.NoError(t, err)

	fromMnemonic, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Mnemonic:       mnemonic[:],
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer fromMnemonic.zero()

	require.Equal(t, seed[:], fromMnemonic.input.seed)
	require.Nil(t, fromMnemonic.input.rootKey)
	require.Equal(t, birthday, fromMnemonic.input.birthday)

	fromDescriptors, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Descriptors: []string{
				"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
			},
			BirthdayUnix:   1_700_000_000,
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer fromDescriptors.zero()

	require.Nil(t, fromDescriptors.input.seed)
	require.Equal(t, root.String(), fromDescriptors.input.rootKey.String())
	require.Equal(
		t, int64(1_700_000_000), fromDescriptors.input.birthday.Unix(),
	)

	require.Len(t, fromMnemonic.publicDescriptors, 2)
	require.Equal(
		t, fromMnemonic.publicDescriptors,
		fromDescriptors.publicDescriptors,
	)
	require.Equal(
		t, fromMnemonic.rootFingerprint,
		fromDescriptors.rootFingerprint,
	)
	for _, text := range fromDescriptors.publicDescriptors {
		require.NotContains(t, text, "prv")
	}

	// zero must wipe the material behind each input.
	fromMnemonic.zero()
	require.Equal(t, make([]byte, len(seed)), fromMnemonic.input.seed)
}

// TestPrepareWalletCreateInputRejects checks descriptor and birthday errors
// surface before any wallet is touched.
func TestPrepareWalletCreateInputRejects(t *testing.T) {
	t.Parallel()

	root := testDescriptorRoot(t, make([]byte, 32))
	xpub, err := root.Neuter()
	require.NoError(t, err)

	_, err = prepareWalletCreateInput(&waverpc.InitWalletRequest{
		Descriptors: []string{
			"tr(" + xpub.String() + "/86h/0h/0h/0/*)",
		},
		WalletPassword: []byte(testDescriptorPassword),
	}, "regtest")
	require.ErrorIs(t, err, walletdesc.ErrWatchOnlyDescriptor)

	_, err = prepareWalletCreateInput(&waverpc.InitWalletRequest{
		Descriptors: []string{
			"tr(" + root.String() + "/86h/0h/0h/0/*)",
		},
		WalletPassword: []byte("short"),
	}, "regtest")
	require.ErrorContains(t, err, "at least")

	_, err = prepareWalletCreateInput(&waverpc.InitWalletRequest{
		Descriptors: []string{
			"tr(" + root.String() + "/86h/0h/0h/0/*)",
		},
		BirthdayUnix:   -1,
		WalletPassword: []byte(testDescriptorPassword),
	}, "regtest")
	require.ErrorContains(t, err, "negative")
}

// TestInitWalletRejectsMixedSourceWithoutClaimingState checks that a
// request mixing mnemonic and descriptors is refused with InvalidArgument
// and leaves the wallet state machine where it was.
func TestInitWalletRejectsMixedSourceWithoutClaimingState(t *testing.T) {
	t.Parallel()

	srv := &RPCServer{server: &Server{
		cfg: &Config{
			Network: "regtest",
			DataDir: t.TempDir(),
			Wallet: &WalletConfig{
				Type: WalletTypeLwwallet,
			},
		},
		chainParams: &chaincfg.RegressionNetParams,
	}}
	srv.server.walletState.Store(int32(WalletStateNone))

	_, err := srv.InitWallet(t.Context(), &waverpc.InitWalletRequest{
		Mnemonic:       []string{"a"},
		Descriptors:    []string{"tr(x)"},
		WalletPassword: []byte(testDescriptorPassword),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(
		t, WalletStateNone,
		WalletState(
			srv.server.walletState.Load(),
		),
	)

	// A malformed descriptor claims the transition, fails, and rolls
	// back to None because no database was created.
	_, err = srv.InitWallet(t.Context(), &waverpc.InitWalletRequest{
		Descriptors:    []string{"sh(wpkh(x))"},
		WalletPassword: []byte(testDescriptorPassword),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, "unsupported descriptor")
	require.Equal(
		t, WalletStateNone,
		WalletState(
			srv.server.walletState.Load(),
		),
	)
}

// testWatchOnlyBundle renders a full text bundle for root on regtest.
func testWatchOnlyBundle(t *testing.T, root *hdkeychain.ExtendedKey) []byte {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	account := func(path ...uint32) string {
		key := root
		for _, step := range path {
			key, err = key.Derive(
				hdkeychain.HardenedKeyStart + step,
			)
			require.NoError(t, err)
		}
		pub, err := walletdesc.StandardAccountPublicKey(key, params)
		require.NoError(t, err)

		return pub.String()
	}

	lines := []string{
		"tr([" + origin + "/86h/0h/0h]" + account(86, 0, 0) +
			"/<0;1>/*)",
		"wpkh([" + origin + "/84h/0h/0h]" + account(84, 0, 0) +
			"/<0;1>/*)",
	}
	for family := uint32(0); family <= 255; family++ {
		lines = append(
			lines,
			fmt.Sprintf(
				"[%s/1017h/1h/%dh]%s/0/*", origin, family,
				account(1017, 1, family),
			),
		)
	}

	return []byte(strings.Join(lines, "\n"))
}

// TestPrepareWalletCreateInputWatchOnly checks a bundle prepares a
// watch-only creation input that reports the same public descriptors and
// fingerprint as the mnemonic of the master key it came from, and records
// the watch-only source.
func TestPrepareWalletCreateInputWatchOnly(t *testing.T) {
	t.Parallel()

	mnemonic, root := compatibleTestMnemonic(t)

	fromMnemonic, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Mnemonic:       mnemonic[:],
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer fromMnemonic.zero()

	fromBundle, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			WatchOnlyBundle: testWatchOnlyBundle(t, root),
			BirthdayUnix:    1_700_000_000,
			WalletPassword:  []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer fromBundle.zero()

	require.NotNil(t, fromBundle.input.watchOnly)
	require.Nil(t, fromBundle.input.seed)
	require.Nil(t, fromBundle.input.rootKey)
	require.Equal(t, int64(1_700_000_000),
		fromBundle.input.birthday.Unix())
	require.Equal(t, db.WalletKeySourceWatchOnly, fromBundle.source)
	require.Equal(
		t, fromMnemonic.rootFingerprint, fromBundle.rootFingerprint,
	)
	require.Equal(
		t, fromMnemonic.publicDescriptors, fromBundle.publicDescriptors,
	)
}

// TestPrepareWalletCreateInputAccountKeys checks account-level private keys
// in the descriptors field prepare an account-key creation input that
// reports the same public descriptors and fingerprint as the mnemonic of
// the master key they came from.
func TestPrepareWalletCreateInputAccountKeys(t *testing.T) {
	t.Parallel()

	mnemonic, root := compatibleTestMnemonic(t)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

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

	fromMnemonic, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Mnemonic:       mnemonic[:],
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer fromMnemonic.zero()

	fromKeys, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Descriptors: []string{
				fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)",
					origin, derive(86, 0, 0)),
				fmt.Sprintf("wpkh([%s/84h/0h/0h]%s/<0;1>/*)",
					origin, derive(84, 0, 0)),
				fmt.Sprintf("[%s/1017h/1h]%s", origin,
					derive(1017, 1)),
			},
			BirthdayUnix:   1_700_000_000,
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)

	require.NotNil(t, fromKeys.input.accountKeys)
	require.Nil(t, fromKeys.input.rootKey)
	require.Equal(t, db.WalletKeySourceAccountKeys, fromKeys.source)
	require.Equal(t, fromMnemonic.rootFingerprint, fromKeys.rootFingerprint)
	require.Equal(
		t, fromMnemonic.publicDescriptors, fromKeys.publicDescriptors,
	)

	fromKeys.zero()
	require.NotEqual(
		t, derive(86, 0, 0).String(),
		fromKeys.input.accountKeys.Accounts[0].Key.String(),
		"zero must wipe the account keys",
	)
}
