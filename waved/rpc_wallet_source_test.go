package waved

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
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

	tests := []struct {
		name    string
		req     *waverpc.InitWalletRequest
		wantErr string
	}{
		{"mnemonic", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			},
		}, ""},
		{"descriptors", &waverpc.InitWalletRequest{
			Descriptors: []string{
				"tr(x)",
			}, BirthdayUnix: 1,
		}, ""},
		{"both", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			}, Descriptors: []string{
				"tr(x)",
			},
		}, "mutually exclusive"},
		{"descriptors with passphrase", &waverpc.InitWalletRequest{
			Descriptors: []string{
				"tr(x)",
			},
			SeedPassphrase: []byte("pass"),
		}, "seed_passphrase"},
		{"birthday with mnemonic", &waverpc.InitWalletRequest{
			Mnemonic: []string{
				"a",
			}, BirthdayUnix: 5,
		}, "birthday_unix"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateInitWalletSource(tc.req)
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
