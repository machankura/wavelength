//go:build systest

package systest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/harness"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/stretchr/testify/require"
)

// minimalBundlePassword is the wallet password of the split-signing wallet.
const minimalBundlePassword = "minimal-bundle-systest-pw"

// lndRoot returns the master key an lnd wallet created from mnemonic
// derives from: the aezeed entropy itself is its HD seed.
func lndRoot(t *testing.T, mnemonic []string) *hdkeychain.ExtendedKey {
	t.Helper()

	var words aezeed.Mnemonic
	require.Len(t, mnemonic, len(words))
	copy(words[:], mnemonic)

	seed, err := words.ToCipherSeed(nil)
	require.NoError(t, err)
	root, err := hdkeychain.NewMaster(
		seed.Entropy[:], &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	return root
}

// familyAccountPrivate returns the private key of family's account as the
// signer's wallet derived it. btcwallet's legacy hardened derivation can
// differ from standard BIP32, so both are tried and the one matching the
// signer's own listed xpub wins.
func familyAccountPrivate(t *testing.T, root *hdkeychain.ExtendedKey,
	family uint32, want string) *hdkeychain.ExtendedKey {

	t.Helper()

	path := []uint32{1017, 1, family}
	for _, legacy := range []bool{true, false} {
		key := root
		for _, step := range path {
			var err error
			if legacy {
				key, err = key.DeriveNonStandard(
					hdkeychain.HardenedKeyStart + step,
				)
			} else {
				key, err = key.Derive(
					hdkeychain.HardenedKeyStart + step,
				)
			}
			require.NoError(t, err)
		}

		pub, err := walletdesc.StandardAccountPublicKey(
			key, &chaincfg.RegressionNetParams,
		)
		require.NoError(t, err)
		if pub.String() == want {
			return key
		}
	}

	t.Fatalf("no derivation of family %d matches the signer", family)

	return nil
}

// minimalBundleFromSigner builds the minimal bundle a split-signing user
// would export: the signer's BIP86 account and fund family xpubs as it
// lists them, and the authentication families' private keys from the
// signer's mnemonic.
func minimalBundleFromSigner(ctx context.Context, t *testing.T,
	signer *harness.LndInstance, mnemonic []string) []byte {

	t.Helper()

	params := &chaincfg.RegressionNetParams
	listed, err := walletdesc.ParseWatchOnlyBundle(
		signerBundle(ctx, t, signer), params,
	)
	require.NoError(t, err)

	root := lndRoot(t, mnemonic)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	listedKey := func(purpose, account uint32) string {
		acct, ok := listed.Account(purpose, account)
		require.True(t, ok)

		return acct.Key.String()
	}

	lines := []string{fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
		listedKey(86, 0))}
	for _, family := range []uint32{6, 42, 44, 45, 202} {
		lines = append(
			lines,
			fmt.Sprintf(
				"[%s/1017h/1h/%dh]%s/0/*", origin, family,
				listedKey(1017, family),
			),
		)
	}
	for _, family := range []uint32{21, 43} {
		key := familyAccountPrivate(
			t, root, family, listedKey(1017, family),
		)
		lines = append(
			lines, fmt.Sprintf("[%s/1017h/1h/%dh]%s/0/*", origin,
				family, key),
		)
	}

	return []byte(strings.Join(lines, "\n"))
}

// newMinimalBundleFixture starts a full waved instance with
// wallet.type=lwwallet over a split-signing wallet: fund keys on a plain
// lnd signer, authentication keys in the daemon's keystore.
func newMinimalBundleFixture(t *testing.T) (*directedSendFixture,
	*harness.LndInstance) {

	t.Helper()

	var signer *harness.LndInstance
	fixture := newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			ctx := h.Context()

			var mnemonic []string
			signer, mnemonic = h.Harness.StartAdditionalLNDWithSeed(
				"signer",
			)

			_, minimal, err := walletdesc.ParseBundle(
				minimalBundleFromSigner(
					ctx, t, signer, mnemonic,
				),
				&chaincfg.RegressionNetParams,
			)
			require.NoError(t, err)
			require.NotNil(t, minimal)
			defer minimal.Zero()

			remote := &walletcore.RemoteSignerConfig{
				RPCHost: net.JoinHostPort(
					"localhost", signer.GRPCPort,
				),
				MacaroonPath: signer.Macaroon,
				TLSCertPath:  signer.TLSCert,
			}

			require.NoError(t, os.MkdirAll(cfg.NetworkDir(), 0o700))
			w, err := lwwallet.New(lwwallet.Config{
				WatchOnlyMinimal: minimal,
				RemoteSigner:     remote,
				WalletPassword:   []byte(minimalBundlePassword),
				EsploraURL:       h.Harness.EsploraURL,
				ChainParams:      &chaincfg.RegressionNetParams,
				PollInterval:     time.Second,
				DBDir:            cfg.NetworkDir(),
			})
			require.NoError(t, err)
			require.NoError(t, w.Start())
			w.Stop()

			passwordFile := filepath.Join(t.TempDir(), "password")
			require.NoError(
				t,
				os.WriteFile(
					passwordFile,
					[]byte(minimalBundlePassword), 0o600,
				),
			)

			cfg.Wallet.Type = waved.WalletTypeLwwallet
			cfg.Wallet.EsploraURL = h.Harness.EsploraURL
			cfg.Wallet.PollInterval = time.Second
			cfg.Wallet.PasswordFile = passwordFile
			cfg.Wallet.RemoteSigner = waved.RemoteSignerConfig{
				Enable:       true,
				RPCHost:      remote.RPCHost,
				MacaroonPath: remote.MacaroonPath,
				TLSCertPath:  remote.TLSCertPath,
			}
		},
	)

	return fixture, signer
}

// TestMinimalBundleDaemon is the W0 scenario on a split-signing wallet:
// waved runs wallet.type=lwwallet with the fund keys on an lnd signer and
// the authentication keys in its own keystore, reopened from its password
// file. Boarding signs its join authorization locally and its inputs
// remotely; the out-of-round send and the boarding exit sign remotely.
func TestMinimalBundleDaemon(t *testing.T) {
	ParallelN(t)

	fixture, signer := newMinimalBundleFixture(t)

	ownedOutpoint := seedSignerOwnedVTXO(t, fixture, signer)
	requireSignerIdentity(t, fixture.client, signer)

	runRemoteSignerFlows(t, fixture, ownedOutpoint)
}
