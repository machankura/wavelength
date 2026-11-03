//go:build systest

package systest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// waveSignerPassword is the watch-only wallet's password.
const waveSignerPassword = "wavesigner-systest-pw"

// accountKeyPub returns the public key at family/0/index of keys.
func accountKeyPub(t *testing.T, keys *walletdesc.AccountKeys,
	loc keychain.KeyLocator) *btcec.PublicKey {

	t.Helper()

	acct, ok := keys.Account(
		walletdesc.PurposeKeyFamily, uint32(loc.Family),
	)
	require.True(t, ok)
	branch, err := acct.Key.Derive(0)
	require.NoError(t, err)
	child, err := branch.Derive(loc.Index)
	require.NoError(t, err)
	pub, err := child.ECPubKey()
	require.NoError(t, err)

	return pub
}

// newWaveSignerFixture runs a Wavelength signer holding a fixed master
// key's keys and a watch-only lwwallet daemon signing through it, with no
// lnd anywhere. The daemon's wallet is created from the bundle the signer
// exports, full or minimal.
func newWaveSignerFixture(t *testing.T,
	minimal bool) (*directedSendFixture, *walletdesc.AccountKeys) {

	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0xc0 + i)
	}
	params := &chaincfg.RegressionNetParams
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)

	keys, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	t.Cleanup(keys.Zero)

	fixture := newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			signerKeys, err := keys.Clone()
			require.NoError(t, err)

			dir := t.TempDir()
			signer, err := signerserver.New(signerserver.Config{
				ListenAddr:  "127.0.0.1:0",
				TLSCertPath: filepath.Join(dir, "tls.cert"),
				TLSKeyPath:  filepath.Join(dir, "tls.key"),
				MacaroonPath: filepath.Join(
					dir, "signer.macaroon",
				),
				RootKeyPath: filepath.Join(dir, "macaroon.key"),
				Keys:        signerKeys,
				Params:      params,
			})
			require.NoError(t, err)
			go func() {
				_ = signer.Serve()
			}()
			t.Cleanup(signer.Stop)

			bundlePath := filepath.Join(dir, "watchonly.bundle")
			require.NoError(
				t, signerserver.WriteBundle(
					bundlePath, keys, minimal,
				),
			)
			data, err := os.ReadFile(bundlePath)
			require.NoError(t, err)
			full, split, err := walletdesc.ParseBundle(data, params)
			require.NoError(t, err)
			if split != nil {
				defer split.Zero()
			}

			remote := &walletcore.RemoteSignerConfig{
				RPCHost: signer.Addr().String(),
				MacaroonPath: filepath.Join(
					dir, "signer.macaroon",
				),
				TLSCertPath: filepath.Join(dir, "tls.cert"),
			}

			require.NoError(t, os.MkdirAll(cfg.NetworkDir(), 0o700))
			w, err := lwwallet.New(lwwallet.Config{
				WatchOnly:        full,
				WatchOnlyMinimal: split,
				RemoteSigner:     remote,
				WalletPassword:   []byte(waveSignerPassword),
				EsploraURL:       h.Harness.EsploraURL,
				ChainParams:      params,
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
					[]byte(waveSignerPassword), 0o600,
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

	return fixture, keys
}

// runWaveSignerScenario runs the W0 scenario over a Wavelength signer.
func runWaveSignerScenario(t *testing.T, minimal bool) {
	t.Helper()

	fixture, keys := newWaveSignerFixture(t, minimal)

	ownerLoc := keychain.KeyLocator{
		Family: types.VTXOOwnerKeyFamily,
		Index:  7,
	}
	ownedOutpoint := seedOwnedVTXO(t, fixture, keychain.KeyDescriptor{
		KeyLocator: ownerLoc,
		PubKey:     accountKeyPub(t, keys, ownerLoc),
	})
	requireIdentity(
		t, fixture.client,
		accountKeyPub(
			t, keys, keychain.KeyLocator{
				Family: keychain.KeyFamilyNodeKey,
			},
		),
	)

	runRemoteSignerFlows(t, fixture, ownedOutpoint)
}

// TestWaveSignerDaemon is the W0 scenario with no lnd at all: a
// Wavelength signer holds the keys and a watch-only lwwallet daemon,
// created from the signer's full bundle, signs everything through it.
func TestWaveSignerDaemon(t *testing.T) {
	ParallelN(t)

	runWaveSignerScenario(t, false)
}

// TestWaveSignerMinimalDaemon is the same with the signer's minimal
// bundle: fund keys on the Wavelength signer, authentication keys in the
// daemon.
func TestWaveSignerMinimalDaemon(t *testing.T) {
	ParallelN(t)

	runWaveSignerScenario(t, true)
}
