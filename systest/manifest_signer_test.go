//go:build systest

package systest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// manifestSystestRoot returns a fixed master key, distinct per first byte.
func manifestSystestRoot(t *testing.T, first byte) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = first + byte(i)
	}
	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// overriddenSignerKeys returns a primary root's account keys with the
// on-chain account and families 42, 44 and 202 filled from three other
// roots, as `wavesigner create --override SLOT=FILE` does with
// XPRV/path key sources.
func overriddenSignerKeys(t *testing.T) *walletdesc.AccountKeys {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	keys, err := walletdesc.BtcwalletAccountKeys(
		manifestSystestRoot(t, 0xc0), params,
	)
	require.NoError(t, err)

	override := func(slot string, root *hdkeychain.ExtendedKey,
		path string) {

		key, origin, err := walletdesc.ParseKeySource(
			root.String()+path, params,
		)
		require.NoError(t, err)
		require.NoError(
			t, walletdesc.ApplyOverride(keys, slot, key, origin),
		)
	}

	cold := manifestSystestRoot(t, 0x10)
	override("onchain", manifestSystestRoot(t, 0x40), "/86h/0h/5h")
	override("42", cold, "/1017h/1h/42h")
	override("202", cold, "/1017h/1h/202h")
	override("44", manifestSystestRoot(t, 0x70), "/9000h/44h")

	return keys
}

// startManifestSigner runs a Wavelength signer over keys and returns the
// remote signer config a watch-only wallet dials it with.
func startManifestSigner(t *testing.T,
	keys *walletdesc.AccountKeys) *walletcore.RemoteSignerConfig {

	t.Helper()

	signerKeys, err := keys.Clone()
	require.NoError(t, err)

	dir := t.TempDir()
	signer, err := signerserver.New(signerserver.Config{
		ListenAddr:   "127.0.0.1:0",
		TLSCertPath:  filepath.Join(dir, "tls.cert"),
		TLSKeyPath:   filepath.Join(dir, "tls.key"),
		MacaroonPath: filepath.Join(dir, "signer.macaroon"),
		RootKeyPath:  filepath.Join(dir, "macaroon.key"),
		Keys:         signerKeys,
		Params:       &chaincfg.RegressionNetParams,
	})
	require.NoError(t, err)
	go func() {
		_ = signer.Serve()
	}()
	t.Cleanup(signer.Stop)

	return &walletcore.RemoteSignerConfig{
		RPCHost:      signer.Addr().String(),
		MacaroonPath: filepath.Join(dir, "signer.macaroon"),
		TLSCertPath:  filepath.Join(dir, "tls.cert"),
	}
}

// manifestExport is what a signer with overrides hands a watch-only
// daemon: the public manifest and the authentication keys file.
type manifestExport struct {
	manifest []byte
	authKeys []byte
}

// exportManifest writes keys' manifest and authentication keys the way
// `wavesigner export-watchonly --manifest-out --auth-keys-out` does and
// reads both back.
func exportManifest(t *testing.T, keys *walletdesc.AccountKeys) manifestExport {
	t.Helper()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "wallet.manifest")
	authPath := filepath.Join(dir, "auth.keys")
	require.NoError(
		t, signerserver.WriteManifest(
			manifestPath, authPath, keys,
			&chaincfg.RegressionNetParams,
		),
	)

	manifest, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	authKeys, err := os.ReadFile(authPath)
	require.NoError(t, err)

	return manifestExport{manifest: manifest, authKeys: authKeys}
}

// newManifestWallet creates a watch-only lwwallet in dbDir from export
// exactly as the daemon's InitWallet does for watch_only_manifest, and
// returns it unstarted with the parsed manifest.
func newManifestWallet(t *testing.T, export manifestExport, dbDir,
	esploraURL string,
	remote *walletcore.RemoteSignerConfig) (*lwwallet.Wallet,
	*walletdesc.Manifest) {

	t.Helper()

	params := &chaincfg.RegressionNetParams
	manifest, err := walletdesc.ParseManifest(export.manifest, params)
	require.NoError(t, err)
	require.NoError(t, manifest.CheckIdentity(false, params))

	auth, err := walletdesc.ParseAuthKeys(export.authKeys, params)
	require.NoError(t, err)
	defer auth.Zero()
	minimal, err := manifest.MinimalBundle(auth, params)
	require.NoError(t, err)
	defer minimal.Zero()

	require.NoError(t, os.MkdirAll(dbDir, 0o700))
	w, err := lwwallet.New(lwwallet.Config{
		WatchOnlyMinimal:  minimal,
		WatchOnlyManifest: manifest,
		RemoteSigner:      remote,
		WalletPassword:    []byte(waveSignerPassword),
		EsploraURL:        esploraURL,
		ChainParams:       params,
		PollInterval:      time.Second,
		DBDir:             dbDir,
	})
	require.NoError(t, err)

	return w, manifest
}

// requireSlotKeys checks w derives, for every fund family, the index-0 key
// of the signer's slot, overridden or not.
func requireSlotKeys(t *testing.T, w *lwwallet.Wallet,
	keys *walletdesc.AccountKeys) {

	t.Helper()

	for _, family := range keyfamily.Families(keyfamily.Funds) {
		loc := keychain.KeyLocator{Family: family}
		desc, err := w.DeriveKey(t.Context(), loc)
		require.NoError(t, err)
		require.True(
			t, accountKeyPub(t, keys, loc).IsEqual(desc.PubKey),
			fmt.Sprintf("family %d", family),
		)
	}
}

// TestManifestSignerDaemon runs the remote-signer scenario on a wallet
// whose on-chain account and families 42, 44 and 202 come from three keys
// other than the primary root: a Wavelength signer holds all four sources,
// and a watch-only lwwallet daemon is created from the manifest and
// authentication keys the signer exports.
//
// Before the daemon starts, a signer holding only the primary root's keys
// must be refused for exactly the overridden slots. After the scenario, a
// fresh wallet restored from the same manifest must derive the same slot
// keys and report the same manifest hash.
func TestManifestSignerDaemon(t *testing.T) {
	ParallelN(t)

	keys := overriddenSignerKeys(t)
	t.Cleanup(keys.Zero)
	export := exportManifest(t, keys)

	var (
		manifestHash string
		esploraURL   string
	)
	fixture := newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			esploraURL = h.Harness.EsploraURL

			// A signer without the overriding keys: the wallet is
			// created, but its first start probes every slot.
			primary, err := walletdesc.BtcwalletAccountKeys(
				manifestSystestRoot(t, 0xc0),
				&chaincfg.RegressionNetParams,
			)
			require.NoError(t, err)
			wrong := startManifestSigner(t, primary)
			primary.Zero()

			w, manifest := newManifestWallet(
				t, export, cfg.NetworkDir(), esploraURL, wrong,
			)
			err = w.Start()
			require.ErrorIs(t, err, walletcore.ErrSlotProbeFailed)
			for _, slot := range []string{
				"onchain", "42", "44", "202",
			} {
				require.ErrorContains(t, err, slot)
			}
			require.NotContains(t, err.Error(), "6 (")

			// A failed Start already closed the database.
			w.StopRemoteSigner()
			manifestHash = manifest.HashHex()

			// The daemon opens the same database with the signer
			// that holds every slot.
			remote := startManifestSigner(t, keys)
			passwordFile := filepath.Join(t.TempDir(), "password")
			require.NoError(
				t,
				os.WriteFile(
					passwordFile,
					[]byte(waveSignerPassword), 0o600,
				),
			)

			cfg.Wallet.Type = waved.WalletTypeLwwallet
			cfg.Wallet.EsploraURL = esploraURL
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

	// The daemon reports the manifest it runs on and keeps the primary
	// root's identity.
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	info, err := fixture.client.GetInfo(ctx, &waverpc.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, manifestHash, info.GetManifestHash())
	requireIdentity(
		t, fixture.client,
		accountKeyPub(
			t, keys, keychain.KeyLocator{
				Family: keychain.KeyFamilyNodeKey,
			},
		),
	)

	// The VTXO is owned by the overridden family 44, and boarding uses
	// the overridden family 42.
	ownerLoc := keychain.KeyLocator{
		Family: types.VTXOOwnerKeyFamily,
		Index:  7,
	}
	ownedOutpoint := seedOwnedVTXO(t, fixture, keychain.KeyDescriptor{
		KeyLocator: ownerLoc,
		PubKey:     accountKeyPub(t, keys, ownerLoc),
	})
	runRemoteSignerFlows(t, fixture, ownedOutpoint)

	// Restore: a fresh wallet from the same manifest and authentication
	// keys passes the probe and derives the slot keys the daemon used.
	restored, manifest := newManifestWallet(
		t, export, t.TempDir(), esploraURL,
		startManifestSigner(t, keys),
	)
	require.NoError(t, restored.Start())
	defer restored.Stop()
	require.Equal(t, manifestHash, manifest.HashHex())
	requireSlotKeys(t, restored, keys)
}
