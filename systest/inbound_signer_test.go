//go:build systest

package systest

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/rpcauth"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// bakeSignerMacaroon has the daemon at rpcAddr bake a macaroon granting
// only remotesigner:generate, authorized by its admin macaroon, and writes
// it to a file.
func bakeSignerMacaroon(t *testing.T, cfg *waved.Config,
	rpcAddr string) string {

	t.Helper()

	waitForFixtureFile(t, cfg.RPC.TLSCertPath)
	waitForFixtureFile(t, cfg.RPC.MacaroonPath)
	creds, err := rpcauth.ClientTLSCredentials(cfg.RPC.TLSCertPath)
	require.NoError(t, err)
	macaroonOpt, err := rpcauth.DialOptionFromFile(cfg.RPC.MacaroonPath)
	require.NoError(t, err)
	conn, err := grpc.NewClient(
		rpcAddr, grpc.WithTransportCredentials(creds), macaroonOpt,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, conn.Close())
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	resp, err := waverpc.NewMacaroonServiceClient(conn).BakeMacaroon(
		ctx, &waverpc.BakeMacaroonRequest{
			Permissions: []*waverpc.MacaroonPermission{{
				Entity: "remotesigner",
				Action: "generate",
			}},
		},
	)
	require.NoError(t, err)

	data, err := hex.DecodeString(resp.GetMacaroon())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "remotesigner.macaroon")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

// TestWaveSignerInboundDaemon runs the remote-signer scenario with the
// connection reversed: the daemon runs with
// wallet.remotesigner.allowinbound and a Wavelength signer with no listener
// dials the daemon's RPC port, authenticated by a macaroon granting only
// remotesigner:generate. The daemon's auto-unlock waits for the signer and
// probes every slot over the inbound stream before the wallet is ready.
// The fixture restarts the daemon after seeding the VTXO, so the signer
// also reconnects to a relaunched daemon.
func TestWaveSignerInboundDaemon(t *testing.T) {
	ParallelN(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0xa0 + i)
	}
	params := &chaincfg.RegressionNetParams
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	keys, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	t.Cleanup(keys.Zero)

	var daemonCfg *waved.Config
	setup := func(h *SysTestHarness, cfg *waved.Config) {
		daemonCfg = cfg

		// Create the watch-only wallet through a listening signer,
		// as InitWallet would; the daemon reopens it inbound.
		remote := startManifestSigner(t, keys)
		text, err := walletdesc.FormatBundle(keys, false)
		require.NoError(t, err)
		bundle, _, err := walletdesc.ParseBundle(text, params)
		require.NoError(t, err)

		require.NoError(t, os.MkdirAll(cfg.NetworkDir(), 0o700))
		w, err := lwwallet.New(lwwallet.Config{
			WatchOnly:      bundle,
			RemoteSigner:   remote,
			WalletPassword: []byte(waveSignerPassword),
			EsploraURL:     h.Harness.EsploraURL,
			ChainParams:    params,
			PollInterval:   time.Second,
			DBDir:          cfg.NetworkDir(),
		})
		require.NoError(t, err)
		require.NoError(t, w.Start())
		w.Stop()

		passwordFile := filepath.Join(t.TempDir(), "password")
		require.NoError(
			t,
			os.WriteFile(
				passwordFile, []byte(waveSignerPassword), 0o600,
			),
		)

		securityDir := filepath.Join(cfg.DataDir, "data", cfg.Network)
		cfg.RPC.NoTLS = false
		cfg.RPC.NoMacaroons = false
		cfg.RPC.TLSCertPath = filepath.Join(securityDir, "tls.cert")
		cfg.RPC.TLSKeyPath = filepath.Join(securityDir, "tls.key")
		cfg.RPC.MacaroonPath = filepath.Join(
			securityDir, "admin.macaroon",
		)

		cfg.Wallet.Type = waved.WalletTypeLwwallet
		cfg.Wallet.EsploraURL = h.Harness.EsploraURL
		cfg.Wallet.PollInterval = time.Second
		cfg.Wallet.PasswordFile = passwordFile
		cfg.Wallet.RemoteSigner = waved.RemoteSignerConfig{
			Enable:       true,
			AllowInbound: true,
			Timeout:      time.Minute,
		}
	}

	afterListen := func(rpcAddr string) {
		macaroonPath := bakeSignerMacaroon(t, daemonCfg, rpcAddr)

		signerKeys, err := keys.Clone()
		require.NoError(t, err)
		signer, err := signerserver.New(signerserver.Config{
			Keys:   signerKeys,
			Params: params,
		})
		require.NoError(t, err)
		t.Cleanup(signer.Stop)
		require.Nil(t, signer.Addr())

		require.NoError(
			t,
			signer.ConnectWatchOnly(
				t.Context(), signerserver.WatchOnlyConfig{
					RPCHost:      rpcAddr,
					MacaroonPath: macaroonPath,
					TLSCertPath:  daemonCfg.RPC.TLSCertPath,
				},
			),
		)
	}

	fixture := newDirectedSendFixtureWithHooks(t, setup, afterListen)

	requireIdentity(
		t, fixture.client,
		accountKeyPub(
			t, keys, keychain.KeyLocator{
				Family: keychain.KeyFamilyNodeKey,
			},
		),
	)

	ownerLoc := keychain.KeyLocator{
		Family: types.VTXOOwnerKeyFamily,
		Index:  7,
	}
	ownedOutpoint := seedOwnedVTXO(t, fixture, keychain.KeyDescriptor{
		KeyLocator: ownerLoc,
		PubKey:     accountKeyPub(t, keys, ownerLoc),
	})
	runRemoteSignerFlows(t, fixture, ownedOutpoint)
}
