package wavewalletdk

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/stretchr/testify/require"
)

// watchOnlyInputs are the exports of a signer of the descriptor test root.
type watchOnlyInputs struct {
	full, minimal, manifest, auth []byte
	identity                      string
}

// testWatchOnlyInputs returns the full bundle, minimal bundle, manifest and
// authentication keys a signer of the descriptor test root exports, and the
// identity they imply.
func testWatchOnlyInputs(t *testing.T) watchOnlyInputs {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	_, root, identity := testDescriptorWallet(t)
	keys, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	t.Cleanup(keys.Zero)

	in := watchOnlyInputs{identity: identity}
	in.full, err = walletdesc.FormatBundle(keys, false)
	require.NoError(t, err)
	in.minimal, err = walletdesc.FormatBundle(keys, true)
	require.NoError(t, err)
	in.manifest, err = walletdesc.FormatManifest(keys, params)
	require.NoError(t, err)
	in.auth, err = walletdesc.FormatAuthKeys(keys)
	require.NoError(t, err)

	return in
}

// TestWatchOnlyIdentity checks every watch-only input form implies the
// root's identity, and the request shapes that are refused.
func TestWatchOnlyIdentity(t *testing.T) {
	t.Parallel()

	in := testWatchOnlyInputs(t)
	full, minimal, manifest, auth := in.full, in.minimal, in.manifest,
		in.auth
	identity := in.identity
	password := []byte("watch-only-password")

	for _, req := range []WatchOnlyWalletRequest{
		{
			Bundle:         full,
			WalletPassword: password,
		},
		{
			Bundle:         minimal,
			WalletPassword: password,
		},
		{
			Manifest:       manifest,
			AuthKeys:       auth,
			WalletPassword: password,
		},
	} {
		got, err := watchOnlyIdentity(req, "regtest")
		require.NoError(t, err)
		require.Equal(t, identity, got)
	}

	for _, tc := range []struct {
		req  WatchOnlyWalletRequest
		want string
	}{
		{
			WatchOnlyWalletRequest{
				Bundle: full,
			},
			"wallet password",
		},
		{WatchOnlyWalletRequest{
			WalletPassword: password,
		}, "exactly one"},
		{WatchOnlyWalletRequest{
			Bundle: full, Manifest: manifest,
			WalletPassword: password,
		}, "exactly one"},
		{WatchOnlyWalletRequest{
			Manifest: manifest, WalletPassword: password,
		}, "authentication keys"},
		{WatchOnlyWalletRequest{
			Bundle: full, AuthKeys: auth, WalletPassword: password,
		}, "only used with a manifest"},
		{WatchOnlyWalletRequest{
			Bundle: []byte("junk"), WalletPassword: password,
		}, "invalid watch-only bundle"},
	} {
		_, err := watchOnlyIdentity(tc.req, "regtest")
		require.ErrorContains(t, err, tc.want)
	}
}

// TestOpenWatchOnlyWalletImport checks an empty daemon is created from the
// manifest with the host's password, and a wrong identity is refused.
func TestOpenWatchOnlyWalletImport(t *testing.T) {
	t.Parallel()

	in := testWatchOnlyInputs(t)
	manifest, auth, identity := in.manifest, in.auth, in.identity
	stub := &stubDaemonServer{
		state: waverpc.WalletState_WALLET_STATE_NONE,
		initResp: &waverpc.InitWalletResponse{
			IdentityPubkey: identity,
			ManifestHash:   "feed",
		},
	}
	client := newStubClient(t, stub)

	req := WatchOnlyWalletRequest{
		Manifest:       manifest,
		AuthKeys:       auth,
		WalletPassword: []byte("watch-only-password"),
	}
	result, err := client.openWatchOnlyWallet(t.Context(), req, identity)
	require.NoError(t, err)
	require.True(t, result.Imported)
	require.Equal(t, "feed", result.ManifestHash)
	require.Equal(t, manifest, stub.lastInitReq.GetWatchOnlyManifest())
	require.Equal(t, auth, stub.lastInitReq.GetAuthKeys())
	require.Empty(t, stub.lastInitReq.GetMnemonic())
	require.Equal(
		t, req.WalletPassword, stub.lastInitReq.GetWalletPassword(),
	)

	stub.state = waverpc.WalletState_WALLET_STATE_NONE
	_, err = client.openWatchOnlyWallet(t.Context(), req, "other")
	require.ErrorContains(t, err, "identity mismatch")
}

// TestOpenWatchOnlyWalletUnlock checks a locked daemon is unlocked with the
// host's password and reports the same details as an import would, and that
// a wrong identity is refused.
func TestOpenWatchOnlyWalletUnlock(t *testing.T) {
	t.Parallel()

	in := testWatchOnlyInputs(t)
	stub := &stubDaemonServer{
		state:          waverpc.WalletState_WALLET_STATE_LOCKED,
		unlockIdentity: in.identity,
		listDescriptorsResp: &waverpc.ListWalletDescriptorsResponse{
			RootFingerprint: "abcd0123",
			Descriptors: []string{
				"tr(tpub)",
				"wpkh(tpub)",
			},
		},
	}
	client := newStubClient(t, stub)

	req := WatchOnlyWalletRequest{
		Manifest:       in.manifest,
		AuthKeys:       in.auth,
		WalletPassword: []byte("watch-only-password"),
	}
	result, err := client.openWatchOnlyWallet(
		t.Context(), req, in.identity,
	)
	require.NoError(t, err)
	require.False(t, result.Imported)
	require.Equal(t, in.identity, result.IdentityPubKey)
	require.Equal(t, "abcd0123", result.RootFingerprint)
	require.Equal(t, []string{"tr(tpub)", "wpkh(tpub)"}, result.Descriptors)

	stub.state = waverpc.WalletState_WALLET_STATE_LOCKED
	_, err = client.openWatchOnlyWallet(t.Context(), req, "other")
	require.ErrorContains(t, err, "identity mismatch")
}

// TestStartWatchOnlyWalletNeedsRemoteSigner checks a watch-only start is
// refused before the daemon starts without a remote signer, and that
// Config.RemoteSigner reaches the daemon config.
func TestStartWatchOnlyWalletNeedsRemoteSigner(t *testing.T) {
	t.Setenv(wavedSeedEnvVar, "")
	t.Setenv(wavedPasswordEnvVar, "")

	full := testWatchOnlyInputs(t).full
	dir := t.TempDir()
	client, result, err := StartWatchOnlyWallet(
		t.Context(), Config{DataDir: dir, Network: "regtest"},
		WatchOnlyWalletRequest{
			Bundle: full, WalletPassword: []byte("pw"),
		},
	)
	require.ErrorContains(t, err, "Config.RemoteSigner")
	require.Nil(t, client)
	require.Nil(t, result)

	daemonCfg, err := daemonConfig(Config{
		Network: "regtest",
		RemoteSigner: &RemoteSignerConfig{
			RPCHost:      "127.0.0.1:10019",
			MacaroonPath: "signer.macaroon",
			TLSCertPath:  "tls.cert",
		},
	})
	require.NoError(t, err)
	require.Equal(t, waved.RemoteSignerConfig{
		Enable:       true,
		RPCHost:      "127.0.0.1:10019",
		MacaroonPath: "signer.macaroon",
		TLSCertPath:  "tls.cert",
	}, daemonCfg.Wallet.RemoteSigner)
}
