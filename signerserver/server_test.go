//go:build !(js && wasm)

package signerserver_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

var params = &chaincfg.RegressionNetParams

// signerFixture is a running signer and the paths a client needs.
type signerFixture struct {
	server       *signerserver.Server
	keys         *walletdesc.AccountKeys
	tlsCertPath  string
	macaroonPath string
}

// startSigner serves keys derived from a fixed master key.
func startSigner(t *testing.T) *signerFixture {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x70 + i)
	}
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)

	keys, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	t.Cleanup(keys.Zero)
	serverKeys, err := keys.Clone()
	require.NoError(t, err)

	dir := t.TempDir()
	cfg := signerserver.Config{
		ListenAddr:   "127.0.0.1:0",
		TLSCertPath:  filepath.Join(dir, "tls.cert"),
		TLSKeyPath:   filepath.Join(dir, "tls.key"),
		MacaroonPath: filepath.Join(dir, "signer.macaroon"),
		RootKeyPath:  filepath.Join(dir, "macaroon.key"),
		Keys:         serverKeys,
		Params:       params,
	}
	server, err := signerserver.New(cfg)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-done)
	})

	return &signerFixture{
		server:       server,
		keys:         keys,
		tlsCertPath:  cfg.TLSCertPath,
		macaroonPath: cfg.MacaroonPath,
	}
}

// dial connects lnd's remote signer client to the signer.
func (f *signerFixture) dial(t *testing.T,
	macaroonPath string) walletcore.RemoteKeyRing {

	t.Helper()

	text, err := walletdesc.FormatBundle(f.keys, false)
	require.NoError(t, err)
	bundle, _, err := walletdesc.ParseBundle(text, params)
	require.NoError(t, err)

	btcw, err := walletcore.NewWatchOnlyBtcWallet(btcwallet.Config{
		PublicPass: []byte("signer-server-test"),
		NetParams:  params,
		CoinType:   walletcore.CoinTypeForNet(params),
		LoaderOptions: []btcwallet.LoaderOption{
			btcwallet.LoaderWithLocalWalletDB(
				t.TempDir(), false, time.Minute,
			),
		},
	}, bundle, blockcache.NewBlockCache(10))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = btcw.InternalWallet().Database().Close()
	})

	remote := walletcore.RemoteSignerConfig{
		RPCHost:      f.server.Addr().String(),
		TLSCertPath:  f.tlsCertPath,
		MacaroonPath: macaroonPath,
	}
	require.NoError(t, remote.Validate())
	conn, err := walletcore.DialRemoteSigner(t.Context(), remote)
	require.NoError(t, err)
	t.Cleanup(conn.Stop)

	ring, err := walletcore.NewRemoteKeyRing(
		btcw, walletcore.CoinTypeForNet(params), conn, params,
	)
	require.NoError(t, err)

	return ring
}

// TestSignerServer drives the signer through lnd's own remote signer
// client: the identity challenge, a tagged message, a two-party MuSig2
// signature and a taproot spend the script engine accepts.
func TestSignerServer(t *testing.T) {
	t.Parallel()

	f := startSigner(t)
	ring := f.dial(t, f.macaroonPath)

	require.NoError(t, walletcore.VerifyRemoteSigner(ring))

	joinLoc := keychain.KeyLocator{Family: 43, Index: 4}
	joinKey, err := ring.DeriveKey(joinLoc)
	require.NoError(t, err)
	msg := []byte("join round")
	tag := []byte("wavelength/signer-server-test")
	sig, err := ring.SignMessageSchnorr(joinLoc, msg, false, nil, tag)
	require.NoError(t, err)
	digest := chainhash.TaggedHash(tag, msg)
	require.True(t, sig.Verify(digest[:], joinKey.PubKey))

	// MuSig2 with an independent cosigner.
	treeLoc := keychain.KeyLocator{Family: 45, Index: 2}
	treeKey, err := ring.DeriveKey(treeLoc)
	require.NoError(t, err)
	cosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signers := []*btcec.PublicKey{treeKey.PubKey, cosigner.PubKey()}

	session, err := ring.MuSig2CreateSession(
		input.MuSig2Version100RC2, treeLoc, signers,
		&input.MuSig2Tweaks{
			TaprootBIP0086Tweak: true,
		},
		nil,
		nil,
	)
	require.NoError(t, err)
	cosignerCtx, err := musig2.NewContext(
		cosigner, true, musig2.WithKnownSigners(signers),
		musig2.WithBip86TweakCtx(),
	)
	require.NoError(t, err)
	cosignerSession, err := cosignerCtx.NewSession()
	require.NoError(t, err)
	_, err = ring.MuSig2RegisterNonces(
		session.SessionID, [][musig2.PubNonceSize]byte{
			cosignerSession.PublicNonce(),
		},
	)
	require.NoError(t, err)
	_, err = cosignerSession.RegisterPubNonce(session.PublicNonce)
	require.NoError(t, err)

	treeMsg := sha256.Sum256([]byte("tree node"))
	_, err = ring.MuSig2Sign(session.SessionID, treeMsg, false)
	require.NoError(t, err)
	cosignerPartial, err := cosignerSession.Sign(treeMsg)
	require.NoError(t, err)
	final, done, err := ring.MuSig2CombineSig(
		session.SessionID, []*musig2.PartialSignature{cosignerPartial},
	)
	require.NoError(t, err)
	require.True(t, done)
	require.True(t, final.Verify(treeMsg[:], session.CombinedKey))

	// A taproot key-path spend of a VTXO owner key.
	ownerLoc := keychain.KeyLocator{Family: 44, Index: 9}
	owner, err := ring.DeriveKey(ownerLoc)
	require.NoError(t, err)
	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(owner.PubKey),
	)
	require.NoError(t, err)
	prevOut := &wire.TxOut{Value: 40_000, PkScript: pkScript}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 3}})
	tx.AddTxOut(&wire.TxOut{Value: 39_000, PkScript: pkScript})
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, 40_000)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	spendSig, err := ring.SignOutputRaw(tx, &input.SignDescriptor{
		KeyDesc:           owner,
		Output:            prevOut,
		HashType:          txscript.SigHashDefault,
		PrevOutputFetcher: fetcher,
		SigHashes:         sigHashes,
		SignMethod:        input.TaprootKeySpendBIP0086SignMethod,
	})
	require.NoError(t, err)
	tx.TxIn[0].Witness = wire.TxWitness{spendSig.Serialize()}
	vm, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags, nil, sigHashes,
		40_000, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())
}

// accountLister is the part of lnd's remote signer client that lists
// accounts.
type accountLister interface {
	ListAccounts(ctx context.Context, in *walletrpc.ListAccountsRequest,
		opts ...grpc.CallOption) (
		*walletrpc.ListAccountsResponse,
		error,
	)
}

// TestSignerServerAccountsAndAuth checks ListAccounts gives a bundle equal
// to the exported one, in lnd's format, and that a macaroon minted by
// another signer is refused.
func TestSignerServerAccountsAndAuth(t *testing.T) {
	t.Parallel()

	f := startSigner(t)

	remote := walletcore.RemoteSignerConfig{
		RPCHost:      f.server.Addr().String(),
		TLSCertPath:  f.tlsCertPath,
		MacaroonPath: f.macaroonPath,
	}
	require.NoError(t, remote.Validate())
	conn, err := walletcore.DialRemoteSigner(t.Context(), remote)
	require.NoError(t, err)
	defer conn.Stop()

	lister, ok := conn.(accountLister)
	require.True(t, ok)
	resp, err := lister.ListAccounts(
		t.Context(), &walletrpc.ListAccountsRequest{},
	)
	require.NoError(t, err)
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
	require.NoError(t, err)

	listed, err := walletdesc.ParseWatchOnlyBundle(data, params)
	require.NoError(t, err)
	want, err := f.keys.Bundle()
	require.NoError(t, err)
	require.Equal(t, want.MasterFingerprint, listed.MasterFingerprint)
	require.Len(t, listed.Accounts, len(want.Accounts))
	for i := range want.Accounts {
		require.Equal(
			t, want.Accounts[i].Key.String(),
			listed.Accounts[i].Key.String(),
		)
	}

	// A macaroon from another signer's root key is refused.
	other := startSigner(t)
	foreign, err := os.ReadFile(other.macaroonPath)
	require.NoError(t, err)
	foreignPath := filepath.Join(t.TempDir(), "foreign.macaroon")
	require.NoError(t, os.WriteFile(foreignPath, foreign, 0o600))

	ring := f.dial(t, foreignPath)
	err = walletcore.VerifyRemoteSigner(ring)
	require.ErrorContains(t, err, "invalid macaroon")
}
