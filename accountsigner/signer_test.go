package accountsigner_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/require"
)

var testParams = &chaincfg.RegressionNetParams

// testRoot returns a fixed regtest master key.
func testRoot(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	root, err := hdkeychain.NewMaster(seed, testParams)
	require.NoError(t, err)

	return root
}

// derive walks a hardened path from key with standard BIP32.
func derive(t *testing.T, key *hdkeychain.ExtendedKey,
	path ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	for _, step := range path {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}

	return key
}

// testAccountKeys returns the account keys of root.
func testAccountKeys(t *testing.T,
	root *hdkeychain.ExtendedKey) *walletdesc.AccountKeys {

	t.Helper()

	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	keys, err := walletdesc.ParseAccountKeys([]string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			derive(t, root, 86, 0, 0)),
		fmt.Sprintf("[%s/1017h/1h]%s", origin,
			derive(t, root, 1017, 1)),
	}, testParams)
	require.NoError(t, err)

	return keys
}

// familyPriv derives the private key at family/0/index from root.
func familyPriv(t *testing.T, root *hdkeychain.ExtendedKey,
	loc keychain.KeyLocator) *btcec.PrivateKey {

	t.Helper()

	key := derive(t, root, 1017, 1, uint32(loc.Family))
	key, err := key.Derive(0)
	require.NoError(t, err)
	key, err = key.Derive(loc.Index)
	require.NoError(t, err)
	priv, err := key.ECPrivKey()
	require.NoError(t, err)

	return priv
}

// newTestRing builds the production arrangement: a watch-only btcwallet
// from the keys' public half, fronted by lnd's RPC key ring talking to the
// account signer.
func newTestRing(t *testing.T,
	keys *walletdesc.AccountKeys) (walletcore.RemoteKeyRing,
	*accountsigner.Signer) {

	t.Helper()

	bundle, err := keys.Bundle()
	require.NoError(t, err)

	btcw, err := walletcore.NewWatchOnlyBtcWallet(btcwallet.Config{
		PublicPass: []byte("account-signer-test"),
		NetParams:  testParams,
		CoinType:   walletcore.CoinTypeForNet(testParams),
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

	signer := accountsigner.New(keys, testParams)
	ring, err := walletcore.NewRemoteKeyRing(
		btcw, walletcore.CoinTypeForNet(testParams), signer, testParams,
	)
	require.NoError(t, err)

	return ring, signer
}

// TestSignerMessagesAndECDH checks message signatures, the identity
// challenge and ECDH against keys derived directly from the master key.
func TestSignerMessagesAndECDH(t *testing.T) {
	t.Parallel()

	root := testRoot(t)
	ring, signer := newTestRing(t, testAccountKeys(t, root))

	require.NoError(t, walletcore.VerifyRemoteSigner(ring))

	loc := keychain.KeyLocator{Family: 43, Index: 5}
	priv := familyPriv(t, root, loc)
	msg := []byte("account signer message")

	sig, err := ring.SignMessage(loc, msg, false)
	require.NoError(t, err)
	require.True(t, sig.Verify(chainhash.HashB(msg), priv.PubKey()))

	// lnd's RPC key ring only signs compact with the node key.
	nodeLoc := keychain.KeyLocator{Family: keychain.KeyFamilyNodeKey}
	compact, err := ring.SignMessageCompact(nodeLoc, msg, true)
	require.NoError(t, err)
	recovered, _, err := ecdsa.RecoverCompact(
		compact, chainhash.DoubleHashB(msg),
	)
	require.NoError(t, err)
	require.True(
		t,
		recovered.IsEqual(
			familyPriv(t, root, nodeLoc).PubKey(),
		),
	)

	tag := []byte("account-signer-test")
	schnorrSig, err := ring.SignMessageSchnorr(loc, msg, false, nil, tag)
	require.NoError(t, err)
	digest := chainhash.TaggedHash(tag, msg)
	require.True(t, schnorrSig.Verify(digest[:], priv.PubKey()))

	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	authLoc := keychain.KeyLocator{Family: 21}
	shared, err := ring.ECDH(
		keychain.KeyDescriptor{
			KeyLocator: authLoc,
		},
		other.PubKey(),
	)
	require.NoError(t, err)
	want, err := (&keychain.PrivKeyECDH{
		PrivKey: familyPriv(t, root, authLoc),
	}).ECDH(other.PubKey())
	require.NoError(t, err)
	require.Equal(t, want, shared)

	// After Stop the keys are gone.
	signer.Stop()
	_, err = ring.SignMessage(loc, msg, false)
	require.ErrorContains(t, err, accountsigner.ErrStopped.Error())
}

// TestSignerMuSig2 runs a two-party MuSig2 session, the round's VTXO tree
// signing, between the account signer and an independent cosigner.
func TestSignerMuSig2(t *testing.T) {
	t.Parallel()

	root := testRoot(t)
	ring, _ := newTestRing(t, testAccountKeys(t, root))

	loc := keychain.KeyLocator{Family: 45, Index: 3}
	ours := familyPriv(t, root, loc).PubKey()
	cosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signers := []*btcec.PublicKey{ours, cosigner.PubKey()}

	tweaks := &input.MuSig2Tweaks{TaprootBIP0086Tweak: true}
	session, err := ring.MuSig2CreateSession(
		input.MuSig2Version100RC2, loc, signers, tweaks, nil, nil,
	)
	require.NoError(t, err)

	cosignerCtx, err := musig2.NewContext(
		cosigner, true, musig2.WithKnownSigners(signers),
		musig2.WithBip86TweakCtx(),
	)
	require.NoError(t, err)
	cosignerSession, err := cosignerCtx.NewSession()
	require.NoError(t, err)

	haveAll, err := ring.MuSig2RegisterNonces(
		session.SessionID, [][musig2.PubNonceSize]byte{
			cosignerSession.PublicNonce(),
		},
	)
	require.NoError(t, err)
	require.True(t, haveAll)
	_, err = cosignerSession.RegisterPubNonce(session.PublicNonce)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("vtxo tree node"))
	ourPartial, err := ring.MuSig2Sign(session.SessionID, msg, false)
	require.NoError(t, err)
	cosignerPartial, err := cosignerSession.Sign(msg)
	require.NoError(t, err)
	_, err = cosignerSession.CombineSig(ourPartial)
	require.NoError(t, err)

	final, done, err := ring.MuSig2CombineSig(
		session.SessionID, []*musig2.PartialSignature{cosignerPartial},
	)
	require.NoError(t, err)
	require.True(t, done)
	require.True(t, final.Verify(msg[:], session.CombinedKey))
}

// TestSignerSignOutputRaw spends a taproot output through both paths a
// VTXO uses, the key path and a tapscript leaf, and checks the script
// engine accepts each witness.
func TestSignerSignOutputRaw(t *testing.T) {
	t.Parallel()

	root := testRoot(t)
	ring, _ := newTestRing(t, testAccountKeys(t, root))

	loc := keychain.KeyLocator{Family: 44, Index: 7}
	ownerPriv := familyPriv(t, root, loc)
	ownerPub := ownerPriv.PubKey()

	leafScript, err := txscript.NewScriptBuilder().
		AddData(schnorrPub(ownerPub)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()

	internal := ownerPub
	outputKey := txscript.ComputeTaprootOutputKey(internal, rootHash[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	prevOut := &wire.TxOut{Value: 50_000, PkScript: pkScript}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxOut(&wire.TxOut{Value: 49_000, PkScript: pkScript})

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	desc := &input.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: loc,
			PubKey:     ownerPub,
		},
		Output:            prevOut,
		HashType:          txscript.SigHashDefault,
		PrevOutputFetcher: fetcher,
		SigHashes:         sigHashes,
		InputIndex:        0,
	}

	verify := func(witness wire.TxWitness) {
		t.Helper()

		tx.TxIn[0].Witness = witness
		vm, err := txscript.NewEngine(
			prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags,
			nil, sigHashes, prevOut.Value, fetcher,
		)
		require.NoError(t, err)
		require.NoError(t, vm.Execute())
	}

	// Key path: the internal key tweaked by the script root.
	keyDesc := *desc
	keyDesc.SignMethod = input.TaprootKeySpendSignMethod
	keyDesc.TapTweak = rootHash[:]
	keySig, err := ring.SignOutputRaw(tx, &keyDesc)
	require.NoError(t, err)
	verify(wire.TxWitness{keySig.Serialize()})

	// Script path: the leaf's own key, with the control block. The
	// key-path witness comes off first, or the input reads as final.
	tx.TxIn[0].Witness = nil
	scriptDesc := *desc
	scriptDesc.SignMethod = input.TaprootScriptSpendSignMethod
	scriptDesc.WitnessScript = leafScript
	scriptSig, err := ring.SignOutputRaw(tx, &scriptDesc)
	require.NoError(t, err)

	proof := tree.LeafMerkleProofs[0]
	control := proof.ToControlBlock(internal)
	controlBytes, err := control.ToBytes()
	require.NoError(t, err)
	verify(wire.TxWitness{
		scriptSig.Serialize(), leafScript, controlBytes,
	})
}

// schnorrPub returns the x-only serialization of pub.
func schnorrPub(pub *btcec.PublicKey) []byte {
	return pub.SerializeCompressed()[1:]
}
