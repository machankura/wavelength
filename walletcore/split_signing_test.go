package walletcore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// recordingSigner is a remote signer that holds every key and records the
// key family of each request it serves.
type recordingSigner struct {
	*accountsigner.Signer

	mu       sync.Mutex
	families []keychain.KeyFamily
}

// record notes a request for family.
func (r *recordingSigner) record(family int32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.families = append(r.families, keychain.KeyFamily(family))
}

// seen returns the distinct families requested so far.
func (r *recordingSigner) seen() []keychain.KeyFamily {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := slices.Clone(r.families)
	slices.Sort(seen)

	return slices.Compact(seen)
}

// SignMessage records the key family.
func (r *recordingSigner) SignMessage(ctx context.Context,
	in *signrpc.SignMessageReq, opts ...grpc.CallOption) (
	*signrpc.SignMessageResp, error) {

	r.record(in.GetKeyLoc().GetKeyFamily())

	return r.Signer.SignMessage(ctx, in, opts...)
}

// DeriveSharedKey records the key family.
func (r *recordingSigner) DeriveSharedKey(ctx context.Context,
	in *signrpc.SharedKeyRequest, opts ...grpc.CallOption) (
	*signrpc.SharedKeyResponse, error) {

	r.record(in.GetKeyDesc().GetKeyLoc().GetKeyFamily())

	return r.Signer.DeriveSharedKey(ctx, in, opts...)
}

// MuSig2CreateSession records the key family.
func (r *recordingSigner) MuSig2CreateSession(ctx context.Context,
	in *signrpc.MuSig2SessionRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2SessionResponse, error) {

	r.record(in.GetKeyLoc().GetKeyFamily())

	return r.Signer.MuSig2CreateSession(ctx, in, opts...)
}

// SignPsbt records the family of every key-family input.
func (r *recordingSigner) SignPsbt(ctx context.Context,
	in *walletrpc.SignPsbtRequest, opts ...grpc.CallOption) (
	*walletrpc.SignPsbtResponse, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(in.FundedPsbt), false,
	)
	if err != nil {
		return nil, err
	}

	familyPurpose := hdkeychain.HardenedKeyStart +
		walletdesc.PurposeKeyFamily
	for _, pin := range packet.Inputs {
		for _, d := range pin.Bip32Derivation {
			if len(d.Bip32Path) != 5 ||
				d.Bip32Path[0] != familyPurpose {

				continue
			}

			r.record(
				int32(
					d.Bip32Path[2] -
						hdkeychain.HardenedKeyStart,
				),
			)
		}
	}

	return r.Signer.SignPsbt(ctx, in, opts...)
}

// minimalBundleText renders keys as a minimal bundle: the BIP86 account
// and fund families public, the authentication families private.
func minimalBundleText(t *testing.T, keys *walletdesc.AccountKeys) []byte {
	t.Helper()

	origin := walletdesc.FormatFingerprint(keys.MasterFingerprint)
	publicKey := func(acct walletdesc.AccountKey) string {
		pub, err := acct.Key.Neuter()
		require.NoError(t, err)

		return pub.String()
	}
	familyLine := func(acct walletdesc.AccountKey, key string) string {
		return fmt.Sprintf("[%s/1017h/%dh/%dh]%s/0/*", origin,
			acct.CoinType, acct.Account, key)
	}

	funds := []uint32{6, 42, 44, 45, 202}
	var lines []string
	for _, acct := range keys.Accounts {
		switch {
		case acct.Purpose == 86:
			lines = append(
				lines,
				fmt.Sprintf(
					"tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
					publicKey(acct),
				),
			)

		case acct.Purpose != walletdesc.PurposeKeyFamily:
		case slices.Contains(funds, acct.Account):
			lines = append(
				lines,
				familyLine(
					acct, publicKey(acct),
				),
			)

		case acct.Account == 21 || acct.Account == 43:
			lines = append(
				lines,
				familyLine(
					acct, acct.Key.String(),
				),
			)
		}
	}

	return []byte(strings.Join(lines, "\n"))
}

// familyPrivKey derives family/0/index from keys directly.
func familyPrivKey(t *testing.T, keys *walletdesc.AccountKeys,
	loc keychain.KeyLocator) *btcec.PrivateKey {

	t.Helper()

	acct, ok := keys.Account(
		walletdesc.PurposeKeyFamily, uint32(loc.Family),
	)
	require.True(t, ok)
	branch, err := acct.Key.Derive(0)
	require.NoError(t, err)
	child, err := branch.Derive(loc.Index)
	require.NoError(t, err)
	priv, err := child.ECPrivKey()
	require.NoError(t, err)

	return priv
}

// signTaprootKeySpend has ring sign a key-path spend of an output owned by
// loc's key and checks the script engine accepts it.
func signTaprootKeySpend(t *testing.T, ring walletcore.RemoteKeyRing,
	loc keychain.KeyLocator) {

	t.Helper()

	desc, err := ring.DeriveKey(loc)
	require.NoError(t, err)

	outputKey := txscript.ComputeTaprootKeyNoScript(desc.PubKey)
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	prevOut := &wire.TxOut{Value: 30_000, PkScript: pkScript}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 2}})
	tx.AddTxOut(&wire.TxOut{Value: 29_000, PkScript: pkScript})
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	sig, err := ring.SignOutputRaw(tx, &input.SignDescriptor{
		KeyDesc:           desc,
		Output:            prevOut,
		HashType:          txscript.SigHashDefault,
		PrevOutputFetcher: fetcher,
		SigHashes:         sigHashes,
		SignMethod:        input.TaprootKeySpendBIP0086SignMethod,
	})
	require.NoError(t, err)

	tx.TxIn[0].Witness = wire.TxWitness{sig.Serialize()}
	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())
}

// TestSplitSigning creates a wallet from a minimal bundle and drives the
// signatures a daemon makes. The recording remote signer must see no
// request for the authentication families and a request for every fund
// family touched; the wallet must refuse any family its bundle did not
// supply; reopening must restore the split; and a stored bundle that no
// longer covers the registry must refuse to open.
func TestSplitSigning(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	keys := seedAccountKeys(t, params, testSeed())
	defer keys.Zero()

	full, minimal, err := walletdesc.ParseBundle(
		minimalBundleText(t, keys), params,
	)
	require.NoError(t, err)
	require.Nil(t, full)
	defer minimal.Zero()

	newRemote := func() *recordingSigner {
		signerKeys, err := keys.Clone()
		require.NoError(t, err)

		return &recordingSigner{
			Signer: accountsigner.New(signerKeys, params),
		}
	}

	dir := t.TempDir()
	cfg := watchOnlyConfig(params, dir, watchOnlyPassword)
	cache := blockcache.NewBlockCache(10)

	remote := newRemote()
	signing, err := walletcore.OpenWithSigner(
		cfg, nil, minimal, remote, cache,
	)
	require.NoError(t, err)
	ring := signing.KeyRing

	// Identity: remote.
	require.NoError(t, walletcore.VerifyRemoteSigner(ring))

	// Round-join authentication: local.
	joinLoc := keychain.KeyLocator{Family: 43, Index: 2}
	msg := []byte("join round")
	tag := []byte("wavelength/test-join")
	sig, err := ring.SignMessageSchnorr(joinLoc, msg, false, nil, tag)
	require.NoError(t, err)
	digest := chainhash.TaggedHash(tag, msg)
	require.True(
		t,
		sig.Verify(
			digest[:], familyPrivKey(t, keys, joinLoc).PubKey(),
		),
	)

	// Receive authentication: local.
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
		PrivKey: familyPrivKey(t, keys, authLoc),
	}).ECDH(other.PubKey())
	require.NoError(t, err)
	require.Equal(t, want, shared)

	// VTXO tree MuSig2: remote.
	treeLoc := keychain.KeyLocator{Family: 45, Index: 1}
	ours := familyPrivKey(t, keys, treeLoc).PubKey()
	cosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	session, err := ring.MuSig2CreateSession(
		input.MuSig2Version100RC2, treeLoc,
		[]*btcec.PublicKey{ours, cosigner.PubKey()},
		&input.MuSig2Tweaks{}, nil, nil,
	)
	require.NoError(t, err)
	cosignerNonces, err := musig2.GenNonces(
		musig2.WithPublicKey(
			cosigner.PubKey(),
		),
	)
	require.NoError(t, err)
	_, err = ring.MuSig2RegisterNonces(
		session.SessionID,
		[][musig2.PubNonceSize]byte{cosignerNonces.PubNonce},
	)
	require.NoError(t, err)
	_, err = ring.MuSig2Sign(
		session.SessionID,
		sha256.Sum256(
			[]byte("tree"),
		),
		true,
	)
	require.NoError(t, err)

	// Boarding, VTXO owner and OOR receive spends: remote.
	for _, family := range []keychain.KeyFamily{42, 44, 202} {
		signTaprootKeySpend(
			t, ring, keychain.KeyLocator{
				Family: family,
				Index:  3,
			},
		)
	}

	seen := remote.seen()
	require.NotContains(t, seen, keychain.KeyFamily(21))
	require.NotContains(t, seen, keychain.KeyFamily(43))
	for _, family := range []keychain.KeyFamily{6, 42, 44, 45, 202} {
		require.Contains(t, seen, family)
	}

	// Placeholders and unknown families are refused before any signer
	// is asked.
	before := len(remote.seen())
	_, err = ring.DeriveKey(keychain.KeyLocator{Family: 7})
	require.ErrorIs(t, err, walletcore.ErrFamilyNotSupplied)
	_, err = ring.DeriveNextKey(0)
	require.ErrorIs(t, err, walletcore.ErrFamilyNotSupplied)
	_, err = ring.SignMessage(keychain.KeyLocator{Family: 300}, msg, false)
	require.ErrorIs(t, err, walletcore.ErrFamilyNotSupplied)
	require.Len(t, remote.seen(), before)

	signing.Conn.Stop()
	closeBtcWallet(t, signing.BtcWallet)

	// Reopening restores the split from the keystore.
	remote = newRemote()
	reopened, err := walletcore.OpenWithSigner(cfg, nil, nil, remote, cache)
	require.NoError(t, err)
	_, err = reopened.KeyRing.SignMessageSchnorr(
		joinLoc, msg, false, nil, tag,
	)
	require.NoError(t, err)
	require.Empty(t, remote.seen())
	_, err = reopened.KeyRing.DeriveKey(keychain.KeyLocator{Family: 7})
	require.ErrorIs(t, err, walletcore.ErrFamilyNotSupplied)

	// A stored bundle without a fund family the registry has is
	// refused, as after an upgrade that adds one.
	db := reopened.BtcWallet.InternalWallet().Database()
	require.NoError(
		t,
		accountsigner.StoreSuppliedFamilies(
			db, []keychain.KeyFamily{6, 21, 42, 43, 44, 45},
		),
	)
	reopened.Conn.Stop()
	closeBtcWallet(t, reopened.BtcWallet)

	_, err = walletcore.OpenWithSigner(cfg, nil, nil, newRemote(), cache)
	require.ErrorIs(t, err, walletcore.ErrBundleOutdated)
}
