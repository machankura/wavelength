package walletcore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
)

var (
	// ErrSlotProbeFailed is returned when the signer does not hold the
	// key a wallet slot expects.
	ErrSlotProbeFailed = errors.New("signer does not hold the key for a " +
		"wallet slot")

	// ErrManifestMismatch is returned when a wallet's accounts no longer
	// match the manifest it was created from.
	ErrManifestMismatch = errors.New("wallet accounts do not match its " +
		"stored manifest")
)

// SlotProbe is the result of probing one wallet slot.
type SlotProbe struct {
	// Slot is "onchain" or a key family number.
	Slot string

	// OK reports whether the signer signed with the expected key.
	OK bool
}

// ProbeSigner checks the signer holds the key of every fund slot: a fresh
// tagged challenge for each fund family's index-0 key, and a spend of a
// fabricated, never broadcast output locked to the on-chain account's
// first key. Each signature is verified against the key the watch-only
// wallet derives itself. It returns every slot's result and
// ErrSlotProbeFailed if any failed; a single-root signer, such as lnd,
// fails here for any slot a manifest overrides.
func ProbeSigner(ring RemoteKeyRing, btcw *btcwallet.BtcWallet,
	params *chaincfg.Params) ([]SlotProbe, error) {

	var probes []SlotProbe
	var failed []string
	record := func(slot string, err error) {
		probes = append(probes, SlotProbe{Slot: slot, OK: err == nil})
		if err != nil {
			failed = append(
				failed, fmt.Sprintf("%s (%v)", slot, err),
			)
		}
	}

	record("onchain", probeOnChain(ring, btcw, params))
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		record(
			strconv.Itoa(int(family)), probeFamily(ring, family),
		)
	}

	if len(failed) > 0 {
		return probes, fmt.Errorf("%w: %v", ErrSlotProbeFailed, failed)
	}

	return probes, nil
}

// probeFamily has the signer sign a challenge with family's index-0 key.
func probeFamily(ring RemoteKeyRing, family keychain.KeyFamily) error {
	loc := keychain.KeyLocator{Family: family}
	desc, err := ring.DeriveKey(loc)
	if err != nil {
		return err
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	sig, err := ring.SignMessageSchnorr(
		loc, challenge, false, nil, remoteSignerCheckTag,
	)
	if err != nil {
		return err
	}

	digest := chainhash.TaggedHash(remoteSignerCheckTag, challenge)
	if !sig.Verify(digest[:], desc.PubKey) {
		return errors.New("wrong key")
	}

	return nil
}

// probeOnChain has the signer sign a key-path spend of a fabricated BIP86
// output paying the on-chain account's first receive key.
func probeOnChain(ring RemoteKeyRing, btcw *btcwallet.BtcWallet,
	params *chaincfg.Params) error {

	props, err := btcw.InternalWallet().AccountProperties(
		waddrmgr.KeyScopeBIP0086, 0,
	)
	if err != nil {
		return err
	}
	branch, err := props.AccountPubKey.Derive(0)
	if err != nil {
		return err
	}
	child, err := branch.Derive(0)
	if err != nil {
		return err
	}
	pub, err := child.ECPubKey()
	if err != nil {
		return err
	}

	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(pub),
	)
	if err != nil {
		return err
	}

	var fabricated wire.OutPoint
	if _, err := rand.Read(fabricated.Hash[:]); err != nil {
		return err
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: fabricated})
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return err
	}

	purpose := walletdesc.ScriptTaproot.Purpose()
	path := []uint32{
		hdkeychain.HardenedKeyStart + purpose,
		hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
		0, 0,
	}
	prevOut := &wire.TxOut{Value: 2_000, PkScript: pkScript}
	packet.Inputs[0].WitnessUtxo = prevOut
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:               pub.SerializeCompressed(),
		MasterKeyFingerprint: props.MasterKeyFingerprint,
		Bip32Path:            path,
	}}
	taprootDerivation := &psbt.TaprootBip32Derivation{
		XOnlyPubKey:          pub.SerializeCompressed()[1:],
		MasterKeyFingerprint: props.MasterKeyFingerprint,
		Bip32Path:            path,
	}
	in := &packet.Inputs[0]
	in.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		taprootDerivation,
	}

	if _, err := ring.SignPsbt(packet); err != nil {
		return err
	}
	if len(packet.Inputs[0].TaprootKeySpendSig) == 0 {
		return errors.New("not signed")
	}

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	tx.TxIn[0].Witness = wire.TxWitness{packet.Inputs[0].TaprootKeySpendSig}
	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prevOut.Value, fetcher,
	)
	if err != nil {
		return err
	}
	if err := vm.Execute(); err != nil {
		return errors.New("wrong key")
	}

	return nil
}

// checkManifestAccounts refuses a wallet whose btcwallet accounts no longer
// hold the keys its manifest assigned to each slot.
func checkManifestAccounts(btcw *btcwallet.BtcWallet, m *walletdesc.Manifest,
	params *chaincfg.Params) error {

	w := btcw.InternalWallet()
	check := func(scope waddrmgr.KeyScope, account uint32,
		want *hdkeychain.ExtendedKey, slot string) error {

		props, err := w.AccountProperties(scope, account)
		if err != nil {
			return fmt.Errorf("%w: slot %s: %w",
				ErrManifestMismatch, slot, err)
		}
		have, err := walletdesc.StandardAccountPublicKey(
			props.AccountPubKey, params,
		)
		if err != nil {
			return err
		}
		if have.String() != want.String() {
			return fmt.Errorf("%w: slot %s", ErrManifestMismatch,
				slot)
		}

		return nil
	}

	err := check(waddrmgr.KeyScopeBIP0086, 0, m.OnChain.Key, "onchain")
	if err != nil {
		return err
	}

	scope := waddrmgr.KeyScope{
		Purpose: keychain.BIP0043Purpose,
		Coin:    CoinTypeForNet(params),
	}
	for family, slot := range m.Families {
		err := check(
			scope, uint32(family), slot.Key,
			strconv.Itoa(
				int(family),
			),
		)
		if err != nil {
			return err
		}
	}

	return nil
}
