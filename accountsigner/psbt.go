package accountsigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"google.golang.org/grpc"
)

// SignPsbt signs every input of a PSBT that carries BIP32 derivation info
// for one of the account keys, and returns the PSBT with the signatures
// added and the indexes it signed. It follows lnd's BtcWallet.SignPsbt:
// inputs it cannot sign are skipped rather than failed, since another
// party may sign them, and a derived key must match the public key the
// derivation info names. The single and double key tweaks lnd's RPC key
// ring sends as PSBT unknowns are applied.
func (s *Signer) SignPsbt(_ context.Context, in *walletrpc.SignPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.SignPsbtResponse, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(in.FundedPsbt), false,
	)
	if err != nil {
		return nil, fmt.Errorf("parse PSBT: %w", err)
	}

	var signed []uint32
	err = s.withKeys(func(keys *walletdesc.AccountKeys) error {
		var err error
		signed, err = signPsbt(keys, packet)

		return err
	})
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := packet.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("serialize PSBT: %w", err)
	}

	return &walletrpc.SignPsbtResponse{
		SignedPsbt:   buf.Bytes(),
		SignedInputs: signed,
	}, nil
}

// signPsbt signs packet in place.
func signPsbt(keys *walletdesc.AccountKeys,
	packet *psbt.Packet) ([]uint32, error) {

	if err := psbt.InputsReadyToSign(packet); err != nil {
		return nil, err
	}

	tx := packet.UnsignedTx
	sigHashes := txscript.NewTxSigHashes(
		tx, wallet.PsbtPrevOutputFetcher(packet),
	)

	var signed []uint32
	for idx := range tx.TxIn {
		in := &packet.Inputs[idx]
		if in.WitnessUtxo == nil || len(in.FinalScriptWitness) > 0 ||
			len(in.Bip32Derivation) == 0 {

			continue
		}

		derivation := in.Bip32Derivation[0]
		priv, err := privKeyAt(keys, derivation.Bip32Path)
		if errors.Is(err, ErrUnknownKey) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", idx, err)
		}

		if !bytes.Equal(
			derivation.PubKey, priv.PubKey().SerializeCompressed(),
		) {

			continue
		}

		priv = tweakPrivKey(in.Unknowns, priv)

		method, err := signingMethod(in)
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", idx, err)
		}

		switch method {
		case input.WitnessV0SignMethod:
			err = signSegWitV0(in, tx, sigHashes, idx, priv)

		case input.TaprootKeySpendBIP0086SignMethod:
			err = signTaprootKeySpend(
				in, tx, sigHashes, idx, priv, []byte{},
			)

		case input.TaprootKeySpendSignMethod:
			err = signTaprootKeySpend(
				in, tx, sigHashes, idx, priv,
				in.TaprootMerkleRoot,
			)

		case input.TaprootScriptSpendSignMethod:
			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			err = signTaprootScriptSpend(
				in, tx, sigHashes, idx, priv, leaf,
			)

		default:
			err = fmt.Errorf("unsupported signing method %v",
				method)
		}
		if err != nil {
			return nil, err
		}

		signed = append(signed, uint32(idx))
	}

	return signed, nil
}

// signingMethod detects the signature an input needs, as lnd's
// validateSigningMethod does.
func signingMethod(in *psbt.PInput) (input.SignMethod, error) {
	script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
	if err != nil {
		return 0, fmt.Errorf("parse pkScript: %w", err)
	}

	switch script.Class() {
	case txscript.WitnessV0PubKeyHashTy, txscript.ScriptHashTy,
		txscript.WitnessV0ScriptHashTy:
		return input.WitnessV0SignMethod, nil

	case txscript.WitnessV1TaprootTy:
	default:
		return 0, fmt.Errorf("unsupported script class %v",
			script.Class())
	}

	if len(in.TaprootBip32Derivation) != 1 {
		return 0, errors.New("a taproot input needs exactly one " +
			"taproot BIP32 derivation")
	}

	derivation := in.TaprootBip32Derivation[0]
	switch len(derivation.LeafHashes) {
	case 0:
		if len(in.TaprootMerkleRoot) == 0 {
			return input.TaprootKeySpendBIP0086SignMethod, nil
		}
		if len(in.TaprootMerkleRoot) != sha256.Size {
			return 0, errors.New("invalid taproot merkle root " +
				"length")
		}

		return input.TaprootKeySpendSignMethod, nil

	case 1:
		if len(in.TaprootLeafScript) != 1 {
			return 0, errors.New("leaf hash given without its " +
				"leaf script")
		}

		leaf := txscript.TapLeaf{
			LeafVersion: in.TaprootLeafScript[0].LeafVersion,
			Script:      in.TaprootLeafScript[0].Script,
		}
		leafHash := leaf.TapHash()
		if !bytes.Equal(leafHash[:], derivation.LeafHashes[0]) {
			return 0, errors.New("leaf hash does not match the " +
				"leaf script")
		}

		return input.TaprootScriptSpendSignMethod, nil

	default:
		return 0, errors.New("can only sign one leaf at a time")
	}
}

// signSegWitV0 adds a segwit v0 partial signature.
func signSegWitV0(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int,
	priv *btcec.PrivateKey) error {

	subScript := in.WitnessUtxo.PkScript
	switch {
	case len(in.RedeemScript) > 0:
		subScript = in.RedeemScript

	case len(in.WitnessScript) > 0:
		subScript = in.WitnessScript
	}

	sig, err := txscript.RawTxInWitnessSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value, subScript,
		in.SighashType, priv,
	)
	if err != nil {
		return fmt.Errorf("sign input %d: %w", idx, err)
	}

	in.PartialSigs = append(in.PartialSigs, &psbt.PartialSig{
		PubKey:    priv.PubKey().SerializeCompressed(),
		Signature: sig,
	})

	return nil
}

// signTaprootKeySpend adds a taproot key-path signature, tweaking the key
// by rootHash (empty for a BIP86 output).
func signTaprootKeySpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, priv *btcec.PrivateKey,
	rootHash []byte) error {

	sig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, rootHash, in.SighashType, priv,
	)
	if err != nil {
		return fmt.Errorf("sign taproot input %d: %w", idx, err)
	}

	in.TaprootKeySpendSig = sig

	return nil
}

// signTaprootScriptSpend adds a tapscript signature for leaf.
func signTaprootScriptSpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, priv *btcec.PrivateKey,
	leaf txscript.TapLeaf) error {

	sig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, leaf, in.SighashType, priv,
	)
	if err != nil {
		return fmt.Errorf("sign taproot script input %d: %w", idx, err)
	}

	leafHash := leaf.TapHash()
	in.TaprootScriptSpendSig = append(
		in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: in.TaprootBip32Derivation[0].XOnlyPubKey,
			LeafHash:    leafHash[:],
			Signature:   sig[:schnorr.SignatureSize],
			SigHash:     in.SighashType,
		},
	)

	return nil
}

// tweakPrivKey applies the single or double tweak lnd's RPC key ring
// attaches to an input as a PSBT unknown.
func tweakPrivKey(unknowns []*psbt.Unknown,
	priv *btcec.PrivateKey) *btcec.PrivateKey {

	for _, u := range unknowns {
		switch {
		case bytes.Equal(
			u.Key, btcwallet.PsbtKeyTypeInputSignatureTweakSingle,
		):
			return input.TweakPrivKey(priv, u.Value)

		case bytes.Equal(
			u.Key, btcwallet.PsbtKeyTypeInputSignatureTweakDouble,
		):

			doubleTweak, _ := btcec.PrivKeyFromBytes(u.Value)

			return input.DeriveRevocationPrivKey(priv, doubleTweak)
		}
	}

	return priv
}
