package oor

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
)

// notedOutput is an output a noted transaction spends.
type notedOutput struct {
	Value    int64  `json:"value"`
	PkScript string `json:"pk_script"`
}

// notedSig is a BIP-340 signature an input already carries. Whose it is, a
// signer finds out by verifying it against the key it expects.
type notedSig struct {
	Input     int    `json:"input"`
	Signature string `json:"signature"`
}

// notedTx is one transaction of a transfer, what it spends, and the signatures
// it has so far.
type notedTx struct {
	Tx       string        `json:"tx"`
	PrevOuts []notedOutput `json:"prev_outs"`
	Sigs     []notedSig    `json:"sigs,omitempty"`
}

// notedPackage is what a signer that judges its requests is told about a
// transfer: an Ark transaction moves value only through its checkpoints, so
// neither can be checked without the other.
type notedPackage struct {
	Ark         notedTx   `json:"ark"`
	Checkpoints []notedTx `json:"checkpoints"`
}

// notedTxOf renders a PSBT's transaction and prevouts, or reports it can't.
func notedTxOf(packet *psbt.Packet) (notedTx, bool) {
	var raw bytes.Buffer
	if err := packet.UnsignedTx.Serialize(&raw); err != nil {
		return notedTx{}, false
	}

	noted := notedTx{Tx: hex.EncodeToString(raw.Bytes())}
	for i, in := range packet.Inputs {
		if in.WitnessUtxo == nil {
			return notedTx{}, false
		}
		noted.PrevOuts = append(noted.PrevOuts, notedOutput{
			Value:    in.WitnessUtxo.Value,
			PkScript: hex.EncodeToString(in.WitnessUtxo.PkScript),
		})

		for _, sig := range in.TaprootScriptSpendSig {
			noted.Sigs = append(noted.Sigs, notedSig{
				Input:     i,
				Signature: hex.EncodeToString(sig.Signature),
			})
		}

		// An input the operator already finalized carries its
		// signatures in the witness instead.
		witness, err := oortx.BuildTaprootWitness(in)
		if err != nil {
			continue
		}
		for _, item := range witness {
			if len(item) != schnorr.SignatureSize {
				continue
			}
			noted.Sigs = append(noted.Sigs, notedSig{
				Input:     i,
				Signature: hex.EncodeToString(item),
			})
		}
	}

	return noted, true
}

// recordSigningNote notes a transfer's package under each of its transactions,
// so that signing any of them finds it. A package that will not render is left
// unnoted, which leaves a signer that wants a note refusing it. It is noted again
// once the operator has co-signed, since a signature on a checkpoint hands the
// VTXO over, and a signer wants to see first that the Ark transaction can spend
// what it hands over to.
func recordSigningNote(ark *psbt.Packet, checkpoints []*psbt.Packet) {
	if !signctx.Enabled() {
		return
	}

	arkTx, ok := notedTxOf(ark)
	if !ok {
		return
	}

	arkTxid := ark.UnsignedTx.TxHash()
	keys := [][32]byte{arkTxid}
	material := notedPackage{Ark: arkTx}
	for _, checkpoint := range checkpoints {
		noted, ok := notedTxOf(checkpoint)
		if !ok {
			return
		}
		keys = append(keys, checkpoint.UnsignedTx.TxHash())
		material.Checkpoints = append(material.Checkpoints, noted)
	}

	signctx.Record(signctx.KindOOR, arkTxid.String(), keys, material)
}
