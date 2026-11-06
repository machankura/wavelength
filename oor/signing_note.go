package oor

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
)

// notedOutput is an output a noted transaction spends.
type notedOutput struct {
	Value    int64  `json:"value"`
	PkScript string `json:"pk_script"`
}

// notedTx is one transaction of a transfer and what it spends.
type notedTx struct {
	Tx       string        `json:"tx"`
	PrevOuts []notedOutput `json:"prev_outs"`
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
	for _, in := range packet.Inputs {
		if in.WitnessUtxo == nil {
			return notedTx{}, false
		}
		noted.PrevOuts = append(noted.PrevOuts, notedOutput{
			Value:    in.WitnessUtxo.Value,
			PkScript: hex.EncodeToString(in.WitnessUtxo.PkScript),
		})
	}

	return noted, true
}

// recordSigningNote notes a transfer's package under each of its transactions,
// so that signing any of them finds it. A package that will not render is left
// unnoted, which leaves a signer that wants a note refusing it.
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
