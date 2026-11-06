package oor

import (
	"bytes"
	"encoding/hex"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
)

// notedPackage is what a signer that judges its requests is told about a
// transfer: an Ark transaction moves value only through its checkpoints, so
// neither can be checked without the other.
type notedPackage struct {
	Ark         string   `json:"ark"`
	Checkpoints []string `json:"checkpoints"`
}

// recordSigningNote notes a transfer's package under each of its transactions,
// so that signing any of them finds it.
func recordSigningNote(ark *psbt.Packet, checkpoints []*psbt.Packet) {
	if !signctx.Enabled() {
		return
	}

	encode := func(packet *psbt.Packet) string {
		var buf bytes.Buffer
		if err := packet.Serialize(&buf); err != nil {
			return ""
		}

		return hex.EncodeToString(buf.Bytes())
	}

	arkTxid := ark.UnsignedTx.TxHash()
	keys := [][32]byte{arkTxid}
	material := notedPackage{Ark: encode(ark)}
	for _, checkpoint := range checkpoints {
		keys = append(keys, checkpoint.UnsignedTx.TxHash())
		material.Checkpoints = append(
			material.Checkpoints, encode(checkpoint),
		)
	}

	signctx.Record(signctx.KindOOR, arkTxid.String(), keys, material)
}
