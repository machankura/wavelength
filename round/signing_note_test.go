package round

import (
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/stretchr/testify/require"
)

// noteFixture builds a commitment transaction with one connector tree output,
// and the mapping a round hands a forfeit.
func noteFixture(t *testing.T) (*psbt.Packet, *btcec.PublicKey,
	*ConnectorLeafInfo) {

	t.Helper()

	operator, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := txscript.PayToTaprootScript(operator.PubKey())
	require.NoError(t, err)

	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{1},
	}})
	tx.AddTxOut(&wire.TxOut{Value: 8 * 600, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 10_000, PkScript: pkScript,
	}

	root := wire.OutPoint{Hash: tx.TxHash()}
	connectors, err := tree.BuildConnectorTree(
		root, tx.TxOut[0], tree.ConnectorDescriptor{
			PkScript:  pkScript,
			NumLeaves: 8,
			Amount:    btcutil.Amount(600),
		}, operator.PubKey(), 2,
	)
	require.NoError(t, err)

	leaves := connectors.Root.GetLeafNodes()
	outpoint, err := leaves[3].GetNonAnchorOutpoint()
	require.NoError(t, err)

	return packet, operator.PubKey(), &ConnectorLeafInfo{
		LeafIndex:         3,
		ConnectorOutpoint: *outpoint,
		ConnectorPkScript: pkScript,
		ConnectorAmount:   600,
		VTXOAmount:        btcutil.Amount(50_000),
		NumLeaves:         8,
		Radix:             2,
	}
}

// TestSigningNoteOnlyWhenEnabled proves a wallet with no judging signer does no
// work here at all.
func TestSigningNoteOnlyWhenEnabled(t *testing.T) {
	packet, key, info := noteFixture(t)

	recordSigningNote(
		RoundID{}, packet, key, 144, key, nil, Intents{},
		func(int, types.VTXORequest) int64 { return 0 },
		map[wire.OutPoint]*ConnectorLeafInfo{{Index: 1}: info},
	)
	_, ok := signctx.Lookup(packet.UnsignedTx.TxHash())
	require.False(t, ok)
}

// TestSigningNoteReachesAForfeit proves a forfeit finds its round through the
// connector it spends, and is told the whole path back to the commitment.
func TestSigningNoteReachesAForfeit(t *testing.T) {
	signctx.Enable()
	t.Cleanup(signctx.Disable)

	packet, key, info := noteFixture(t)

	recordSigningNote(
		RoundID{}, packet, key, 144, key, nil, Intents{},
		func(int, types.VTXORequest) int64 { return 0 },
		map[wire.OutPoint]*ConnectorLeafInfo{{Index: 1}: info},
	)

	note, ok := signctx.Lookup(info.ConnectorOutpoint.Hash)
	require.True(t, ok)
	require.Equal(t, signctx.KindRound, note.Kind)

	var round notedRound
	require.NoError(t, json.Unmarshal(note.Material, &round))
	require.Len(t, round.Forfeits, 1)

	// A binary tree of eight leaves: root, two branches, and the leaf.
	require.Len(t, round.Forfeits[0].ConnectorPath, 4)

	_, ok = signctx.Lookup(packet.UnsignedTx.TxHash())
	require.True(t, ok, "boarding signs the commitment itself")
}

// TestSigningNoteFailsClosed proves a round with a connector it cannot rebuild
// is not noted at all, leaving a signer that wants a note refusing it.
func TestSigningNoteFailsClosed(t *testing.T) {
	signctx.Enable()
	t.Cleanup(signctx.Disable)

	packet, key, info := noteFixture(t)
	info.RootOutputIndex = 9

	recordSigningNote(
		RoundID{}, packet, key, 144, key, nil, Intents{},
		func(int, types.VTXORequest) int64 { return 0 },
		map[wire.OutPoint]*ConnectorLeafInfo{{Index: 1}: info},
	)

	_, ok := signctx.Lookup(packet.UnsignedTx.TxHash())
	require.False(t, ok)
}
