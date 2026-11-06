package round

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/lib/types"
)

// notedOutput is an output in a signing note.
type notedOutput struct {
	Value    int64  `json:"value"`
	PkScript string `json:"pk_script"`
}

// notedNode is one transaction of a tree this wallet signs: everything a signer
// needs to rebuild the digest it is asked for, and to walk from the commitment
// transaction to the leaf.
type notedNode struct {
	Tx        string   `json:"tx"`
	Digest    string   `json:"digest"`
	CoSigners []string `json:"co_signers"`

	// Signature is the node's aggregated signature, once there is one. A
	// signer that gives anything up for a round wants to see these first,
	// since an unsigned tree is a VTXO its owner can't exit with.
	Signature string `json:"signature,omitempty"`
}

// notedTree is a tree path, its batch output and its sweep root.
type notedTree struct {
	OutputIndex int         `json:"output_index"`
	BatchOutput notedOutput `json:"batch_output"`
	SweepRoot   string      `json:"sweep_root"`
	Nodes       []notedNode `json:"nodes"`
}

// notedVTXO is one VTXO this wallet asked of the round.
type notedVTXO struct {
	SigningKey     string `json:"signing_key"`
	OwnerKey       string `json:"owner_key"`
	Amount         int64  `json:"amount"`
	PkScript       string `json:"pk_script"`
	PolicyTemplate string `json:"policy_template"`
}

// notedForfeit is one VTXO this wallet gives up in the round, and the connector
// that makes giving it up conditional on the round confirming.
type notedForfeit struct {
	VTXOOutpoint      string `json:"vtxo_outpoint"`
	VTXOAmount        int64  `json:"vtxo_amount"`
	ConnectorOutpoint string `json:"connector_outpoint"`
	ConnectorPkScript string `json:"connector_pk_script"`
	ConnectorAmount   int64  `json:"connector_amount"`

	// ConnectorPath is every transaction from the commitment output to the
	// connector, which is what makes giving this VTXO up conditional.
	ConnectorPath []string `json:"connector_path"`
}

// notedRound is what a signer that judges its requests is told about a round
// once this wallet has validated it. The client's own validation has passed by
// now, but the signer is not this client and repeats it.
type notedRound struct {
	CommitmentTx string         `json:"commitment_tx"`
	PrevOuts     []notedOutput  `json:"prev_outs"`
	SweepKey     string         `json:"sweep_key"`
	SweepDelay   uint32         `json:"sweep_delay"`
	Trees        []notedTree    `json:"trees"`
	VTXOs        []notedVTXO    `json:"vtxos"`
	Leaves       []notedOutput  `json:"leaves"`
	Forfeits     []notedForfeit `json:"forfeits"`
}

// notedJoin is what a signer is told about a proof of funds: the to_spend
// transaction whose only output the proof's first input spends. to_spend cannot
// be mined, so a signature here can never move a coin, and that is what a signer
// checks instead of trusting that this is a proof.
type notedJoin struct {
	ToSpend string `json:"to_spend"`
}

// recordJoinNote notes a proof of funds under its to_sign transaction.
func recordJoinNote(toSpend, toSign *wire.MsgTx) {
	if !signctx.Enabled() {
		return
	}

	var raw bytes.Buffer
	if err := toSpend.Serialize(&raw); err != nil {
		return
	}

	txid := toSign.TxHash()
	signctx.Record(
		signctx.KindJoin, txid.String(), [][32]byte{txid},
		notedJoin{ToSpend: hex.EncodeToString(raw.Bytes())},
	)
}

// compressedHex renders a public key that may be absent.
func compressedHex(key *btcec.PublicKey) string {
	if key == nil {
		return ""
	}

	return hex.EncodeToString(key.SerializeCompressed())
}

// notedTreeOf renders a tree path and adds its transactions and digests to
// keys, which fails closed by leaving them unnoted if a node will not render.
func notedTreeOf(index int, path *tree.Tree,
	keys *[][32]byte) (*notedTree, bool) {

	if path == nil || path.Root == nil || path.BatchOutput == nil {
		return nil, false
	}

	fetcher, err := path.Root.PrevOutputFetcher(path.BatchOutput)
	if err != nil {
		return nil, false
	}

	noted := &notedTree{
		OutputIndex: index,
		BatchOutput: notedOutput{
			Value: path.BatchOutput.Value,
			PkScript: hex.EncodeToString(
				path.BatchOutput.PkScript,
			),
		},
		SweepRoot: hex.EncodeToString(path.SweepTapscriptRoot),
	}
	for node := range path.Root.NodesIter() {
		rendered, ok := notedNodeOf(node, fetcher, keys)
		if !ok {
			return nil, false
		}
		noted.Nodes = append(noted.Nodes, *rendered)
	}

	return noted, true
}

// notedNodeOf renders one transaction of a tree.
func notedNodeOf(node *tree.Node, fetcher txscript.PrevOutputFetcher,
	keys *[][32]byte) (*notedNode, bool) {

	tx, err := node.ToTx()
	if err != nil {
		return nil, false
	}
	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		return nil, false
	}
	digest, err := node.SigHash(fetcher)
	if err != nil || len(digest) != 32 {
		return nil, false
	}

	rendered := &notedNode{
		Tx:     hex.EncodeToString(raw.Bytes()),
		Digest: hex.EncodeToString(digest),
	}
	for _, key := range node.CoSigners {
		rendered.CoSigners = append(
			rendered.CoSigners, compressedHex(key),
		)
	}

	var digestKey [32]byte
	copy(digestKey[:], digest)
	*keys = append(*keys, tx.TxHash(), digestKey)

	return rendered, true
}

// connectorPathOf rebuilds the path from the commitment output to a connector
// leaf, as verifyConnectorLeaf already has by the time this is called, and
// renders its transactions.
func connectorPathOf(commitment *wire.MsgTx, operatorKey *btcec.PublicKey,
	info *ConnectorLeafInfo) ([]string, bool) {

	if info.RootOutputIndex >= uint32(len(commitment.TxOut)) {
		return nil, false
	}
	rootOutput := commitment.TxOut[info.RootOutputIndex]

	connectors, err := tree.BuildConnectorTree(
		wire.OutPoint{
			Hash:  commitment.TxHash(),
			Index: info.RootOutputIndex,
		},
		rootOutput, tree.ConnectorDescriptor{
			PkScript:  rootOutput.PkScript,
			NumLeaves: int(info.NumLeaves),
			Amount:    btcutil.Amount(info.ConnectorAmount),
		}, operatorKey, int(info.Radix),
	)
	if err != nil {
		return nil, false
	}

	path, err := connectors.ExtractPathForIndices(info.LeafIndex)
	if err != nil || path == nil {
		return nil, false
	}

	var rendered []string
	for node := range path.Root.NodesIter() {
		tx, err := node.ToTx()
		if err != nil {
			return nil, false
		}
		var raw bytes.Buffer
		if err := tx.Serialize(&raw); err != nil {
			return nil, false
		}
		rendered = append(rendered, hex.EncodeToString(raw.Bytes()))
	}

	return rendered, true
}

// recordSignedTrees adds a round's aggregated tree signatures to its note, so
// that a request made after tree signing shows them. A round with no note stays
// that way, which leaves a signer that wants one refusing the request.
func recordSignedTrees(commitment chainhash.Hash,
	sigs map[tree.TxID]*schnorr.Signature) {

	if !signctx.Enabled() {
		return
	}

	note, ok := signctx.Lookup(commitment)
	if !ok {
		return
	}

	var noted notedRound
	if err := json.Unmarshal(note.Material, &noted); err != nil {
		return
	}

	for i := range noted.Trees {
		for j := range noted.Trees[i].Nodes {
			node := &noted.Trees[i].Nodes[j]

			raw, err := hex.DecodeString(node.Tx)
			if err != nil {
				return
			}

			var tx wire.MsgTx
			err = tx.Deserialize(bytes.NewReader(raw))
			if err != nil {
				return
			}

			if sig, ok := sigs[tx.TxHash()]; ok && sig != nil {
				node.Signature = hex.EncodeToString(
					sig.Serialize(),
				)
			}
		}
	}

	signctx.Amend(commitment, noted)
}

// recordSigningNote notes a validated round under its commitment transaction,
// each of its tree transactions and digests, and the transaction of each
// connector a forfeit will spend. A round that will not render is left unnoted,
// which leaves a signer that wants a note refusing it.
func recordSigningNote(roundID RoundID, commitment *psbt.Packet,
	sweepKey *btcec.PublicKey, sweepDelay uint32,
	connectorKey *btcec.PublicKey, trees map[int]*tree.Tree,
	intents Intents, vtxoAmount func(int, types.VTXORequest) int64,
	forfeits map[wire.OutPoint]*ConnectorLeafInfo) {

	if !signctx.Enabled() || commitment == nil ||
		commitment.UnsignedTx == nil {

		return
	}

	var raw bytes.Buffer
	if err := commitment.UnsignedTx.Serialize(&raw); err != nil {
		return
	}

	keys := [][32]byte{commitment.UnsignedTx.TxHash()}
	noted := notedRound{
		CommitmentTx: hex.EncodeToString(raw.Bytes()),
		SweepKey:     compressedHex(sweepKey),
		SweepDelay:   sweepDelay,
	}

	for _, in := range commitment.Inputs {
		if in.WitnessUtxo == nil {
			return
		}
		noted.PrevOuts = append(noted.PrevOuts, notedOutput{
			Value:    in.WitnessUtxo.Value,
			PkScript: hex.EncodeToString(in.WitnessUtxo.PkScript),
		})
	}

	for index, path := range trees {
		rendered, ok := notedTreeOf(index, path, &keys)
		if !ok {
			return
		}
		noted.Trees = append(noted.Trees, *rendered)
	}

	for i, req := range intents.VTXOs {
		noted.VTXOs = append(noted.VTXOs, notedVTXO{
			SigningKey: compressedHex(req.SigningKey.PubKey),
			OwnerKey:   compressedHex(req.OwnerKey.PubKey),
			Amount:     vtxoAmount(i, req),
			PkScript:   hex.EncodeToString(req.PkScript),
			PolicyTemplate: hex.EncodeToString(
				req.PolicyTemplate,
			),
		})
	}

	for _, leave := range intents.Leaves {
		if leave == nil || leave.Output == nil {
			return
		}
		noted.Leaves = append(noted.Leaves, notedOutput{
			Value:    leave.Output.Value,
			PkScript: hex.EncodeToString(leave.Output.PkScript),
		})
	}

	for outpoint, info := range forfeits {
		if info == nil {
			return
		}
		path, ok := connectorPathOf(
			commitment.UnsignedTx, connectorKey, info,
		)
		if !ok {
			return
		}
		keys = append(keys, info.ConnectorOutpoint.Hash)
		noted.Forfeits = append(noted.Forfeits, notedForfeit{
			VTXOOutpoint:      outpoint.String(),
			VTXOAmount:        int64(info.VTXOAmount),
			ConnectorOutpoint: info.ConnectorOutpoint.String(),
			ConnectorPkScript: hex.EncodeToString(
				info.ConnectorPkScript,
			),
			ConnectorAmount: info.ConnectorAmount,
			ConnectorPath:   path,
		})
	}

	signctx.Record(signctx.KindRound, roundID.String(), keys, noted)
}
