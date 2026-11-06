package round

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/callbacksigner"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/bip322"
	"github.com/lightninglabs/wavelength/lib/signctx"
	"github.com/lightninglabs/wavelength/lib/tree"
	arktx "github.com/lightninglabs/wavelength/lib/tx"
	"github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

// groupManifestFixture is the manifest a Kotlin implementation computes for a
// fixed group key: walletdesc pins the same bytes.
const groupManifestFixture = `{"families":{"202":"[61504962/1017h/1h/202h]tpubDC2Q4xK4XH7BAenNARz6U8TAL11UqC9iqKTQMLwPUHkcaVskrJcaLPtVkHM73HzBtjBvs6xSMwwrKdfnPm7LEjcwGD1XuHeVnxM2bhxrex2/0/*#4cjxxt0d","42":"[61504962/1017h/1h/42h]tpubDC2Q4xK4XH747ybuRVuvViz8zat5GVWYr3odo1Yh9AmyWo3kS3ca5pyuGvb95QKPsbdaK46XJfddvWx9eGvRnH325f18Cz8FZ6Vu8YirRSK/0/*#d4xku9au","44":"[61504962/1017h/1h/44h]tpubDC2Q4xK4XH74D3owKbc1dk7VcgGVcyktHQ6R12u3QF585V2MDuSKDWoNSK1hte5wnysFN2c1oVVXJHsEf7a663Aygqfyvh4ZNk9kpmkjPdX/0/*#pw6xg84u","45":"[61504962/1017h/1h/45h]tpubDC2Q4xK4XH74G6VpFhDtCyqVkLKi86gn3mhaeikCZSGDozkLXn7iYZVL2c8BNiMdBkJAWqJ7NuPLuVGoq2JRZ9FF8RjBbznzrqLFSu8KMcN/0/*#x3j0eh0v","6":"[ac04f47d/1017h/1h/6h]tpubDC5MkyuEv1GqMW7urZE7cbSSr2v5gMd8UFEiqJqpcvx6dY6yj1okzVVVTuWuj5WqZJqchNCGCs69obGbXvZebs3U1jDtprGoRLey2gmcrjG/0/*#62zpkr4s"},"network":"regtest","onchain":"tr([61504962/86h/0h/0h]tpubDC2Q4xK4XH72Gn5JVi6ggnB5aESmPj6d22iRN7c3S2eS5wE3y8hoF8NBQ3mwkzAhtgGaFz25uT1vbkoyjJRGr8qwDjL3A3ysWJL8RQuSHkD/<0;1>/*)#kcs89q9g","primary_fingerprint":"ac04f47d","version":1}`

// recordingHost keeps every request and answers them with nothing useful, since
// a fixture is about what a host is asked.
type recordingHost struct {
	requests []json.RawMessage
}

// Handle implements callbacksigner.Host.
func (h *recordingHost) Handle(raw []byte) ([]byte, error) {
	h.requests = append(h.requests, json.RawMessage(bytes.Clone(raw)))

	return json.Marshal(&callbacksigner.Response{
		Signature:   hex.EncodeToString(make([]byte, 64)),
		SessionID:   hex.EncodeToString(make([]byte, 32)),
		PublicNonce: hex.EncodeToString(make([]byte, 66)),
	})
}

// aggregateFixtureSig is what a tree node's cosigners would make between them,
// and what a signer has to be able to verify before it gives anything up.
func aggregateFixtureSig(t *testing.T, cosigners []*btcec.PublicKey,
	privs map[string]*btcec.PrivateKey, digest, root []byte) *schnorr.Signature {

	t.Helper()

	sessions := make([]*musig2.Session, 0, len(cosigners))
	for _, key := range cosigners {
		priv := privs[hex.EncodeToString(key.SerializeCompressed())]
		require.NotNil(t, priv)

		// A context sorts its signers in place.
		signer, err := musig2.NewContext(
			priv, true, musig2.WithKnownSigners(
				slices.Clone(cosigners),
			),
			musig2.WithTaprootTweakCtx(root),
		)
		require.NoError(t, err)

		// Fixed nonces, so that the file a Kotlin test reads only
		// changes when what it describes does.
		seed := chainhash.HashB(append(
			key.SerializeCompressed(), digest...,
		))
		nonces, err := musig2.GenNonces(
			musig2.WithPublicKey(key),
			musig2.WithCustomRand(bytes.NewReader(seed)),
		)
		require.NoError(t, err)
		session, err := signer.NewSession(
			musig2.WithPreGeneratedNonce(nonces),
		)
		require.NoError(t, err)
		sessions = append(sessions, session)
	}
	for i, session := range sessions {
		for j, other := range sessions {
			if i == j {
				continue
			}
			_, err := session.RegisterPubNonce(other.PublicNonce())
			require.NoError(t, err)
		}
	}

	var message [32]byte
	copy(message[:], digest)
	for i, session := range sessions {
		partial, err := session.Sign(message)
		require.NoError(t, err)
		if i > 0 {
			_, err = sessions[0].CombineSig(partial)
			require.NoError(t, err)
		}
	}

	return sessions[0].FinalSig()
}

// policyFixtures is the JSON a Kotlin signing policy is tested against.
type policyFixtures struct {
	Operator   string          `json:"operator"`
	SweepKey   string          `json:"sweep_key"`
	SweepDelay uint32          `json:"sweep_delay"`
	ExitDelay  uint32          `json:"exit_delay"`
	TreeKey    string          `json:"tree_key"`
	Onchain    string          `json:"onchain_script"`
	OwnerKey   string          `json:"owner_key"`
	VTXOScript string          `json:"vtxo_script"`
	TreeSign   json.RawMessage `json:"tree_sign"`
	Forfeit    json.RawMessage `json:"forfeit"`
	Boarding   json.RawMessage `json:"boarding"`
	JoinProof  json.RawMessage `json:"join_proof"`
	ExitSweep  json.RawMessage `json:"exit_sweep"`
	OORArk     json.RawMessage `json:"oor_ark"`
	OORPoint   json.RawMessage `json:"oor_checkpoint"`
	IndexerMsg json.RawMessage `json:"indexer_message"`
}

// fixtureKeys derives the group's keys from the pinned manifest.
type fixtureKeys struct {
	t        *testing.T
	manifest *walletdesc.Manifest
}

// family derives a family key's public key at /0/index.
func (k *fixtureKeys) family(family int, index uint32) *btcec.PublicKey {
	var key *hdkeychain.ExtendedKey
	for f, slot := range k.manifest.Families {
		if int(f) == family {
			key = slot.Key
		}
	}
	require.NotNil(k.t, key)

	branch, err := key.Derive(0)
	require.NoError(k.t, err)
	child, err := branch.Derive(index)
	require.NoError(k.t, err)
	pub, err := child.ECPubKey()
	require.NoError(k.t, err)

	return pub
}

// signingPacket asks the signer for input idx of tx, as lnd's RPC key ring does.
func signingPacket(t *testing.T, tx *wire.MsgTx, prevOuts []*wire.TxOut, idx int,
	family, index uint32, key *btcec.PublicKey, leaf []byte,
	spendInfo *arkscript.SpendInfo) []byte {

	t.Helper()

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for i, prev := range prevOuts {
		packet.Inputs[i].WitnessUtxo = prev
		packet.Inputs[i].SighashType = txscript.SigHashDefault
	}

	const hardened = hdkeychain.HardenedKeyStart
	derivation := &psbt.TaprootBip32Derivation{
		XOnlyPubKey: schnorr.SerializePubKey(key),
		Bip32Path: []uint32{
			1017 + hardened, 1 + hardened, family + hardened, 0, index,
		},
	}
	tapLeaf := txscript.NewBaseTapLeaf(leaf)
	hash := tapLeaf.TapHash()
	derivation.LeafHashes = [][]byte{hash[:]}
	packet.Inputs[idx].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		derivation,
	}
	packet.Inputs[idx].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: spendInfo.ControlBlock,
		Script:       leaf,
		LeafVersion:  tapLeaf.LeafVersion,
	}}

	var buf bytes.Buffer
	require.NoError(t, packet.Serialize(&buf))

	return buf.Bytes()
}

// TestGroupPolicyFixtures builds a round, a transfer, a join and an exit out of
// this daemon's own builders, runs them through the callback signer and records
// what a host is asked, so a policy written elsewhere is tested against the real
// shapes. Set UPDATE_POLICY_FIXTURES to rewrite the file.
func TestGroupPolicyFixtures(t *testing.T) {
	signctx.Enable()
	t.Cleanup(signctx.Disable)

	manifest, err := walletdesc.ParseManifest(
		[]byte(groupManifestFixture), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	keys := &fixtureKeys{t: t, manifest: manifest}

	seeded := func(b byte) *btcec.PrivateKey {
		priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{b}, 32))

		return priv
	}
	operator := seeded(0x31).PubKey()
	treeKey := seeded(0x32).PubKey()
	otherTreeKey := seeded(0x33).PubKey()
	otherOwner := seeded(0x34).PubKey()
	sweepKey := seeded(0x35).PubKey()
	const (
		exitDelay  = uint32(144)
		sweepDelay = uint32(1000)
	)

	owner := keys.family(44, 5)
	receiver := keys.family(202, 1)
	boardingKey := keys.family(42, 0)

	// Where a leave pays: the group's onchain wallet, as far as this says.
	onchainScript, err := txscript.PayToTaprootScript(seeded(0x36).PubKey())
	require.NoError(t, err)

	sweepLeaf, err := arkscript.UnilateralCSVTimeoutTapLeaf(
		sweepKey, sweepDelay,
	)
	require.NoError(t, err)
	sweepRoot := sweepLeaf.TapHash()

	ownVTXO, err := tree.NewVTXODescriptor(
		btcutil.Amount(50_000), owner, operator, exitDelay,
	)
	require.NoError(t, err)
	otherVTXO, err := tree.NewVTXODescriptor(
		btcutil.Amount(30_000), otherOwner, operator, exitDelay,
	)
	require.NoError(t, err)
	ownLeaf := ownVTXO.ToLeafDescriptor()
	ownLeaf.CoSignerKey = treeKey
	otherLeaf := otherVTXO.ToLeafDescriptor()
	otherLeaf.CoSignerKey = otherTreeKey

	// The commitment: a boarding input of the group's, the operator's own
	// funding, the batch output and a connector output.
	boardingScript, err := arkscript.VTXOTapKey(
		boardingKey, operator, exitDelay,
	)
	require.NoError(t, err)
	boardingPkScript, err := txscript.PayToTaprootScript(boardingScript)
	require.NoError(t, err)
	operatorPkScript, err := txscript.PayToTaprootScript(operator)
	require.NoError(t, err)

	keysInTree := []*btcec.PublicKey{treeKey, otherTreeKey, operator}
	sort.Slice(keysInTree, func(i, j int) bool {
		return bytes.Compare(
			keysInTree[i].SerializeCompressed(),
			keysInTree[j].SerializeCompressed(),
		) < 0
	})
	combined, err := input.MuSig2CombineKeys(
		input.MuSig2Version100RC2, keysInTree, true,
		&input.MuSig2Tweaks{TaprootTweak: sweepRoot[:]},
	)
	require.NoError(t, err)
	batchScript, err := txscript.PayToTaprootScript(combined.FinalKey)
	require.NoError(t, err)

	commitment := wire.NewMsgTx(3)
	commitment.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xb0}},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	commitment.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xb1}},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	commitment.AddTxOut(&wire.TxOut{Value: 80_000, PkScript: batchScript})
	commitment.AddTxOut(&wire.TxOut{
		Value: 2 * 600, PkScript: operatorPkScript,
	})
	commitment.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: onchainScript})

	commitmentPrev := []*wire.TxOut{
		{Value: 20_000, PkScript: boardingPkScript},
		{Value: 500_000, PkScript: operatorPkScript},
	}
	commitmentPacket, err := psbt.NewFromUnsignedTx(commitment)
	require.NoError(t, err)
	commitmentPacket.Inputs[0].WitnessUtxo = commitmentPrev[0]
	commitmentPacket.Inputs[1].WitnessUtxo = commitmentPrev[1]

	vtxoTree, err := tree.NewTree(
		wire.OutPoint{Hash: commitment.TxHash()}, commitment.TxOut[0],
		[]tree.LeafDescriptor{ownLeaf, otherLeaf}, operator,
		sweepRoot[:], 2,
	)
	require.NoError(t, err)
	path, err := vtxoTree.ExtractPathForCoSigners(treeKey)
	require.NoError(t, err)

	connectors, err := tree.BuildConnectorTree(
		wire.OutPoint{Hash: commitment.TxHash(), Index: 1},
		commitment.TxOut[1], tree.ConnectorDescriptor{
			PkScript:  operatorPkScript,
			NumLeaves: 2,
			Amount:    btcutil.Amount(600),
		}, operator, 2,
	)
	require.NoError(t, err)
	connectorOutpoint, err := connectors.Root.GetLeafNodes()[0].
		GetNonAnchorOutpoint()
	require.NoError(t, err)

	spent := wire.OutPoint{Hash: chainhash.Hash{0xc0}, Index: 2}
	info := &ConnectorLeafInfo{
		LeafIndex:         0,
		ConnectorOutpoint: *connectorOutpoint,
		ConnectorPkScript: operatorPkScript,
		ConnectorAmount:   600,
		VTXOAmount:        btcutil.Amount(40_000),
		RootOutputIndex:   1,
		NumLeaves:         2,
		Radix:             2,
	}

	intents := Intents{
		VTXOs: []types.VTXORequest{{
			Amount: ownVTXO.Amount,
		}},
		// A leave pays what was asked for less the server's fee.
		Leaves: []*types.LeaveRequest{{
			Output: &wire.TxOut{
				Value:    commitment.TxOut[2].Value + 313,
				PkScript: commitment.TxOut[2].PkScript,
			},
		}},
		QuotedLeaveAmounts: []int64{commitment.TxOut[2].Value},
	}
	intents.VTXOs[0].SigningKey.PubKey = treeKey
	intents.VTXOs[0].OwnerKey.PubKey = owner
	intents.VTXOs[0].PolicyTemplate = ownVTXO.PolicyTemplate

	// The round that made the VTXO has already noted its transaction, and a
	// real forfeit has to find this round's note instead of that one.
	signctx.Record(
		signctx.KindRound, "the round that made it",
		[][32]byte{spent.Hash}, map[string]any{"forfeits": nil},
	)

	recordSigningNote(
		RoundID{}, commitmentPacket, sweepKey, sweepDelay, operator,
		map[int]*tree.Tree{0: path}, intents,
		func(_ int, req types.VTXORequest) int64 {
			return int64(req.Amount)
		},
		map[wire.OutPoint]*ConnectorLeafInfo{spent: info},
	)

	host := &recordingHost{}
	conn := callbacksigner.New(host, time.Second)
	defer conn.Stop()
	ctx := context.Background()

	take := func() json.RawMessage {
		require.NotEmpty(t, host.requests)
		last := host.requests[len(host.requests)-1]
		host.requests = nil

		return last
	}
	signPacket := func(raw []byte) json.RawMessage {
		_, err := conn.SignPsbt(ctx, &walletrpc.SignPsbtRequest{
			FundedPsbt: raw,
		})
		require.NoError(t, err)

		return take()
	}

	// A tree signature: the digest of the path's leaf.
	fetcher, err := path.Root.PrevOutputFetcher(path.BatchOutput)
	require.NoError(t, err)
	leafNode := path.Root.GetLeafNodes()[0]
	digest, err := leafNode.SigHash(fetcher)
	require.NoError(t, err)
	_, err = conn.MuSig2Sign(ctx, &signrpc.MuSig2SignRequest{
		SessionId: make([]byte, 32), MessageDigest: digest,
	})
	require.NoError(t, err)
	treeSign := take()

	// Everything after this comes once the tree has been signed.
	treePrivs := make(map[string]*btcec.PrivateKey)
	for _, b := range []byte{0x31, 0x32, 0x33} {
		priv := seeded(b)
		treePrivs[hex.EncodeToString(
			priv.PubKey().SerializeCompressed(),
		)] = priv
	}
	treeSigs := make(map[tree.TxID]*schnorr.Signature)
	for node := range path.Root.NodesIter() {
		nodeDigest, err := node.SigHash(fetcher)
		require.NoError(t, err)
		nodeTx, err := node.ToTx()
		require.NoError(t, err)
		treeSigs[nodeTx.TxHash()] = aggregateFixtureSig(
			t, node.CoSigners, treePrivs, nodeDigest,
			path.SweepTapscriptRoot,
		)
	}
	require.NoError(t, path.SubmitTreeSigs(treeSigs))
	require.NoError(t, path.VerifySigned())
	recordSignedTrees(commitment.TxHash(), treeSigs)

	// A forfeit of an old VTXO of the group's over that connector.
	oldOwner := keys.family(44, 3)
	oldVTXOKey, err := arkscript.VTXOTapKey(oldOwner, operator, exitDelay)
	require.NoError(t, err)
	oldScript, err := txscript.PayToTaprootScript(oldVTXOKey)
	require.NoError(t, err)
	oldSpend, err := arkscript.NewVTXOSpendInfoFromPolicy(
		oldOwner, operator, exitDelay, 0,
	)
	require.NoError(t, err)

	forfeitTx, err := arktx.BuildForfeitTx(
		&spent, btcutil.Amount(40_000), connectorOutpoint,
		btcutil.Amount(600), operatorPkScript,
	)
	require.NoError(t, err)
	forfeit := signPacket(signingPacket(
		t, forfeitTx, []*wire.TxOut{
			{Value: 40_000, PkScript: oldScript},
			{Value: 600, PkScript: operatorPkScript},
		}, 0, 44, 3, oldOwner, oldSpend.WitnessScript, oldSpend,
	))

	// The boarding input of the commitment.
	boardSpend, err := arkscript.NewVTXOSpendInfoFromPolicy(
		boardingKey, operator, exitDelay, 0,
	)
	require.NoError(t, err)
	boarding := signPacket(signingPacket(
		t, commitment.Copy(), commitmentPrev, 0, 42, 0, boardingKey,
		boardSpend.WitnessScript, boardSpend,
	))

	// A join proof, spending the exit leaf of that old VTXO.
	exitSpend, err := arkscript.NewVTXOSpendInfoFromPolicy(
		oldOwner, operator, exitDelay, 1,
	)
	require.NoError(t, err)
	identifier := seeded(0x37).PubKey()
	challenge, err := txscript.PayToTaprootScript(identifier)
	require.NoError(t, err)
	toSpend, err := bip322.BuildToSpend(
		bip322.MessageHash([]byte("join")), challenge,
	)
	require.NoError(t, err)
	toSign := wire.NewMsgTx(2)
	toSign.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: toSpend.TxHash()},
	})
	toSign.AddTxIn(&wire.TxIn{
		PreviousOutPoint: spent, Sequence: exitDelay,
	})
	toSign.AddTxOut(&wire.TxOut{PkScript: []byte{txscript.OP_RETURN}})
	recordJoinNote(toSpend, toSign)
	joinProof := signPacket(signingPacket(
		t, toSign, []*wire.TxOut{
			toSpend.TxOut[0], {Value: 40_000, PkScript: oldScript},
		}, 1, 44, 3, oldOwner, exitSpend.WitnessScript, exitSpend,
	))

	// An exit sweep to the group's onchain wallet.
	sweepTx := wire.NewMsgTx(2)
	sweepTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: spent, Sequence: exitDelay,
	})
	sweepTx.AddTxOut(&wire.TxOut{Value: 39_000, PkScript: onchainScript})
	exitSweep := signPacket(signingPacket(
		t, sweepTx, []*wire.TxOut{{Value: 40_000, PkScript: oldScript}},
		0, 44, 3, oldOwner, exitSpend.WitnessScript, exitSpend,
	))

	// A transfer to the group's own receive key: a checkpoint, then the
	// Ark transaction, through the real builders.
	collab := oldSpend.WitnessScript
	policy := arkscript.CheckpointPolicy{
		OperatorKey: operator, CSVDelay: exitDelay,
	}
	checkpointArtifact, err := oor.BuildCheckpointPSBT(
		policy, oor.CheckpointInput{
			SpentVTXO: oor.SpentVTXORef{
				Outpoint: spent,
				Output: &wire.TxOut{
					Value: 40_000, PkScript: oldScript,
				},
			},
			OwnerLeafScript: collab,
		},
	)
	require.NoError(t, err)
	checkpointOutput, err := checkpointArtifact.ToCheckpointOutput()
	require.NoError(t, err)

	receiverKey, err := arkscript.VTXOTapKey(receiver, operator, exitDelay)
	require.NoError(t, err)
	receiverScript, err := txscript.PayToTaprootScript(receiverKey)
	require.NoError(t, err)
	arkPacket, err := oor.BuildArkPSBT(
		[]oor.CheckpointOutput{checkpointOutput},
		[]oor.RecipientOutput{{
			PkScript: receiverScript, Value: btcutil.Amount(40_000),
		}},
	)
	require.NoError(t, err)

	notedArk := func(packet *psbt.Packet) notedRoundTx {
		var raw bytes.Buffer
		require.NoError(t, packet.UnsignedTx.Serialize(&raw))
		noted := notedRoundTx{Tx: hex.EncodeToString(raw.Bytes())}
		for _, in := range packet.Inputs {
			require.NotNil(t, in.WitnessUtxo)
			noted.PrevOuts = append(noted.PrevOuts, notedOutput{
				Value: in.WitnessUtxo.Value,
				PkScript: hex.EncodeToString(
					in.WitnessUtxo.PkScript,
				),
			})
		}

		return noted
	}
	arkTxid := arkPacket.UnsignedTx.TxHash()
	signctx.Record(
		signctx.KindOOR, arkTxid.String(), [][32]byte{
			arkTxid, checkpointArtifact.PSBT.UnsignedTx.TxHash(),
		},
		map[string]any{
			"ark":         notedArk(arkPacket),
			"checkpoints": []notedRoundTx{notedArk(checkpointArtifact.PSBT)},
		},
	)

	arkPrev := []*wire.TxOut{checkpointOutput.Output}
	checkpointSpend := oldSpend
	oorArk := signPacket(signingPacket(
		t, arkPacket.UnsignedTx.Copy(), arkPrev, 0, 44, 3, oldOwner,
		collab, checkpointSpend,
	))

	// The operator co-signs the Ark transaction, and only then is a
	// checkpoint asked for.
	arkFetcher := txscript.NewCannedPrevOutputFetcher(
		checkpointOutput.Output.PkScript, checkpointOutput.Output.Value,
	)
	operatorDigest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(arkPacket.UnsignedTx, arkFetcher),
		txscript.SigHashDefault, arkPacket.UnsignedTx, 0, arkFetcher,
		txscript.NewBaseTapLeaf(collab),
	)
	require.NoError(t, err)
	operatorSig, err := schnorr.Sign(seeded(0x31), operatorDigest)
	require.NoError(t, err)
	coSignedArk := notedArk(arkPacket)
	coSignedArk.Sigs = []notedRoundSig{{
		Input:     0,
		Signature: hex.EncodeToString(operatorSig.Serialize()),
	}}
	signctx.Amend(arkTxid, map[string]any{
		"ark":         coSignedArk,
		"checkpoints": []notedRoundTx{notedArk(checkpointArtifact.PSBT)},
	})

	oorPoint := signPacket(signingPacket(
		t, checkpointArtifact.PSBT.UnsignedTx.Copy(),
		[]*wire.TxOut{{Value: 40_000, PkScript: oldScript}}, 0, 44, 3,
		oldOwner, collab, oldSpend,
	))

	// An indexer proof under a VTXO owner key.
	_, err = conn.SignMessage(ctx, &signrpc.SignMessageReq{
		Msg:        []byte("query scope"),
		KeyLoc:     &signrpc.KeyLocator{KeyFamily: 44, KeyIndex: 3},
		SchnorrSig: true,
		Tag:        []byte("wavelength/indexer/v1"),
	})
	require.NoError(t, err)
	indexerMsg := take()

	fixtures := policyFixtures{
		Operator:   hex.EncodeToString(operator.SerializeCompressed()),
		SweepKey:   hex.EncodeToString(sweepKey.SerializeCompressed()),
		SweepDelay: sweepDelay,
		ExitDelay:  exitDelay,
		TreeKey:    hex.EncodeToString(treeKey.SerializeCompressed()),
		Onchain:    hex.EncodeToString(onchainScript),
		OwnerKey:   hex.EncodeToString(owner.SerializeCompressed()),
		VTXOScript: hex.EncodeToString(ownVTXO.PkScript),
		TreeSign:   treeSign,
		Forfeit:    forfeit,
		Boarding:   boarding,
		JoinProof:  joinProof,
		ExitSweep:  exitSweep,
		OORArk:     oorArk,
		OORPoint:   oorPoint,
		IndexerMsg: indexerMsg,
	}

	rendered, err := json.MarshalIndent(&fixtures, "", " ")
	require.NoError(t, err)

	file := filepath.Join("testdata", "group_policy_fixtures.json")
	if os.Getenv("UPDATE_POLICY_FIXTURES") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(file, rendered, 0o644))
	}

	want, err := os.ReadFile(file)
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(rendered))
}

// notedRoundSig mirrors a signature the oor package notes on a transfer.
type notedRoundSig struct {
	Input     int    `json:"input"`
	Signature string `json:"signature"`
}

// notedRoundTx mirrors the shape the oor package notes a transfer in.
type notedRoundTx struct {
	Tx       string          `json:"tx"`
	PrevOuts []notedOutput   `json:"prev_outs"`
	Sigs     []notedRoundSig `json:"sigs,omitempty"`
}
