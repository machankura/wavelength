package callbacksigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/signctx"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/require"
)

// keyHost answers with one private key, and recomputes every digest from what
// the request carries, as a host that judges requests has to.
type keyHost struct {
	t        *testing.T
	priv     *btcec.PrivateKey
	requests []Request
	delay    time.Duration
	refuse   error
}

// Handle implements Host.
func (h *keyHost) Handle(raw []byte) ([]byte, error) {
	if h.delay > 0 {
		time.Sleep(h.delay)
	}

	var req Request
	require.NoError(h.t, json.Unmarshal(raw, &req))
	h.requests = append(h.requests, req)

	if h.refuse != nil {
		return nil, h.refuse
	}

	var resp Response
	switch req.Kind {
	case KindInput:
		digest := h.recompute(&req)
		require.Equal(h.t, req.Digest, hex.EncodeToString(digest))

		priv := h.priv
		switch req.Method {
		case MethodBIP86:
			priv = txscript.TweakTaprootPrivKey(*priv, nil)

		case MethodKeyPath:
			root, err := hex.DecodeString(req.MerkleRoot)
			require.NoError(h.t, err)
			priv = txscript.TweakTaprootPrivKey(*priv, root)
		}

		sig, err := schnorr.Sign(priv, digest)
		require.NoError(h.t, err)
		resp.Signature = hex.EncodeToString(sig.Serialize())

	case KindMessage:
		msg, err := hex.DecodeString(req.Message)
		require.NoError(h.t, err)
		digest := chainhash.TaggedHash([]byte(req.Tag), msg)
		sig, err := schnorr.Sign(h.priv, digest[:])
		require.NoError(h.t, err)
		resp.Signature = hex.EncodeToString(sig.Serialize())

	case KindMuSig2Create:
		resp.SessionID = hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
		resp.PublicNonce = hex.EncodeToString(
			bytes.Repeat([]byte{2}, 66),
		)

	case KindMuSig2Sign:
		resp.Signature = hex.EncodeToString(bytes.Repeat([]byte{9}, 32))

	case KindNextTreeKey:
		resp.Index = 3
		resp.PubKey = hex.EncodeToString(
			h.priv.PubKey().SerializeCompressed(),
		)
	}

	answer, err := json.Marshal(&resp)
	require.NoError(h.t, err)

	return answer, nil
}

// recompute rebuilds a request's digest from its transaction and prevouts.
func (h *keyHost) recompute(req *Request) []byte {
	rawTx, err := hex.DecodeString(req.Tx)
	require.NoError(h.t, err)

	tx := wire.NewMsgTx(2)
	require.NoError(h.t, tx.Deserialize(bytes.NewReader(rawTx)))

	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i, out := range req.PrevOuts {
		script, err := hex.DecodeString(out.PkScript)
		require.NoError(h.t, err)
		prevOuts[tx.TxIn[i].PreviousOutPoint] = &wire.TxOut{
			Value: out.Value, PkScript: script,
		}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	var digest []byte
	if req.Method == MethodScriptPath {
		script, err := hex.DecodeString(req.LeafScript)
		require.NoError(h.t, err)
		digest, err = txscript.CalcTapscriptSignaturehash(
			sigHashes, txscript.SigHashDefault, tx, req.InputIndex,
			fetcher, txscript.NewBaseTapLeaf(script),
		)
		require.NoError(h.t, err)
	} else {
		digest, err = txscript.CalcTaprootSignatureHash(
			sigHashes, txscript.SigHashDefault, tx, req.InputIndex,
			fetcher,
		)
		require.NoError(h.t, err)
	}

	return digest
}

// fixture is a transaction spending one taproot output of a key, with a PSBT.
type fixture struct {
	priv   *btcec.PrivateKey
	leaf   txscript.TapLeaf
	packet *psbt.Packet
	output *wire.TxOut
}

// newFixture builds a one-input PSBT spending a leaf, or the BIP86 key path.
func newFixture(t *testing.T, scriptPath bool) *fixture {
	t.Helper()

	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	xonly := schnorr.SerializePubKey(priv.PubKey())

	leafScript, err := txscript.NewScriptBuilder().AddData(xonly).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	leaf := txscript.NewBaseTapLeaf(leafScript)

	var outputKey *btcec.PublicKey
	var controlBlock []byte
	if scriptPath {
		tree := txscript.AssembleTaprootScriptTree(leaf)
		root := tree.RootNode.TapHash()
		outputKey = txscript.ComputeTaprootOutputKey(
			priv.PubKey(), root[:],
		)
		block := tree.LeafMerkleProofs[0].ToControlBlock(priv.PubKey())
		controlBlock, err = block.ToBytes()
		require.NoError(t, err)
	} else {
		outputKey = txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	}
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{1},
	}})
	tx.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	output := &wire.TxOut{Value: 1000, PkScript: pkScript}
	in := &packet.Inputs[0]
	in.WitnessUtxo = output
	in.SighashType = txscript.SigHashDefault

	const hardened = 0x80000000
	derivation := &psbt.TaprootBip32Derivation{
		XOnlyPubKey: xonly,
		Bip32Path: []uint32{
			hardened + 1017, hardened, hardened + 44, 0, 5,
		},
	}
	if scriptPath {
		hash := leaf.TapHash()
		derivation.LeafHashes = [][]byte{hash[:]}
		in.TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: controlBlock,
			Script:       leafScript,
			LeafVersion:  leaf.LeafVersion,
		}}
	}
	in.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{derivation}

	return &fixture{
		priv: priv, leaf: leaf, packet: packet, output: output,
	}
}

// signed runs a fixture through conn and returns the PSBT that comes back.
func (f *fixture) sign(t *testing.T, conn *Conn) (*psbt.Packet, error) {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, f.packet.Serialize(&buf))

	resp, err := conn.SignPsbt(
		context.Background(), &walletrpc.SignPsbtRequest{
			FundedPsbt: buf.Bytes(),
		},
	)
	if err != nil {
		return nil, err
	}

	return psbt.NewFromRawBytes(bytes.NewReader(resp.SignedPsbt), false)
}

// TestSignPsbtKeyPath proves the host gets the whole transaction, and that
// its signature ends up where the key ring reads it from.
func TestSignPsbtKeyPath(t *testing.T) {
	f := newFixture(t, false)
	host := &keyHost{t: t, priv: f.priv}
	conn := New(host, time.Second)
	defer conn.Stop()

	signed, err := f.sign(t, conn)
	require.NoError(t, err)

	req := host.requests[0]
	require.Equal(t, MethodBIP86, req.Method)
	require.Equal(t, int32(44), req.Family)
	require.Equal(t, uint32(5), req.Index)
	require.Len(t, req.PrevOuts, 1)

	tx := signed.UnsignedTx
	tx.TxIn[0].Witness = wire.TxWitness{signed.Inputs[0].TaprootKeySpendSig}
	fetcher := txscript.NewCannedPrevOutputFetcher(
		f.output.PkScript, f.output.Value,
	)
	vm, err := txscript.NewEngine(
		f.output.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), f.output.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())
}

// TestSignPsbtScriptPath proves a leaf spend names its leaf, and the signature
// verifies under the leaf's sighash.
func TestSignPsbtScriptPath(t *testing.T) {
	f := newFixture(t, true)
	host := &keyHost{t: t, priv: f.priv}
	conn := New(host, time.Second)
	defer conn.Stop()

	signed, err := f.sign(t, conn)
	require.NoError(t, err)

	req := host.requests[0]
	require.Equal(t, MethodScriptPath, req.Method)
	require.Equal(t, hex.EncodeToString(f.leaf.Script), req.LeafScript)

	spends := signed.Inputs[0].TaprootScriptSpendSig
	require.Len(t, spends, 1)
	sig, err := schnorr.ParseSignature(spends[0].Signature)
	require.NoError(t, err)

	digest, err := hex.DecodeString(req.Digest)
	require.NoError(t, err)
	require.True(t, sig.Verify(digest, f.priv.PubKey()))
}

// TestSignPsbtRefusals proves what a group must not be asked to sign never
// reaches it.
func TestSignPsbtRefusals(t *testing.T) {
	cases := map[string]func(*psbt.PInput){
		"a sighash other than the default": func(in *psbt.PInput) {
			in.SighashType = txscript.SigHashSingle
		},
		"a tweaked key": func(in *psbt.PInput) {
			in.Unknowns = []*psbt.Unknown{{
				Key:   btcwallet.PsbtKeyTypeInputSignatureTweakSingle,
				Value: []byte{1},
			}}
		},
		"a path outside the wallet's": func(in *psbt.PInput) {
			in.TaprootBip32Derivation[0].Bip32Path = []uint32{1, 2}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, false)
			mutate(&f.packet.Inputs[0])
			host := &keyHost{t: t, priv: f.priv}
			conn := New(host, time.Second)
			defer conn.Stop()

			_, err := f.sign(t, conn)
			require.ErrorIs(t, err, ErrUnsupported)
			require.Empty(t, host.requests)
		})
	}
}

// TestHostRefusalIsAnError proves a refusal fails the daemon's call instead of
// returning an empty signature.
func TestHostRefusalIsAnError(t *testing.T) {
	f := newFixture(t, false)
	refused := errors.New("no authorisation")
	conn := New(&keyHost{t: t, priv: f.priv, refuse: refused}, time.Second)
	defer conn.Stop()

	_, err := f.sign(t, conn)
	require.ErrorIs(t, err, refused)
}

// TestSlowHostTimesOut proves the daemon's deadline holds against a host that
// has not answered, and that the late answer goes nowhere.
func TestSlowHostTimesOut(t *testing.T) {
	f := newFixture(t, false)
	host := &keyHost{t: t, priv: f.priv, delay: 200 * time.Millisecond}
	conn := New(host, time.Second)
	defer conn.Stop()

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Millisecond,
	)
	defer cancel()

	_, err := conn.SignMessage(ctx, &signrpc.SignMessageReq{
		Msg:    []byte("m"),
		KeyLoc: &signrpc.KeyLocator{KeyFamily: 6},
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	time.Sleep(250 * time.Millisecond)
}

// TestNotesReachTheHost proves a forfeit's request carries the note of the
// round whose connector it spends, and a tree signature its digest's.
func TestNotesReachTheHost(t *testing.T) {
	f := newFixture(t, false)
	host := &keyHost{t: t, priv: f.priv}
	conn := New(host, time.Second)
	defer conn.Stop()

	connector := f.packet.UnsignedTx.TxIn[0].PreviousOutPoint.Hash
	signctx.Record(
		signctx.KindRound, "round", [][32]byte{connector},
		map[string]string{"x": "y"},
	)
	_, err := f.sign(t, conn)
	require.NoError(t, err)
	require.NotNil(t, host.requests[0].Note)
	require.Equal(t, "round", host.requests[0].Note.ID)

	digest := bytes.Repeat([]byte{0xaa}, 32)
	var key [32]byte
	copy(key[:], digest)
	signctx.Record(signctx.KindRound, "tree", [][32]byte{key}, 1)
	_, err = conn.MuSig2Sign(
		context.Background(), &signrpc.MuSig2SignRequest{
			SessionId: bytes.Repeat([]byte{7}, 32), MessageDigest: digest,
		},
	)
	require.NoError(t, err)
	require.Equal(t, "tree", host.requests[1].Note.ID)
}

// TestMuSig2CreateComputesTheAggregate proves the daemon's session reports the
// key the tree expects, computed here and not taken from the host.
func TestMuSig2CreateComputesTheAggregate(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	other, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
	host := &keyHost{t: t, priv: priv}
	conn := New(host, time.Second)
	defer conn.Stop()

	resp, err := conn.MuSig2CreateSession(
		context.Background(), &signrpc.MuSig2SessionRequest{
			KeyLoc: &signrpc.KeyLocator{KeyFamily: 45, KeyIndex: 2},
			AllSignerPubkeys: [][]byte{
				priv.PubKey().SerializeCompressed(),
				other.PubKey().SerializeCompressed(),
			},
			TaprootTweak: &signrpc.TaprootTweakDesc{
				ScriptRoot: bytes.Repeat([]byte{3}, 32),
			},
			Version: signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2,
		},
	)
	require.NoError(t, err)
	require.Len(t, resp.CombinedKey, 32)
	require.Len(t, resp.LocalPublicNonces, 66)
	require.Equal(t, int32(45), host.requests[0].Family)
	require.Equal(t, uint32(2), host.requests[0].Index)

	_, err = conn.MuSig2CreateSession(
		context.Background(), &signrpc.MuSig2SessionRequest{
			KeyLoc: &signrpc.KeyLocator{KeyFamily: 45},
			AllSignerPubkeys: [][]byte{
				priv.PubKey().SerializeCompressed(),
			},
			Version: signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2,
		},
	)
	require.ErrorIs(t, err, ErrUnsupported, "no script root")
}
