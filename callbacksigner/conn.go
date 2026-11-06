package callbacksigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/lib/signctx"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"google.golang.org/grpc"
)

// Request kinds a Host answers.
const (
	// KindMessage signs a message: an authentication key's at once, or a
	// fund key's indexer proof through the group.
	KindMessage = "message"

	// KindSharedKey computes an ECDH secret with an authentication key.
	KindSharedKey = "shared_key"

	// KindInput signs one input of a transaction.
	KindInput = "input"

	// KindMuSig2Create starts a MuSig2 session and returns its nonce.
	KindMuSig2Create = "musig2_create"

	// KindMuSig2Nonce gives a session its aggregate nonce.
	KindMuSig2Nonce = "musig2_nonce"

	// KindMuSig2Sign asks for a session's partial signature.
	KindMuSig2Sign = "musig2_sign"

	// KindMuSig2Cleanup drops a session.
	KindMuSig2Cleanup = "musig2_cleanup"

	// KindNextTreeKey allocates a tree key for a new VTXO.
	KindNextTreeKey = "next_tree_key"

	// KindTreeKey reads an allocated tree key back.
	KindTreeKey = "tree_key"
)

// Input spending methods.
const (
	// MethodBIP86 is a key-path spend of a BIP86 output.
	MethodBIP86 = "bip86"

	// MethodKeyPath is a key-path spend of an output with a script root.
	MethodKeyPath = "key_path"

	// MethodScriptPath is a tapscript spend of one leaf.
	MethodScriptPath = "script_path"
)

// Host answers a daemon's signing requests. Both sides are JSON: a Request,
// and a Response. It may block for as long as the request timeout allows, and
// the daemon stops waiting after that, whatever the host goes on to do.
//
// gomobile binds this interface, so a host can be written in Kotlin or Swift.
type Host interface {
	// Handle answers one request.
	Handle(request []byte) ([]byte, error)
}

// PrevOut is an output a transaction spends.
type PrevOut struct {
	Value    int64  `json:"value"`
	PkScript string `json:"pk_script"`
}

// Request is one thing the daemon asks of its host. Binary fields are hex.
type Request struct {
	Kind string `json:"kind"`

	// Family and Index name the key. Family is -1 for the on-chain
	// account, whose Branch is then meaningful.
	Family int32  `json:"family"`
	Branch uint32 `json:"branch,omitempty"`
	Index  uint32 `json:"index"`

	// PubKey is the key the daemon expects to be signed for, compressed.
	PubKey string `json:"pub_key,omitempty"`

	// Message fields.
	Message    string `json:"message,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Schnorr    bool   `json:"schnorr,omitempty"`
	Compact    bool   `json:"compact,omitempty"`
	DoubleHash bool   `json:"double_hash,omitempty"`
	TapTweak   string `json:"tap_tweak,omitempty"`

	// Peer is the other side's public key, for a shared key.
	Peer string `json:"peer,omitempty"`

	// Input fields: the unsigned transaction, every prevout in input
	// order, and how this input is spent.
	Tx          string    `json:"tx,omitempty"`
	PrevOuts    []PrevOut `json:"prev_outs,omitempty"`
	InputIndex  int       `json:"input_index,omitempty"`
	Method      string    `json:"method,omitempty"`
	MerkleRoot  string    `json:"merkle_root,omitempty"`
	LeafScript  string    `json:"leaf_script,omitempty"`
	LeafVersion int       `json:"leaf_version,omitempty"`

	// Digest is what the daemon computed, for the host to compare with
	// its own. It is never a reason to sign.
	Digest string `json:"digest,omitempty"`

	// MuSig2 fields.
	SessionID     string   `json:"session_id,omitempty"`
	Signers       []string `json:"signers,omitempty"`
	ScriptRoot    string   `json:"script_root,omitempty"`
	CombinedNonce string   `json:"combined_nonce,omitempty"`

	// Note is what the daemon said about this request, if anything.
	Note *signctx.Note `json:"note,omitempty"`
}

// Response is a host's answer. Binary fields are hex.
type Response struct {
	Signature   string `json:"signature,omitempty"`
	SharedKey   string `json:"shared_key,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	PublicNonce string `json:"public_nonce,omitempty"`
	PubKey      string `json:"pub_key,omitempty"`
	Index       uint32 `json:"index,omitempty"`
}

// ErrUnsupported is returned for a request this signer cannot describe to its
// host, which is refused rather than signed.
var ErrUnsupported = errors.New("request not supported by a callback signer")

// Conn is a signer connection whose answers come from a Host.
type Conn struct {
	host           Host
	requestTimeout time.Duration
}

var _ rpcwallet.RemoteSignerConnection = (*Conn)(nil)

// New returns a connection over host. It enables signctx for as long as the
// connection is open.
func New(host Host, requestTimeout time.Duration) *Conn {
	signctx.Enable()

	return &Conn{host: host, requestTimeout: requestTimeout}
}

// call sends req to the host and waits for its answer or for ctx. A host call
// cannot be cancelled, so a late answer is dropped.
func (c *Conn) call(ctx context.Context, req *Request) (*Response, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		answer, err := c.host.Handle(raw)
		done <- result{raw: answer, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}

		var resp Response
		if err := json.Unmarshal(res.raw, &resp); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}

		return &resp, nil
	}
}

// decode parses a hex field of a host's answer, which must not be empty.
func decode(field, text string) ([]byte, error) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("host answered with a bad %s", field)
	}

	return raw, nil
}

// SignMessage implements rpcwallet.RemoteSignerRequests.
func (c *Conn) SignMessage(ctx context.Context, in *signrpc.SignMessageReq,
	_ ...grpc.CallOption) (*signrpc.SignMessageResp, error) {

	if in.KeyLoc == nil {
		return nil, errors.New("a key locator must be passed in")
	}

	resp, err := c.call(ctx, &Request{
		Kind:       KindMessage,
		Family:     in.KeyLoc.KeyFamily,
		Index:      uint32(in.KeyLoc.KeyIndex),
		Message:    hex.EncodeToString(in.Msg),
		Tag:        string(in.Tag),
		Schnorr:    in.SchnorrSig,
		Compact:    in.CompactSig,
		DoubleHash: in.DoubleHash,
		TapTweak:   hex.EncodeToString(in.SchnorrSigTapTweak),
	})
	if err != nil {
		return nil, err
	}

	sig, err := decode("signature", resp.Signature)
	if err != nil {
		return nil, err
	}

	return &signrpc.SignMessageResp{Signature: sig}, nil
}

// DeriveSharedKey implements rpcwallet.RemoteSignerRequests.
func (c *Conn) DeriveSharedKey(ctx context.Context,
	in *signrpc.SharedKeyRequest, _ ...grpc.CallOption) (
	*signrpc.SharedKeyResponse, error) {

	family := int32(keychain.KeyFamilyNodeKey)
	var index int32
	switch {
	case in.GetKeyDesc().GetKeyLoc() != nil:
		family = in.GetKeyDesc().GetKeyLoc().GetKeyFamily()
		index = in.GetKeyDesc().GetKeyLoc().GetKeyIndex()

	case in.GetKeyLoc() != nil:
		family = in.GetKeyLoc().GetKeyFamily()
		index = in.GetKeyLoc().GetKeyIndex()
	}

	resp, err := c.call(ctx, &Request{
		Kind:   KindSharedKey,
		Family: family,
		Index:  uint32(index),
		Peer:   hex.EncodeToString(in.EphemeralPubkey),
	})
	if err != nil {
		return nil, err
	}

	secret, err := decode("shared key", resp.SharedKey)
	if err != nil {
		return nil, err
	}

	return &signrpc.SharedKeyResponse{SharedKey: secret}, nil
}

// MuSig2CreateSession implements rpcwallet.RemoteSignerRequests. The aggregate
// comes from the same code a tree's own validation uses, so the host only has
// to say what its nonce is.
func (c *Conn) MuSig2CreateSession(ctx context.Context,
	in *signrpc.MuSig2SessionRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2SessionResponse, error) {

	switch {
	case in.KeyLoc == nil:
		return nil, errors.New("missing key_loc")

	case in.Version != signrpc.MuSig2Version_MUSIG2_VERSION_V100RC2:
		return nil, fmt.Errorf("%w: MuSig2 version %v", ErrUnsupported,
			in.Version)

	case len(in.Tweaks) > 0, len(in.PregeneratedLocalNonce) > 0,
		len(in.OtherSignerPublicNonces) > 0:

		return nil, fmt.Errorf("%w: generic tweaks or supplied nonces",
			ErrUnsupported)

	case in.TaprootTweak == nil || in.TaprootTweak.KeySpendOnly:
		return nil, fmt.Errorf("%w: a session without a script root",
			ErrUnsupported)
	}

	version := input.MuSig2Version100RC2
	signers, err := input.MuSig2ParsePubKeys(version, in.AllSignerPubkeys)
	if err != nil {
		return nil, fmt.Errorf("signer public keys: %w", err)
	}

	tweaks := &input.MuSig2Tweaks{TaprootTweak: in.TaprootTweak.ScriptRoot}
	combined, err := input.MuSig2CombineKeys(version, signers, true, tweaks)
	if err != nil {
		return nil, fmt.Errorf("combine keys: %w", err)
	}

	req := &Request{
		Kind:       KindMuSig2Create,
		Family:     in.KeyLoc.KeyFamily,
		Index:      uint32(in.KeyLoc.KeyIndex),
		ScriptRoot: hex.EncodeToString(in.TaprootTweak.ScriptRoot),
	}
	for _, key := range in.AllSignerPubkeys {
		req.Signers = append(req.Signers, hex.EncodeToString(key))
	}

	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}

	sessionID, err := decode("session id", resp.SessionID)
	if err != nil {
		return nil, err
	}
	nonce, err := decode("public nonce", resp.PublicNonce)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2SessionResponse{
		SessionId:   sessionID,
		CombinedKey: combined.FinalKey.SerializeCompressed()[1:],
		TaprootInternalKey: combined.PreTweakedKey.
			SerializeCompressed()[1:],
		LocalPublicNonces: nonce,
		Version:           in.Version,
	}, nil
}

// MuSig2RegisterNonces implements rpcwallet.RemoteSignerRequests. A tree
// session is given its aggregate nonce and never individual ones.
func (c *Conn) MuSig2RegisterNonces(context.Context,
	*signrpc.MuSig2RegisterNoncesRequest, ...grpc.CallOption) (
	*signrpc.MuSig2RegisterNoncesResponse, error) {

	return nil, fmt.Errorf("%w: individual nonces", ErrUnsupported)
}

// MuSig2RegisterCombinedNonce implements rpcwallet.RemoteSignerRequests.
func (c *Conn) MuSig2RegisterCombinedNonce(ctx context.Context,
	in *signrpc.MuSig2RegisterCombinedNonceRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2RegisterCombinedNonceResponse,
	error) {

	_, err := c.call(ctx, &Request{
		Kind:          KindMuSig2Nonce,
		SessionID:     hex.EncodeToString(in.SessionId),
		CombinedNonce: hex.EncodeToString(in.CombinedPublicNonce),
	})
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2RegisterCombinedNonceResponse{}, nil
}

// MuSig2GetCombinedNonce implements rpcwallet.RemoteSignerRequests.
func (c *Conn) MuSig2GetCombinedNonce(context.Context,
	*signrpc.MuSig2GetCombinedNonceRequest, ...grpc.CallOption) (
	*signrpc.MuSig2GetCombinedNonceResponse, error) {

	return nil, fmt.Errorf("%w: reading a combined nonce", ErrUnsupported)
}

// MuSig2Sign implements rpcwallet.RemoteSignerRequests.
func (c *Conn) MuSig2Sign(ctx context.Context, in *signrpc.MuSig2SignRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SignResponse, error) {

	req := &Request{
		Kind:      KindMuSig2Sign,
		SessionID: hex.EncodeToString(in.SessionId),
		Digest:    hex.EncodeToString(in.MessageDigest),
	}
	if len(in.MessageDigest) == chainhash.HashSize {
		var key [chainhash.HashSize]byte
		copy(key[:], in.MessageDigest)
		if note, ok := signctx.Lookup(key); ok {
			req.Note = note
		}
	}

	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}

	sig, err := decode("partial signature", resp.Signature)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2SignResponse{LocalPartialSignature: sig}, nil
}

// MuSig2CombineSig implements rpcwallet.RemoteSignerRequests. The operator
// aggregates a tree's signatures.
func (c *Conn) MuSig2CombineSig(context.Context,
	*signrpc.MuSig2CombineSigRequest, ...grpc.CallOption) (
	*signrpc.MuSig2CombineSigResponse, error) {

	return nil, fmt.Errorf("%w: combining signatures", ErrUnsupported)
}

// MuSig2Cleanup implements rpcwallet.RemoteSignerRequests.
func (c *Conn) MuSig2Cleanup(ctx context.Context,
	in *signrpc.MuSig2CleanupRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2CleanupResponse, error) {

	_, err := c.call(ctx, &Request{
		Kind:      KindMuSig2Cleanup,
		SessionID: hex.EncodeToString(in.SessionId),
	})
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2CleanupResponse{}, nil
}

// SignPsbt implements rpcwallet.RemoteSignerRequests: one host request per
// input that names a key this wallet holds. Other inputs are left for whoever
// else signs them, as lnd's own SignPsbt leaves them.
func (c *Conn) SignPsbt(ctx context.Context, in *walletrpc.SignPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.SignPsbtResponse, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(in.FundedPsbt), false,
	)
	if err != nil {
		return nil, fmt.Errorf("parse PSBT: %w", err)
	}
	if err := psbt.InputsReadyToSign(packet); err != nil {
		return nil, err
	}

	tx := packet.UnsignedTx
	fetcher := wallet.PsbtPrevOutputFetcher(packet)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	var rawTx bytes.Buffer
	if err := tx.Serialize(&rawTx); err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}

	prevOuts := make([]PrevOut, len(tx.TxIn))
	for i, txIn := range tx.TxIn {
		out := fetcher.FetchPrevOutput(txIn.PreviousOutPoint)
		if out == nil {
			return nil, fmt.Errorf("input %d has no prevout", i)
		}
		prevOuts[i] = PrevOut{
			Value:    out.Value,
			PkScript: hex.EncodeToString(out.PkScript),
		}
	}

	var signed []uint32
	for idx := range tx.TxIn {
		pIn := &packet.Inputs[idx]
		if pIn.WitnessUtxo == nil || len(pIn.FinalScriptWitness) > 0 ||
			len(pIn.TaprootBip32Derivation) == 0 {

			continue
		}

		req, err := inputRequest(tx, sigHashes, idx, pIn, fetcher)
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", idx, err)
		}
		req.Tx = hex.EncodeToString(rawTx.Bytes())
		req.PrevOuts = prevOuts

		resp, err := c.call(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", idx, err)
		}

		sig, err := decode("signature", resp.Signature)
		if err != nil {
			return nil, err
		}

		if req.Method == MethodScriptPath {
			derivation := pIn.TaprootBip32Derivation[0]
			pIn.TaprootScriptSpendSig = append(
				pIn.TaprootScriptSpendSig,
				&psbt.TaprootScriptSpendSig{
					XOnlyPubKey: derivation.XOnlyPubKey,
					LeafHash:    derivation.LeafHashes[0],
					Signature:   sig,
					SigHash:     pIn.SighashType,
				},
			)
		} else {
			pIn.TaprootKeySpendSig = sig
		}

		signed = append(signed, uint32(idx))
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

// inputRequest describes one taproot input to the host, and refuses what a
// threshold group has no business signing.
func inputRequest(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
	pIn *psbt.PInput, fetcher txscript.PrevOutputFetcher) (*Request,
	error) {

	if pIn.SighashType != txscript.SigHashDefault {
		return nil, fmt.Errorf("%w: sighash type %d", ErrUnsupported,
			pIn.SighashType)
	}
	if len(pIn.Unknowns) > 0 {
		return nil, fmt.Errorf("%w: a tweaked key", ErrUnsupported)
	}
	if len(pIn.TaprootBip32Derivation) != 1 {
		return nil, fmt.Errorf("%w: several keys on one input",
			ErrUnsupported)
	}

	derivation := pIn.TaprootBip32Derivation[0]
	family, branch, index, err := locatorOf(derivation.Bip32Path)
	if err != nil {
		return nil, err
	}

	req := &Request{
		Kind:       KindInput,
		Family:     family,
		Branch:     branch,
		Index:      index,
		InputIndex: idx,
	}

	var digest []byte
	switch {
	case len(derivation.LeafHashes) == 1 &&
		len(pIn.TaprootLeafScript) == 1:

		leafScript := pIn.TaprootLeafScript[0]
		leaf := txscript.TapLeaf{
			LeafVersion: leafScript.LeafVersion,
			Script:      leafScript.Script,
		}
		hash := leaf.TapHash()
		if !bytes.Equal(hash[:], derivation.LeafHashes[0]) {
			return nil, errors.New("leaf hash does not match the " +
				"leaf script")
		}

		req.Method = MethodScriptPath
		req.LeafScript = hex.EncodeToString(leafScript.Script)
		req.LeafVersion = int(leafScript.LeafVersion)
		digest, err = txscript.CalcTapscriptSignaturehash(
			sigHashes, pIn.SighashType, tx, idx, fetcher, leaf,
		)

	case len(derivation.LeafHashes) == 0 &&
		len(pIn.TaprootMerkleRoot) == 0:

		req.Method = MethodBIP86
		digest, err = txscript.CalcTaprootSignatureHash(
			sigHashes, pIn.SighashType, tx, idx, fetcher,
		)

	case len(derivation.LeafHashes) == 0:
		req.Method = MethodKeyPath
		req.MerkleRoot = hex.EncodeToString(pIn.TaprootMerkleRoot)
		digest, err = txscript.CalcTaprootSignatureHash(
			sigHashes, pIn.SighashType, tx, idx, fetcher,
		)

	default:
		return nil, fmt.Errorf("%w: several leaves on one input",
			ErrUnsupported)
	}
	if err != nil {
		return nil, fmt.Errorf("sighash: %w", err)
	}
	req.Digest = hex.EncodeToString(digest)

	// A note about this transaction, or about one it spends: a forfeit
	// spends a connector whose round has been noted, and a round's own
	// commitment transaction is noted directly.
	txid := tx.TxHash()
	if note, ok := signctx.Lookup(txid); ok {
		req.Note = note

		return req, nil
	}
	for _, txIn := range tx.TxIn {
		note, ok := signctx.Lookup(txIn.PreviousOutPoint.Hash)
		if ok {
			req.Note = note

			break
		}
	}

	return req, nil
}

// locatorOf reads a key's family, branch and index from its BIP32 path:
// 86'/0'/0'/branch/index for the on-chain account, whose family is -1, and
// 1017'/coin'/family'/0/index for a key family.
func locatorOf(path []uint32) (int32, uint32, uint32, error) {
	if len(path) != 5 || path[0] < hdkeychain.HardenedKeyStart ||
		path[2] < hdkeychain.HardenedKeyStart {

		return 0, 0, 0, fmt.Errorf("%w: derivation path %v",
			ErrUnsupported, path)
	}

	switch path[0] - hdkeychain.HardenedKeyStart {
	case 86:
		return -1, path[3], path[4], nil

	case keychain.BIP0043Purpose:
		family := path[2] - hdkeychain.HardenedKeyStart

		return int32(family), path[3], path[4], nil

	default:
		return 0, 0, 0, fmt.Errorf("%w: derivation path %v",
			ErrUnsupported, path)
	}
}

// NextTreeKey allocates a tree key for a new VTXO.
func (c *Conn) NextTreeKey(ctx context.Context) (uint32, []byte, error) {
	resp, err := c.call(ctx, &Request{Kind: KindNextTreeKey})
	if err != nil {
		return 0, nil, err
	}

	key, err := decode("tree key", resp.PubKey)
	if err != nil {
		return 0, nil, err
	}

	return resp.Index, key, nil
}

// TreeKey reads an allocated tree key back.
func (c *Conn) TreeKey(ctx context.Context, index uint32) ([]byte, error) {
	resp, err := c.call(ctx, &Request{Kind: KindTreeKey, Index: index})
	if err != nil {
		return nil, err
	}

	return decode("tree key", resp.PubKey)
}

// Timeout implements rpcwallet.RemoteSignerConnection. There is nothing to
// connect to.
func (c *Conn) Timeout() time.Duration {
	return c.requestTimeout
}

// RequestTimeout implements rpcwallet.RemoteSignerConnection.
func (c *Conn) RequestTimeout() time.Duration {
	return c.requestTimeout
}

// Ready implements rpcwallet.RemoteSignerConnection.
func (c *Conn) Ready(context.Context) chan error {
	ready := make(chan error, 1)
	ready <- nil

	return ready
}

// Ping implements rpcwallet.RemoteSignerConnection.
func (c *Conn) Ping(context.Context, time.Duration) error {
	return nil
}

// Stop implements rpcwallet.RemoteSignerConnection.
func (c *Conn) Stop() {
	signctx.Disable()
}
