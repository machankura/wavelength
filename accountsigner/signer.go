package accountsigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"google.golang.org/grpc"
)

// requestTimeout is what the RPC key ring waits for each in-process
// request. Nothing here blocks on I/O, so it only bounds a pathological
// key scan.
const requestTimeout = 30 * time.Second

// bip0340Tag and the TapSighash tag are refused as message tags, the same
// rule lnd's signer applies, so a message signature can never be replayed
// as a transaction signature.
var bip0340Tag = []byte("BIP0340")

// ErrStopped is returned for requests after Stop wiped the keys.
var ErrStopped = errors.New("account signer stopped")

// Signer signs from account-level private keys. It implements lnd's
// rpcwallet.RemoteSignerConnection, so lnd's RPC key ring can use it in
// place of a gRPC connection to a remote signer.
type Signer struct {
	// mu guards keys against Stop racing a request.
	mu sync.RWMutex

	keys     *walletdesc.AccountKeys
	coinType uint32

	// musig holds MuSig2 session state between requests.
	musig *input.MusigSessionManager
}

var _ rpcwallet.RemoteSignerConnection = (*Signer)(nil)

// New returns a signer over keys for params. The signer owns keys from here
// on and wipes them on Stop.
func New(keys *walletdesc.AccountKeys, params *chaincfg.Params) *Signer {
	s := &Signer{
		keys:     keys,
		coinType: params.HDCoinType,
	}
	s.musig = input.NewMusigSessionManager(s.fetchPrivKey)

	return s
}

// withKeys runs fn with the keys, unless the signer was stopped.
func (s *Signer) withKeys(fn func(*walletdesc.AccountKeys) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.keys == nil {
		return ErrStopped
	}

	return fn(s.keys)
}

// fetchPrivKey returns the private key for a key family descriptor. When
// the descriptor carries a public key at index 0, the family is scanned for
// it, the way lnd's key ring resolves a key known only by its public key.
func (s *Signer) fetchPrivKey(desc *keychain.KeyDescriptor) (*btcec.PrivateKey,
	error) {

	var priv *btcec.PrivateKey
	err := s.withKeys(func(keys *walletdesc.AccountKeys) error {
		var err error
		priv, err = privKeyAt(
			keys, familyPath(s.coinType,
				desc.KeyLocator),
		)
		if err != nil {
			return err
		}

		if desc.PubKey == nil || priv.PubKey().IsEqual(desc.PubKey) {
			return nil
		}
		if desc.Index != 0 {
			return fmt.Errorf("%w: public key does not match "+
				"family %d index %d", ErrUnknownKey,
				desc.Family, desc.Index)
		}

		for index := uint32(
			1,
		); index < uint32(keychain.MaxKeyRangeScan); index++ {

			loc := keychain.KeyLocator{
				Family: desc.Family,
				Index:  index,
			}
			priv, err = privKeyAt(keys, familyPath(s.coinType, loc))
			if err != nil {
				return err
			}
			if priv.PubKey().IsEqual(desc.PubKey) {
				return nil
			}
		}

		return fmt.Errorf("%w: public key not found in family %d",
			ErrUnknownKey, desc.Family)
	})

	return priv, err
}

// SignMessage signs a message with a key family key, as ECDSA, compact
// ECDSA or BIP340 Schnorr.
func (s *Signer) SignMessage(_ context.Context, in *signrpc.SignMessageReq,
	_ ...grpc.CallOption) (*signrpc.SignMessageResp, error) {

	switch {
	case in.Msg == nil:
		return nil, errors.New("a message to sign must be passed in")

	case in.KeyLoc == nil:
		return nil, errors.New("a key locator must be passed in")

	case in.SchnorrSig && in.CompactSig:
		return nil, errors.New("compact format can not be used for " +
			"Schnorr signatures")

	case !in.SchnorrSig && len(in.Tag) > 0:
		return nil, errors.New("tag can only be used with Schnorr " +
			"signatures")

	case bytes.HasPrefix(in.Tag, bip0340Tag),
		bytes.HasPrefix(in.Tag, chainhash.TagTapSighash):
		return nil, errors.New("reserved message tag")

	case in.DoubleHash && len(in.Tag) > 0:
		return nil, errors.New("double hash and tag can't be set at " +
			"the same time")
	}

	loc := keychain.KeyLocator{
		Family: keychain.KeyFamily(in.KeyLoc.KeyFamily),
		Index:  uint32(in.KeyLoc.KeyIndex),
	}
	priv, err := s.fetchPrivKey(&keychain.KeyDescriptor{KeyLocator: loc})
	if err != nil {
		return nil, err
	}

	if in.SchnorrSig {
		if len(in.SchnorrSigTapTweak) > 0 {
			priv = txscript.TweakTaprootPrivKey(
				*priv, in.SchnorrSigTapTweak,
			)
		}

		var digest []byte
		switch {
		case len(in.Tag) > 0:
			tagged := chainhash.TaggedHash(in.Tag, in.Msg)
			digest = tagged[:]

		case in.DoubleHash:
			digest = chainhash.DoubleHashB(in.Msg)

		default:
			digest = chainhash.HashB(in.Msg)
		}

		sig, err := schnorr.Sign(priv, digest)
		if err != nil {
			return nil, err
		}

		return &signrpc.SignMessageResp{Signature: sig.Serialize()}, nil
	}

	signer := keychain.NewPrivKeyMessageSigner(priv, loc)
	if in.CompactSig {
		sig, err := signer.SignMessageCompact(in.Msg, in.DoubleHash)
		if err != nil {
			return nil, err
		}

		return &signrpc.SignMessageResp{Signature: sig}, nil
	}

	sig, err := signer.SignMessage(in.Msg, in.DoubleHash)
	if err != nil {
		return nil, err
	}

	return &signrpc.SignMessageResp{Signature: sig.Serialize()}, nil
}

// DeriveSharedKey computes an ECDH shared secret with a key family key:
// the SHA256 of the compressed shared point, as lnd does.
func (s *Signer) DeriveSharedKey(_ context.Context,
	in *signrpc.SharedKeyRequest, _ ...grpc.CallOption) (
	*signrpc.SharedKeyResponse, error) {

	ephemeral, err := btcec.ParsePubKey(in.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("ephemeral pubkey: %w", err)
	}
	if in.KeyDesc != nil && in.KeyLoc != nil {
		return nil, errors.New("use either key_desc or key_loc")
	}

	keyLoc := in.KeyLoc
	var rawKey []byte
	if in.KeyDesc != nil {
		keyLoc = in.KeyDesc.GetKeyLoc()
		rawKey = in.KeyDesc.GetRawKeyBytes()
	}

	desc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
		},
	}
	if keyLoc != nil {
		desc.KeyLocator = keychain.KeyLocator{
			Family: keychain.KeyFamily(keyLoc.KeyFamily),
			Index:  uint32(keyLoc.KeyIndex),
		}
	}
	if len(rawKey) > 0 {
		if desc.Index != 0 {
			return nil, errors.New("use either raw_key_bytes or " +
				"key_index")
		}
		desc.PubKey, err = btcec.ParsePubKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("raw pubkey: %w", err)
		}
	}

	priv, err := s.fetchPrivKey(&desc)
	if err != nil {
		return nil, err
	}

	shared, err := (&keychain.PrivKeyECDH{PrivKey: priv}).ECDH(ephemeral)
	if err != nil {
		return nil, err
	}

	return &signrpc.SharedKeyResponse{SharedKey: shared[:]}, nil
}

// MuSig2CreateSession starts a MuSig2 session with a key family key.
func (s *Signer) MuSig2CreateSession(_ context.Context,
	in *signrpc.MuSig2SessionRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2SessionResponse, error) {

	version, err := signrpc.UnmarshalMuSig2Version(in.Version)
	if err != nil {
		return nil, err
	}
	if in.KeyLoc == nil {
		return nil, errors.New("missing key_loc")
	}
	keyLoc := keychain.KeyLocator{
		Family: keychain.KeyFamily(in.KeyLoc.KeyFamily),
		Index:  uint32(in.KeyLoc.KeyIndex),
	}

	signers, err := input.MuSig2ParsePubKeys(version, in.AllSignerPubkeys)
	if err != nil {
		return nil, fmt.Errorf("signer public keys: %w", err)
	}
	if len(in.OtherSignerPublicNonces) > len(in.AllSignerPubkeys)-1 {
		return nil, errors.New("more nonces than other signers")
	}

	var localNonces *musig2.Nonces
	switch len(in.PregeneratedLocalNonce) {
	case 0:
	case musig2.SecNonceSize:
		var secNonce [musig2.SecNonceSize]byte
		copy(secNonce[:], in.PregeneratedLocalNonce)
		localNonces = &musig2.Nonces{
			SecNonce: secNonce,
			PubNonce: secNonceToPubNonce(secNonce),
		}

	default:
		return nil, fmt.Errorf("local nonce must be %d bytes",
			musig2.SecNonceSize)
	}

	otherNonces, err := parsePubNonces(in.OtherSignerPublicNonces, true)
	if err != nil {
		return nil, err
	}

	tweaks, err := unmarshalTweaks(in.Tweaks, in.TaprootTweak)
	if err != nil {
		return nil, err
	}

	session, err := s.musig.MuSig2CreateSession(
		version, keyLoc, signers, tweaks, otherNonces, localNonces,
	)
	if err != nil {
		return nil, err
	}

	var internalKey []byte
	if session.TaprootTweak {
		internalKey = schnorr.SerializePubKey(
			session.TaprootInternalKey,
		)
	}

	combinedKey := schnorr.SerializePubKey(session.CombinedKey)

	return &signrpc.MuSig2SessionResponse{
		SessionId:          session.SessionID[:],
		CombinedKey:        combinedKey,
		TaprootInternalKey: internalKey,
		LocalPublicNonces:  session.PublicNonce[:],
		HaveAllNonces:      session.HaveAllNonces,
		Version:            in.Version,
	}, nil
}

// MuSig2RegisterNonces adds other signers' public nonces to a session.
func (s *Signer) MuSig2RegisterNonces(_ context.Context,
	in *signrpc.MuSig2RegisterNoncesRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2RegisterNoncesResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}
	nonces, err := parsePubNonces(in.OtherSignerPublicNonces, false)
	if err != nil {
		return nil, err
	}

	haveAll, err := s.musig.MuSig2RegisterNonces(sessionID, nonces)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2RegisterNoncesResponse{
		HaveAllNonces: haveAll,
	}, nil
}

// MuSig2RegisterCombinedNonce sets a session's aggregate nonce directly.
func (s *Signer) MuSig2RegisterCombinedNonce(_ context.Context,
	in *signrpc.MuSig2RegisterCombinedNonceRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2RegisterCombinedNonceResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}
	if len(in.CombinedPublicNonce) != musig2.PubNonceSize {
		return nil, fmt.Errorf("combined nonce must be %d bytes",
			musig2.PubNonceSize)
	}

	var combined [musig2.PubNonceSize]byte
	copy(combined[:], in.CombinedPublicNonce)
	err = s.musig.MuSig2RegisterCombinedNonce(sessionID, combined)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2RegisterCombinedNonceResponse{}, nil
}

// MuSig2GetCombinedNonce returns a session's aggregate nonce.
func (s *Signer) MuSig2GetCombinedNonce(_ context.Context,
	in *signrpc.MuSig2GetCombinedNonceRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2GetCombinedNonceResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}

	combined, err := s.musig.MuSig2GetCombinedNonce(sessionID)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2GetCombinedNonceResponse{
		CombinedPublicNonce: combined[:],
	}, nil
}

// MuSig2Sign produces this signer's partial signature for a session.
func (s *Signer) MuSig2Sign(_ context.Context, in *signrpc.MuSig2SignRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SignResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}
	if len(in.MessageDigest) != sha256.Size {
		return nil, fmt.Errorf("message digest must be %d bytes",
			sha256.Size)
	}

	var digest [sha256.Size]byte
	copy(digest[:], in.MessageDigest)
	partial, err := s.musig.MuSig2Sign(sessionID, digest, in.Cleanup)
	if err != nil {
		return nil, err
	}

	raw, err := input.SerializePartialSignature(partial)
	if err != nil {
		return nil, err
	}

	return &signrpc.MuSig2SignResponse{LocalPartialSignature: raw[:]}, nil
}

// MuSig2CombineSig combines other signers' partial signatures with ours.
func (s *Signer) MuSig2CombineSig(_ context.Context,
	in *signrpc.MuSig2CombineSigRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2CombineSigResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}
	if len(in.OtherPartialSignatures) == 0 {
		return nil, errors.New("at least one partial signature is " +
			"required")
	}

	partials := make(
		[]*musig2.PartialSignature, len(in.OtherPartialSignatures),
	)
	for i, raw := range in.OtherPartialSignatures {
		partials[i], err = input.DeserializePartialSignature(raw)
		if err != nil {
			return nil, fmt.Errorf("partial signature %d: %w", i,
				err)
		}
	}

	final, haveAll, err := s.musig.MuSig2CombineSig(sessionID, partials)
	if err != nil {
		return nil, err
	}

	resp := &signrpc.MuSig2CombineSigResponse{HaveAllSignatures: haveAll}
	if haveAll {
		resp.FinalSignature = final.Serialize()
	}

	return resp, nil
}

// MuSig2Cleanup drops a session.
func (s *Signer) MuSig2Cleanup(_ context.Context,
	in *signrpc.MuSig2CleanupRequest, _ ...grpc.CallOption) (
	*signrpc.MuSig2CleanupResponse, error) {

	sessionID, err := parseSessionID(in.SessionId)
	if err != nil {
		return nil, err
	}
	if err := s.musig.MuSig2Cleanup(sessionID); err != nil {
		return nil, err
	}

	return &signrpc.MuSig2CleanupResponse{}, nil
}

// Timeout bounds connecting, which is immediate in process.
func (s *Signer) Timeout() time.Duration {
	return requestTimeout
}

// RequestTimeout bounds each request.
func (s *Signer) RequestTimeout() time.Duration {
	return requestTimeout
}

// Ready reports the signer ready at once.
func (s *Signer) Ready(context.Context) chan error {
	ready := make(chan error, 1)
	ready <- nil

	return ready
}

// Ping reports whether the signer still holds its keys.
func (s *Signer) Ping(context.Context, time.Duration) error {
	return s.withKeys(func(*walletdesc.AccountKeys) error {
		return nil
	})
}

// Stop wipes the keys. Later requests fail with ErrStopped.
func (s *Signer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.keys != nil {
		s.keys.Zero()
		s.keys = nil
	}
}

// parseSessionID parses a 32-byte MuSig2 session ID.
func parseSessionID(raw []byte) (input.MuSig2SessionID, error) {
	var id input.MuSig2SessionID
	if len(raw) != len(id) {
		return id, fmt.Errorf("session ID must be %d bytes", len(id))
	}
	copy(id[:], raw)

	return id, nil
}

// parsePubNonces parses MuSig2 public nonces.
func parsePubNonces(raw [][]byte,
	emptyAllowed bool) ([][musig2.PubNonceSize]byte, error) {

	if !emptyAllowed && len(raw) == 0 {
		return nil, errors.New("at least one other signer public " +
			"nonce is required")
	}

	nonces := make([][musig2.PubNonceSize]byte, len(raw))
	for i, nonce := range raw {
		if len(nonce) != musig2.PubNonceSize {
			return nil, fmt.Errorf("public nonce %d must be "+
				"%d bytes", i, musig2.PubNonceSize)
		}
		copy(nonces[i][:], nonce)
	}

	return nonces, nil
}

// unmarshalTweaks parses MuSig2 tweaks, mirroring lnd's signrpc server.
func unmarshalTweaks(rpcTweaks []*signrpc.TweakDesc,
	taprootTweak *signrpc.TaprootTweakDesc) (*input.MuSig2Tweaks, error) {

	tweaks := &input.MuSig2Tweaks{
		GenericTweaks: make([]musig2.KeyTweakDesc, len(rpcTweaks)),
	}
	for i, tweak := range rpcTweaks {
		if len(tweak.Tweak) == 0 {
			return nil, errors.New("tweak cannot be empty")
		}
		copy(tweaks.GenericTweaks[i].Tweak[:], tweak.Tweak)
		tweaks.GenericTweaks[i].IsXOnly = tweak.IsXOnly
	}

	switch {
	case taprootTweak == nil:
	case taprootTweak.KeySpendOnly:
		tweaks.TaprootBIP0086Tweak = true

	case len(taprootTweak.ScriptRoot) == 0:
		return nil, errors.New("script root cannot be empty for a " +
			"script-path tweak")

	default:
		tweaks.TaprootTweak = taprootTweak.ScriptRoot
	}

	return tweaks, nil
}

// secNonceToPubNonce derives the public nonce of a pregenerated secret
// nonce, as lnd's signrpc server does.
func secNonceToPubNonce(
	secNonce [musig2.SecNonceSize]byte) [musig2.PubNonceSize]byte {

	var k1, k2 btcec.ModNScalar
	k1.SetByteSlice(secNonce[:btcec.PrivKeyBytesLen])
	k2.SetByteSlice(secNonce[btcec.PrivKeyBytesLen:])

	var r1, r2 btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&k1, &r1)
	btcec.ScalarBaseMultNonConst(&k2, &r2)
	r1.ToAffine()
	r2.ToAffine()

	var pubNonce [musig2.PubNonceSize]byte
	copy(
		pubNonce[:],
		btcec.NewPublicKey(&r1.X, &r1.Y).SerializeCompressed(),
	)
	copy(
		pubNonce[btcec.PubKeyBytesLenCompressed:],
		btcec.NewPublicKey(&r2.X, &r2.Y).SerializeCompressed(),
	)

	return pubNonce
}
