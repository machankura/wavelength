package walletcore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"google.golang.org/grpc"
)

var (
	// ErrFamilyNotSupplied is returned when a split-signing wallet is
	// asked to derive or sign with a key family its bundle did not
	// supply. Such a family's account holds a placeholder key nobody can
	// sign for, so deriving from it would lock funds forever.
	ErrFamilyNotSupplied = errors.New("key family not supplied by the " +
		"wallet's bundle")

	// ErrBundleOutdated is returned when a split-signing wallet's stored
	// bundle lacks a family this build signs with.
	ErrBundleOutdated = errors.New("the wallet's bundle does not cover " +
		"every key family this version uses; export a new minimal " +
		"bundle from the signer and recreate the wallet")
)

// checkSplitCoverage refuses to start a split-signing wallet whose stored
// bundle does not supply every fund family, or whose keystore lacks an
// authentication family, in the registry of this build.
func checkSplitCoverage(supplied, local []keychain.KeyFamily) error {
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		if !slices.Contains(supplied, family) {
			return fmt.Errorf("%w: fund family %d",
				ErrBundleOutdated, family)
		}
	}
	for _, family := range keyfamily.Families(keyfamily.Auth) {
		if !slices.Contains(local, family) {
			return fmt.Errorf("%w: authentication family %d",
				ErrBundleOutdated, family)
		}
	}

	return nil
}

// routedConn is a remote signer connection that sends requests for local
// key families to an in-process signer and everything else to the remote
// signer. Only the authentication families are local: they appear in no
// output script, so PSBT signing always goes to the remote signer, and a
// MuSig2 session stays with whichever side created it.
type routedConn struct {
	remote rpcwallet.RemoteSignerConnection
	local  rpcwallet.RemoteSignerConnection

	localFamilies []keychain.KeyFamily

	// localSessions records MuSig2 sessions created locally.
	localSessions sync.Map
}

var _ rpcwallet.RemoteSignerConnection = (*routedConn)(nil)

// forFamily returns the side that holds family.
func (r *routedConn) forFamily(family int32) rpcwallet.RemoteSignerConnection {
	if slices.Contains(r.localFamilies, keychain.KeyFamily(family)) {
		return r.local
	}

	return r.remote
}

// forSession returns the side that created a MuSig2 session.
func (r *routedConn) forSession(
	sessionID []byte) rpcwallet.RemoteSignerConnection {

	if _, ok := r.localSessions.Load(string(sessionID)); ok {
		return r.local
	}

	return r.remote
}

// SignMessage routes by the signing key's family.
func (r *routedConn) SignMessage(ctx context.Context,
	in *signrpc.SignMessageReq, opts ...grpc.CallOption) (
	*signrpc.SignMessageResp, error) {

	return r.forFamily(in.GetKeyLoc().GetKeyFamily()).SignMessage(
		ctx, in, opts...,
	)
}

// DeriveSharedKey routes by the key's family, defaulting to the node key
// as lnd's signer does.
func (r *routedConn) DeriveSharedKey(ctx context.Context,
	in *signrpc.SharedKeyRequest, opts ...grpc.CallOption) (
	*signrpc.SharedKeyResponse, error) {

	family := int32(keychain.KeyFamilyNodeKey)
	switch {
	case in.GetKeyDesc().GetKeyLoc() != nil:
		family = in.GetKeyDesc().GetKeyLoc().GetKeyFamily()

	case in.GetKeyLoc() != nil:
		family = in.GetKeyLoc().GetKeyFamily()
	}

	return r.forFamily(family).DeriveSharedKey(ctx, in, opts...)
}

// MuSig2CreateSession routes by the signing key's family and remembers a
// local session for the calls that follow.
func (r *routedConn) MuSig2CreateSession(ctx context.Context,
	in *signrpc.MuSig2SessionRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2SessionResponse, error) {

	side := r.forFamily(in.GetKeyLoc().GetKeyFamily())
	resp, err := side.MuSig2CreateSession(ctx, in, opts...)
	if err == nil && side == r.local {
		r.localSessions.Store(string(resp.SessionId), struct{}{})
	}

	return resp, err
}

// MuSig2RegisterNonces routes to the session's side.
func (r *routedConn) MuSig2RegisterNonces(ctx context.Context,
	in *signrpc.MuSig2RegisterNoncesRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2RegisterNoncesResponse, error) {

	return r.forSession(in.SessionId).MuSig2RegisterNonces(
		ctx, in, opts...,
	)
}

// MuSig2RegisterCombinedNonce routes to the session's side.
func (r *routedConn) MuSig2RegisterCombinedNonce(ctx context.Context,
	in *signrpc.MuSig2RegisterCombinedNonceRequest,
	opts ...grpc.CallOption) (*signrpc.MuSig2RegisterCombinedNonceResponse,
	error) {

	return r.forSession(in.SessionId).MuSig2RegisterCombinedNonce(
		ctx, in, opts...,
	)
}

// MuSig2GetCombinedNonce routes to the session's side.
func (r *routedConn) MuSig2GetCombinedNonce(ctx context.Context,
	in *signrpc.MuSig2GetCombinedNonceRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2GetCombinedNonceResponse, error) {

	return r.forSession(in.SessionId).MuSig2GetCombinedNonce(
		ctx, in, opts...,
	)
}

// MuSig2Sign routes to the session's side.
func (r *routedConn) MuSig2Sign(ctx context.Context,
	in *signrpc.MuSig2SignRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2SignResponse, error) {

	resp, err := r.forSession(in.SessionId).MuSig2Sign(ctx, in, opts...)
	if err == nil && in.Cleanup {
		r.localSessions.Delete(string(in.SessionId))
	}

	return resp, err
}

// MuSig2CombineSig routes to the session's side.
func (r *routedConn) MuSig2CombineSig(ctx context.Context,
	in *signrpc.MuSig2CombineSigRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2CombineSigResponse, error) {

	resp, err := r.forSession(in.SessionId).MuSig2CombineSig(
		ctx, in, opts...,
	)
	if err == nil && resp.HaveAllSignatures {
		r.localSessions.Delete(string(in.SessionId))
	}

	return resp, err
}

// MuSig2Cleanup routes to the session's side and forgets it.
func (r *routedConn) MuSig2Cleanup(ctx context.Context,
	in *signrpc.MuSig2CleanupRequest, opts ...grpc.CallOption) (
	*signrpc.MuSig2CleanupResponse, error) {

	side := r.forSession(in.SessionId)
	r.localSessions.Delete(string(in.SessionId))

	return side.MuSig2Cleanup(ctx, in, opts...)
}

// SignPsbt goes to the remote signer: only fund keys sign spends.
func (r *routedConn) SignPsbt(ctx context.Context,
	in *walletrpc.SignPsbtRequest, opts ...grpc.CallOption) (
	*walletrpc.SignPsbtResponse, error) {

	return r.remote.SignPsbt(ctx, in, opts...)
}

// Timeout is the remote signer's connection timeout.
func (r *routedConn) Timeout() time.Duration {
	return r.remote.Timeout()
}

// RequestTimeout is the remote signer's request timeout, the longer of
// the two sides.
func (r *routedConn) RequestTimeout() time.Duration {
	return r.remote.RequestTimeout()
}

// Ready reports when the remote signer is ready; the local side always is.
func (r *routedConn) Ready(ctx context.Context) chan error {
	return r.remote.Ready(ctx)
}

// Ping checks both sides.
func (r *routedConn) Ping(ctx context.Context, timeout time.Duration) error {
	if err := r.local.Ping(ctx, timeout); err != nil {
		return err
	}

	return r.remote.Ping(ctx, timeout)
}

// Stop closes both sides.
func (r *routedConn) Stop() {
	r.local.Stop()
	r.remote.Stop()
}

// guardedKeyRing refuses to derive or sign with a key family the wallet's
// bundle did not supply. A split-signing wallet's watch-only database holds
// placeholder keys for those families, which the remote signer derives
// differently and nobody can sign for; any key derived from one would
// lock funds forever.
type guardedKeyRing struct {
	RemoteKeyRing

	supplied []keychain.KeyFamily
}

// check refuses a family outside the registry or not supplied.
func (g *guardedKeyRing) check(family keychain.KeyFamily) error {
	if _, ok := keyfamily.Lookup(family); !ok {
		return fmt.Errorf("%w: family %d is not a Wavelength "+
			"key family", ErrFamilyNotSupplied, family)
	}
	if !slices.Contains(g.supplied, family) {
		return fmt.Errorf("%w: family %d", ErrFamilyNotSupplied, family)
	}

	return nil
}

// DeriveNextKey derives the next key of a supplied family.
func (g *guardedKeyRing) DeriveNextKey(family keychain.KeyFamily) (
	keychain.KeyDescriptor, error) {

	if err := g.check(family); err != nil {
		return keychain.KeyDescriptor{}, err
	}

	return g.RemoteKeyRing.DeriveNextKey(family)
}

// DeriveKey derives a key of a supplied family.
func (g *guardedKeyRing) DeriveKey(loc keychain.KeyLocator) (
	keychain.KeyDescriptor, error) {

	if err := g.check(loc.Family); err != nil {
		return keychain.KeyDescriptor{}, err
	}

	return g.RemoteKeyRing.DeriveKey(loc)
}

// ECDH uses a key of a supplied family.
func (g *guardedKeyRing) ECDH(desc keychain.KeyDescriptor,
	pub *btcec.PublicKey) ([32]byte, error) {

	if err := g.check(desc.Family); err != nil {
		return [32]byte{}, err
	}

	return g.RemoteKeyRing.ECDH(desc, pub)
}

// SignMessage signs with a key of a supplied family.
func (g *guardedKeyRing) SignMessage(loc keychain.KeyLocator, msg []byte,
	doubleHash bool) (*ecdsa.Signature, error) {

	if err := g.check(loc.Family); err != nil {
		return nil, err
	}

	return g.RemoteKeyRing.SignMessage(loc, msg, doubleHash)
}

// SignMessageCompact signs with a key of a supplied family.
func (g *guardedKeyRing) SignMessageCompact(loc keychain.KeyLocator, msg []byte,
	doubleHash bool) ([]byte, error) {

	if err := g.check(loc.Family); err != nil {
		return nil, err
	}

	return g.RemoteKeyRing.SignMessageCompact(loc, msg, doubleHash)
}

// SignMessageSchnorr signs with a key of a supplied family.
func (g *guardedKeyRing) SignMessageSchnorr(loc keychain.KeyLocator, msg []byte,
	doubleHash bool, taprootTweak []byte, tag []byte) (*schnorr.Signature,
	error) {

	if err := g.check(loc.Family); err != nil {
		return nil, err
	}

	return g.RemoteKeyRing.SignMessageSchnorr(
		loc, msg, doubleHash, taprootTweak, tag,
	)
}

// SignOutputRaw signs with a key of a supplied family. A descriptor that
// names only a public key is resolved by the wallet to an on-chain or
// family key it holds, and the remote signer's answer is verified against
// that key, so it cannot reach a placeholder unnoticed.
func (g *guardedKeyRing) SignOutputRaw(tx *wire.MsgTx,
	desc *input.SignDescriptor) (input.Signature, error) {

	if !desc.KeyDesc.IsEmpty() {
		if err := g.check(desc.KeyDesc.Family); err != nil {
			return nil, err
		}
	}

	return g.RemoteKeyRing.SignOutputRaw(tx, desc)
}

// MuSig2CreateSession starts a session with a key of a supplied family.
func (g *guardedKeyRing) MuSig2CreateSession(version input.MuSig2Version,
	loc keychain.KeyLocator, signers []*btcec.PublicKey,
	tweaks *input.MuSig2Tweaks, otherNonces [][musig2.PubNonceSize]byte,
	localNonces *musig2.Nonces) (*input.MuSig2SessionInfo, error) {

	if err := g.check(loc.Family); err != nil {
		return nil, err
	}

	return g.RemoteKeyRing.MuSig2CreateSession(
		version, loc, signers, tweaks, otherNonces, localNonces,
	)
}
