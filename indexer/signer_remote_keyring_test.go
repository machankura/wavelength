package indexer

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// errNoPrivateKey mimics a remote-signing key ring, which can sign but never
// hands out private keys.
var errNoPrivateKey = errors.New("private key not available")

// remoteStyleKeyRing signs tagged Schnorr messages with one key but refuses
// DerivePrivKey, the way a remote signer's key ring does.
type remoteStyleKeyRing struct {
	keychain.SecretKeyRing

	priv *btcec.PrivateKey
}

// DerivePrivKey always fails.
func (r *remoteStyleKeyRing) DerivePrivKey(keychain.KeyDescriptor) (
	*btcec.PrivateKey, error) {

	return nil, errNoPrivateKey
}

// SignMessageSchnorr signs the tagged hash of msg, matching btcwallet's key
// ring for a nil tweak and no double hashing.
func (r *remoteStyleKeyRing) SignMessageSchnorr(_ keychain.KeyLocator,
	msg []byte, doubleHash bool, taprootTweak []byte, tag []byte) (
	*schnorr.Signature, error) {

	if doubleHash || taprootTweak != nil {
		return nil, errors.New("unexpected signing options")
	}

	return schnorr.Sign(r.priv, chainhash.TaggedHash(tag, msg)[:])
}

// SignMessage is unused here but keeps the stub honest if called.
func (r *remoteStyleKeyRing) SignMessage(keychain.KeyLocator, []byte, bool) (
	*ecdsa.Signature, error) {

	return nil, errors.New("not implemented")
}

// TestKeyRingProofSigningNeedsNoPrivateKey pins that indexer proofs signed
// through a key ring never extract a private key: the proof path uses the
// key ring's tagged-message signing, so a remote-signing key ring works.
func TestKeyRingProofSigningNeedsNoPrivateKey(t *testing.T) {
	t.Parallel()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	ring := &remoteStyleKeyRing{priv: priv}
	signer := NewKeyRingSchnorrSigner(ring, keychain.KeyDescriptor{
		PubKey: priv.PubKey(),
	})

	message := []byte("indexer proof preimage")
	sig, err := schnorrSigOverMessage(t.Context(), message, nil, signer)
	require.NoError(t, err)

	parsed, err := schnorr.ParseSignature(sig)
	require.NoError(t, err)
	require.True(
		t,
		parsed.Verify(
			chainhash.TaggedHash(proofTag(), message)[:],
			priv.PubKey(),
		),
	)

	// The raw-digest entry point is the only one that needs a private
	// key, and it fails cleanly rather than panicking.
	_, err = signer.SignSchnorr(nil, [32]byte{})
	require.ErrorIs(t, err, errNoPrivateKey)
}
