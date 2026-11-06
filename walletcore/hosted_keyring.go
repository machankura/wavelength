package walletcore

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/wavelength/callbacksigner"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/keychain"
)

// hostedKeyRing serves a wallet whose signer is its host. It answers for the
// tree family from the host, because a threshold group cannot derive a key
// inside someone else's MuSig2 aggregation from an xpub: each VTXO's tree key
// is one the group made for it. Everything else goes to the ring it wraps.
type hostedKeyRing struct {
	RemoteKeyRing

	conn *callbacksigner.Conn
}

// DeriveNextKey implements keychain.KeyRing.
func (h *hostedKeyRing) DeriveNextKey(family keychain.KeyFamily) (
	keychain.KeyDescriptor, error) {

	if family != keyfamily.VTXOSigning {
		return h.RemoteKeyRing.DeriveNextKey(family)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), h.conn.RequestTimeout(),
	)
	defer cancel()

	index, raw, err := h.conn.NextTreeKey(ctx)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("next tree key: %w",
			err)
	}

	return treeKeyDescriptor(index, raw)
}

// DeriveKey implements keychain.KeyRing.
func (h *hostedKeyRing) DeriveKey(loc keychain.KeyLocator) (
	keychain.KeyDescriptor, error) {

	if loc.Family != keyfamily.VTXOSigning {
		return h.RemoteKeyRing.DeriveKey(loc)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), h.conn.RequestTimeout(),
	)
	defer cancel()

	raw, err := h.conn.TreeKey(ctx, loc.Index)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("tree key %d: %w",
			loc.Index, err)
	}

	return treeKeyDescriptor(loc.Index, raw)
}

// treeKeyDescriptor builds the descriptor of a host's tree key.
func treeKeyDescriptor(index uint32, raw []byte) (keychain.KeyDescriptor,
	error) {

	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("parse tree key: %w",
			err)
	}

	return keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keyfamily.VTXOSigning,
			Index:  index,
		},
		PubKey: pub,
	}, nil
}
