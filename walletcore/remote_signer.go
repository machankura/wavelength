package walletcore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
)

const (
	// DefaultRemoteSignerTimeout bounds establishing the connection to
	// the remote signer.
	DefaultRemoteSignerTimeout = 30 * time.Second

	// DefaultRemoteSignerRequestTimeout bounds each signing request. A
	// same-host lnd signer answers in milliseconds, so lnd's 5 seconds is
	// already generous; the default leaves room for a signer across a
	// network while staying far inside a round's signing budget.
	DefaultRemoteSignerRequestTimeout = 10 * time.Second
)

var (
	// ErrRemoteSignerUnsupported is returned on builds that cannot dial
	// a remote signer, such as the browser.
	ErrRemoteSignerUnsupported = errors.New("remote signing is not " +
		"supported on this platform")

	// ErrWrongRemoteSigner is returned when the remote signer does not
	// hold the identity key the wallet's account public keys imply.
	ErrWrongRemoteSigner = errors.New("remote signer does not hold this " +
		"wallet's keys")
)

// remoteSignerCheckTag is the BIP340 tag of the challenge the remote signer
// signs on every start. A dedicated tag keeps the signature from being
// meaningful anywhere else.
var remoteSignerCheckTag = []byte("wavelength/remote-signer-check")

// RemoteSignerConfig locates an lnd-compatible remote signer: one serving
// the signrpc and walletrpc calls lnd's RPC key ring makes.
type RemoteSignerConfig struct {
	// RPCHost is the signer's gRPC host:port.
	RPCHost string

	// MacaroonPath is a macaroon the signer accepts for signing.
	MacaroonPath string

	// TLSCertPath is the signer's TLS certificate.
	TLSCertPath string

	// Timeout bounds establishing the connection. Zero selects
	// DefaultRemoteSignerTimeout.
	Timeout time.Duration

	// RequestTimeout bounds each request. Zero selects
	// DefaultRemoteSignerRequestTimeout.
	RequestTimeout time.Duration
}

// Validate checks the configuration is complete and fills in default
// timeouts.
func (c *RemoteSignerConfig) Validate() error {
	switch {
	case c.RPCHost == "":
		return errors.New("remote signer rpchost is required")

	case c.MacaroonPath == "":
		return errors.New("remote signer macaroonpath is required")

	case c.TLSCertPath == "":
		return errors.New("remote signer tlscertpath is required")

	case c.Timeout < 0 || c.RequestTimeout < 0:
		return errors.New("remote signer timeouts must not be negative")
	}

	if c.Timeout == 0 {
		c.Timeout = DefaultRemoteSignerTimeout
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRemoteSignerRequestTimeout
	}

	return nil
}

// RemoteKeyRing is a key ring whose private keys live on a remote signer.
// It derives public keys from the local watch-only wallet and forwards
// every signature, including MuSig2 sessions, to the signer; it also funds
// and finalizes PSBTs, signing through the signer.
type RemoteKeyRing interface {
	keychain.SecretKeyRing
	keychain.MessageSignerRing
	input.Signer
	lnwallet.WalletController
}

// NewRemoteKeyRing puts lnd's RPC key ring in front of a watch-only btcw,
// signing through conn.
func NewRemoteKeyRing(btcw *btcwallet.BtcWallet, coinType uint32,
	conn rpcwallet.RemoteSignerConnection,
	params *chaincfg.Params) (RemoteKeyRing, error) {

	watchOnlyRing := keychain.NewBtcWalletKeyRing(
		btcw.InternalWallet(), coinType,
	)

	return rpcwallet.NewRPCKeyRing(watchOnlyRing, btcw, conn, params)
}

// VerifyRemoteSigner asks ring's signer to sign a fresh challenge with the
// identity key and checks the signature against the identity key the
// watch-only wallet derives. A daemon started against the wrong signer
// fails here rather than at its first spend.
func VerifyRemoteSigner(ring RemoteKeyRing) error {
	loc := keychain.KeyLocator{Family: keyfamily.Identity}
	identity, err := ring.DeriveKey(loc)
	if err != nil {
		return fmt.Errorf("derive identity key: %w", err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}

	sig, err := ring.SignMessageSchnorr(
		loc, challenge, false, nil, remoteSignerCheckTag,
	)
	if err != nil {
		return fmt.Errorf("remote signer challenge: %w", err)
	}

	digest := chainhash.TaggedHash(remoteSignerCheckTag, challenge)
	if !sig.Verify(digest[:], identity.PubKey) {
		return ErrWrongRemoteSigner
	}

	return nil
}

// RemoteSigning is a watch-only wallet with the remote key ring in front of
// it and the signer connection both use.
type RemoteSigning struct {
	// BtcWallet tracks the chain and derives public keys.
	BtcWallet *btcwallet.BtcWallet

	// KeyRing signs through the remote signer. It is the wallet's
	// Signer, KeyRing and Controller.
	KeyRing RemoteKeyRing

	// Conn is the signer connection; Stop closes it.
	Conn rpcwallet.RemoteSignerConnection
}

// OpenRemoteSigning creates (with a bundle) or opens (without one) the
// watch-only btcwallet described by cfg, connects to the remote signer and
// builds the key ring over both. cfg.PublicPass must be the user's wallet
// password. On error nothing is left open.
func OpenRemoteSigning(ctx context.Context, cfg btcwallet.Config,
	bundle *walletdesc.WatchOnlyBundle, remote RemoteSignerConfig,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	if err := remote.Validate(); err != nil {
		return nil, err
	}

	btcw, err := NewWatchOnlyBtcWallet(cfg, bundle, blockCache)
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, remote.Timeout)
	defer cancel()

	conn, err := DialRemoteSigner(dialCtx, remote)
	if err != nil {
		_ = btcw.InternalWallet().Database().Close()

		return nil, err
	}

	ring, err := NewRemoteKeyRing(btcw, cfg.CoinType, conn, cfg.NetParams)
	if err != nil {
		conn.Stop()
		_ = btcw.InternalWallet().Database().Close()

		return nil, err
	}

	return &RemoteSigning{
		BtcWallet: btcw,
		KeyRing:   ring,
		Conn:      conn,
	}, nil
}
