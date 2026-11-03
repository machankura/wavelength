package walletcore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
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

	// ManifestHash is the hex hash of the manifest the wallet was
	// created from, or empty for a wallet without one.
	ManifestHash string
}

// OpenRemoteSigning creates (with a bundle) or opens (without one) the
// watch-only btcwallet described by cfg, connects to the remote signer and
// builds the key ring over both. cfg.PublicPass must be the user's wallet
// password. On error nothing is left open.
//
// A minimal bundle, given instead of a full one, creates a split-signing
// wallet: placeholders complete the bundle for import, the authentication
// families' private keys go into the account keystore under the password,
// and the supplied families are recorded beside it. Opening a wallet with
// such a keystore restores the split. A split-signing wallet signs
// authentication requests in process and everything else remotely, and
// refuses to derive or sign with any family its bundle did not supply.
func OpenRemoteSigning(ctx context.Context, cfg btcwallet.Config,
	bundle *walletdesc.WatchOnlyBundle, minimal *walletdesc.MinimalBundle,
	manifest *walletdesc.Manifest, remote RemoteSignerConfig,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	if err := remote.Validate(); err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, remote.Timeout)
	defer cancel()

	remoteConn, err := DialRemoteSigner(dialCtx, remote)
	if err != nil {
		return nil, err
	}

	signing, err := OpenWithSigner(
		cfg, bundle, minimal, manifest, remoteConn, blockCache,
	)
	if err != nil {
		remoteConn.Stop()

		return nil, err
	}

	return signing, nil
}

// OpenWithSigner is OpenRemoteSigning over an already established signer
// connection, which the result owns once it returns without error.
//
// A manifest, given with the minimal bundle it produced, is stored with
// the wallet; reopening a wallet that has one checks its accounts still
// match it, and the result carries its hash either way.
func OpenWithSigner(cfg btcwallet.Config, bundle *walletdesc.WatchOnlyBundle,
	minimal *walletdesc.MinimalBundle, manifest *walletdesc.Manifest,
	remoteConn rpcwallet.RemoteSignerConnection,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	if bundle != nil && minimal != nil {
		return nil, errors.New("give a full or a minimal bundle, not " +
			"both")
	}

	if minimal != nil {
		var err error
		bundle, err = minimal.WithPlaceholders(cfg.NetParams)
		if err != nil {
			return nil, fmt.Errorf("complete minimal bundle: %w",
				err)
		}
	}

	btcw, err := NewWatchOnlyBtcWallet(cfg, bundle, blockCache)
	if err != nil {
		return nil, err
	}
	db := btcw.InternalWallet().Database()

	opening := bundle == nil
	local, supplied, err := splitSigningKeys(btcw, minimal, opening, cfg)
	if err != nil {
		_ = db.Close()

		return nil, err
	}

	manifestHash, err := walletManifest(btcw, manifest, opening, cfg)
	if err != nil {
		if local != nil {
			local.Zero()
		}
		_ = db.Close()

		return nil, err
	}

	var conn rpcwallet.RemoteSignerConnection = remoteConn
	if local != nil {
		var localFamilies []keychain.KeyFamily
		for _, acct := range local.Accounts {
			localFamilies = append(
				localFamilies, keychain.KeyFamily(acct.Account),
			)
		}

		conn = &routedConn{
			remote:        remoteConn,
			local:         accountsigner.New(local, cfg.NetParams),
			localFamilies: localFamilies,
		}
	}

	ring, err := NewRemoteKeyRing(btcw, cfg.CoinType, conn, cfg.NetParams)
	if err != nil {
		if local != nil {
			local.Zero()
		}
		_ = db.Close()

		return nil, err
	}
	if local != nil {
		ring = &guardedKeyRing{RemoteKeyRing: ring, supplied: supplied}
	}

	return &RemoteSigning{
		BtcWallet:    btcw,
		KeyRing:      ring,
		Conn:         conn,
		ManifestHash: manifestHash,
	}, nil
}

// walletManifest stores manifest with a new wallet, or on open checks the
// stored one still matches the wallet's accounts, and returns its hash.
func walletManifest(btcw *btcwallet.BtcWallet, manifest *walletdesc.Manifest,
	opening bool, cfg btcwallet.Config) (string, error) {

	db := btcw.InternalWallet().Database()
	if !opening {
		if manifest == nil {
			return "", nil
		}
		err := accountsigner.StoreManifest(db, manifest.Canonical())
		if err != nil {
			return "", fmt.Errorf("store manifest: %w", err)
		}

		return manifest.HashHex(), nil
	}

	canonical, err := accountsigner.LoadManifest(db)
	if err != nil || canonical == nil {
		return "", err
	}

	stored, err := walletdesc.ParseManifest(canonical, cfg.NetParams)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrManifestMismatch, err)
	}
	err = checkManifestAccounts(btcw, stored, cfg.NetParams)
	if err != nil {
		return "", err
	}

	return stored.HashHex(), nil
}

// splitSigningKeys returns the local authentication keys and supplied
// families of a split-signing wallet, or nil for a fully remote one. On
// creation from a minimal bundle it writes them to the wallet database
// first; on open it reads them back with the password and checks the
// bundle still covers every family this build uses.
func splitSigningKeys(btcw *btcwallet.BtcWallet,
	minimal *walletdesc.MinimalBundle, opening bool, cfg btcwallet.Config) (
	*walletdesc.AccountKeys, []keychain.KeyFamily, error) {

	db := btcw.InternalWallet().Database()
	password := cfg.PublicPass

	var supplied []keychain.KeyFamily
	switch {
	case minimal != nil:
		err := accountsigner.StoreKeys(db, password, minimal.Local, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("store local keys: %w", err)
		}

		supplied = minimal.Supplied()
		err = accountsigner.StoreSuppliedFamilies(db, supplied)
		if err != nil {
			return nil, nil, fmt.Errorf("store supplied "+
				"families: %w", err)
		}

	case opening:
		has, err := accountsigner.HasKeystore(db)
		if err != nil || !has {
			return nil, nil, err
		}

		supplied, err = accountsigner.LoadSuppliedFamilies(db)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil, nil
	}

	local, err := accountsigner.LoadKeys(db, password, cfg.NetParams)
	if err != nil {
		return nil, nil, fmt.Errorf("load local keys: %w", err)
	}

	var localFamilies []keychain.KeyFamily
	for _, acct := range local.Accounts {
		localFamilies = append(
			localFamilies, keychain.KeyFamily(acct.Account),
		)
	}
	if err := checkSplitCoverage(supplied, localFamilies); err != nil {
		local.Zero()

		return nil, nil, err
	}

	return local, supplied, nil
}
