package walletcore

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
)

// ErrWatchOnlyWithoutSigner is returned when an existing database is
// watch-only, holds no account keys, and no remote signer is configured to
// sign for it.
var ErrWatchOnlyWithoutSigner = errors.New("the wallet database holds public " +
	"keys only; configure the remote signer that holds its private keys")

// CreateAccountSigning creates a wallet from account-level private keys:
// a watch-only btcwallet from their public half, the keys encrypted under
// password in the same database, and lnd's RPC key ring signing through
// an in-process account signer. The signer works on its own copy of keys,
// so the caller still owns and wipes keys. cfg.PublicPass stays
// the static public passphrase, as for a seed wallet: the keystore is what
// password protects.
func CreateAccountSigning(cfg btcwallet.Config, keys *walletdesc.AccountKeys,
	password []byte,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	bundle, err := keys.Bundle()
	if err != nil {
		return nil, err
	}

	btcw, err := NewWatchOnlyBtcWallet(cfg, bundle, blockCache)
	if err != nil {
		return nil, err
	}

	db := btcw.InternalWallet().Database()
	if err := accountsigner.StoreKeys(db, password, keys, nil); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("store account keys: %w", err)
	}

	signerKeys, err := keys.Clone()
	if err != nil {
		_ = db.Close()

		return nil, err
	}

	return newAccountSigning(btcw, signerKeys, cfg)
}

// OpenExisting opens an existing self-managed wallet database of either
// kind. A database that holds its own private keys comes back with a nil
// KeyRing and Conn, and signs through btcwallet as before. A watch-only
// database with an account keystore comes back signing through the account
// signer, after password has decrypted the keystore. A watch-only database
// without one is refused: it needs a remote signer, which is opened with
// OpenRemoteSigning instead.
func OpenExisting(cfg btcwallet.Config, password []byte,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	loader, err := btcwallet.NewWalletLoader(
		cfg.NetParams, cfg.RecoveryWindow, cfg.LoaderOptions...,
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet loader: %w", err)
	}

	w, err := loader.OpenExistingWallet(cfg.PublicPass, false)
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {

		// A remote-signing wallet's public data is encrypted under
		// the user's password, not the static passphrase, so this is
		// what opening one without its signer config looks like.
		return nil, fmt.Errorf("%w (a wallet created for a remote "+
			"signer also needs its remote signer configured)", err)
	}
	if err != nil {
		return nil, err
	}
	closeWallet := func() {
		w.Stop()
		w.WaitForShutdown()
		_ = w.Database().Close()
	}

	var keys *walletdesc.AccountKeys
	if w.Manager.WatchOnly() {
		keys, err = accountsigner.LoadKeys(
			w.Database(), password, cfg.NetParams,
		)
		switch {
		case errors.Is(err, accountsigner.ErrNoKeystore):
			closeWallet()

			return nil, ErrWatchOnlyWithoutSigner

		case err != nil:
			closeWallet()

			return nil, err
		}

		cfg.WatchOnly = true
		cfg.PrivatePass = nil
	}

	cfg.Wallet = w
	btcw, err := btcwallet.New(cfg, blockCache)
	if err != nil {
		if keys != nil {
			keys.Zero()
		}
		closeWallet()

		return nil, err
	}

	if keys == nil {
		return &RemoteSigning{BtcWallet: btcw}, nil
	}

	return newAccountSigning(btcw, keys, cfg)
}

// newAccountSigning fronts btcw with the RPC key ring over an in-process
// account signer for keys.
func newAccountSigning(btcw *btcwallet.BtcWallet, keys *walletdesc.AccountKeys,
	cfg btcwallet.Config) (*RemoteSigning, error) {

	signer := accountsigner.New(keys, cfg.NetParams)
	ring, err := NewRemoteKeyRing(btcw, cfg.CoinType, signer, cfg.NetParams)
	if err != nil {
		signer.Stop()
		_ = btcw.InternalWallet().Database().Close()

		return nil, err
	}

	return &RemoteSigning{BtcWallet: btcw, KeyRing: ring, Conn: signer}, nil
}

// Apply fills the signing fields of core from r: the RPC key ring when a
// signer is in front of the wallet, btcwallet itself otherwise.
func (r *RemoteSigning) Apply(core *Wallet, coinType uint32) {
	core.BtcWallet = r.BtcWallet
	if r.KeyRing == nil {
		core.Signer = r.BtcWallet
		core.Controller = r.BtcWallet
		core.KeyRing = keychain.NewBtcWalletKeyRing(
			r.BtcWallet.InternalWallet(), coinType,
		)

		return
	}

	core.Signer = r.KeyRing
	core.Controller = r.KeyRing
	core.KeyRing = r.KeyRing
	core.RemoteSigner = r.Conn
}

// WalletSource is the creation or open input of a self-managed wallet, as
// both backends' configs carry it.
type WalletSource struct {
	// Seed or RootKey creates a key-holding wallet.
	Seed    []byte
	RootKey *hdkeychain.ExtendedKey

	// WatchOnly creates a remote-signing wallet; RemoteSigner signs for
	// it and also selects opening an existing one.
	WatchOnly    *walletdesc.WatchOnlyBundle
	RemoteSigner *RemoteSignerConfig

	// AccountKeys creates an account-key wallet.
	AccountKeys *walletdesc.AccountKeys

	// WalletPassword is the user's wallet password.
	WalletPassword []byte
}

// OpenSigning creates or opens the btcwallet described by cfg and src and
// puts the right signer in front of it. cfg carries the backend's chain
// source, network and loader options with the static public passphrase;
// the source must already have passed ValidateWalletSource.
func OpenSigning(ctx context.Context, cfg btcwallet.Config, src WalletSource,
	blockCache *blockcache.BlockCache) (*RemoteSigning, error) {

	switch {
	case src.RemoteSigner != nil:
		// A watch-only wallet signing remotely has no private
		// passphrase, so the user's password protects its public
		// data instead.
		cfg.PublicPass = src.WalletPassword
		signing, err := OpenRemoteSigning(
			ctx, cfg, src.WatchOnly, *src.RemoteSigner, blockCache,
		)
		if err != nil {
			return nil, fmt.Errorf("open remote-signing wallet: %w",
				err)
		}

		return signing, nil

	case src.AccountKeys != nil:
		signing, err := CreateAccountSigning(
			cfg, src.AccountKeys, src.WalletPassword, blockCache,
		)
		if err != nil {
			return nil, fmt.Errorf("create account-key wallet: %w",
				err)
		}

		return signing, nil

	case src.Seed != nil || src.RootKey != nil:
		btcw, err := NewBtcWallet(cfg, src.RootKey, blockCache)
		if err != nil {
			return nil, fmt.Errorf("create btcwallet: %w", err)
		}

		return &RemoteSigning{BtcWallet: btcw}, nil

	default:
		signing, err := OpenExisting(
			cfg, src.WalletPassword, blockCache,
		)
		if err != nil {
			return nil, fmt.Errorf("open btcwallet: %w", err)
		}

		return signing, nil
	}
}
