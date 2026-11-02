package walletcore

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
)

var (
	// ErrSeedAndRootKey is returned when a wallet configuration sets both
	// creation inputs.
	ErrSeedAndRootKey = errors.New("seed and root key are mutually " +
		"exclusive")

	// ErrInvalidRootKey is returned for a root key that is not a BIP32
	// master private key for the wallet's network.
	ErrInvalidRootKey = errors.New("invalid root key")
)

// ValidateCreateInput checks the wallet creation inputs and reports whether
// any is set, which means a new database is to be created rather than an
// existing one opened.
func ValidateCreateInput(seed []byte, rootKey *hdkeychain.ExtendedKey,
	params *chaincfg.Params) (bool, error) {

	switch {
	case seed != nil && rootKey != nil:
		return false, ErrSeedAndRootKey

	case seed != nil:
		if len(seed) != SeedLen {
			return false, fmt.Errorf("seed must be %d "+
				"bytes, got %d", SeedLen, len(seed))
		}

		return true, nil

	case rootKey != nil:
		if !rootKey.IsPrivate() {
			return false, fmt.Errorf("%w: must be a private key",
				ErrInvalidRootKey)
		}
		if rootKey.Depth() != 0 {
			return false, fmt.Errorf("%w: must be a master key, "+
				"got depth %d", ErrInvalidRootKey,
				rootKey.Depth())
		}
		if !rootKey.IsForNet(params) {
			return false, fmt.Errorf("%w: key is for a different "+
				"network than %s", ErrInvalidRootKey,
				params.Name)
		}

		return true, nil

	default:
		return false, nil
	}
}

// NewBtcWallet builds lnd's btcwallet wrapper from cfg. With a nil rootKey
// it behaves exactly like btcwallet.New, creating the database from
// cfg.HdSeed or opening an existing one. With a rootKey it first creates the
// database from that master key through the same loader options, then hands
// the open wallet to btcwallet.New, which adopts it instead of creating its
// own. The database handle is closed again if adoption fails.
//
// Callers must have already checked, with ValidateCreateInput and their
// database probe, that a rootKey is only supplied when no database exists.
func NewBtcWallet(cfg btcwallet.Config, rootKey *hdkeychain.ExtendedKey,
	blockCache *blockcache.BlockCache) (*btcwallet.BtcWallet, error) {

	if rootKey == nil {
		return btcwallet.New(cfg, blockCache)
	}

	if cfg.HdSeed != nil {
		return nil, ErrSeedAndRootKey
	}

	loader, err := btcwallet.NewWalletLoader(
		cfg.NetParams, cfg.RecoveryWindow, cfg.LoaderOptions...,
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet loader: %w", err)
	}

	w, err := loader.CreateNewWalletExtendedKey(
		cfg.PublicPass, cfg.PrivatePass, rootKey, cfg.Birthday,
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet from root key: %w", err)
	}

	cfg.Wallet = w
	btcw, err := btcwallet.New(cfg, blockCache)
	if err != nil {
		w.Stop()
		w.WaitForShutdown()
		_ = w.Database().Close()

		return nil, err
	}

	return btcw, nil
}

// ValidateWalletSource extends ValidateCreateInput with the watch-only
// inputs: a bundle of account public keys or a set of account private keys
// creates a database like a seed does, and a remote signer config makes
// the wallet watch-only. It reports whether a new database is to be
// created. A bundle needs a remote signer, a remote-signing wallet is only
// ever created from a bundle, and account keys stand alone.
func ValidateWalletSource(seed []byte, rootKey *hdkeychain.ExtendedKey,
	bundle *walletdesc.WatchOnlyBundle, accountKeys *walletdesc.AccountKeys,
	remote *RemoteSignerConfig, params *chaincfg.Params) (bool, error) {

	create, err := ValidateCreateInput(seed, rootKey, params)
	if err != nil {
		return false, err
	}

	if accountKeys != nil {
		switch {
		case create || bundle != nil:
			return false, errors.New("account keys are mutually " +
				"exclusive with a seed, root key or " +
				"watch-only bundle")

		case remote != nil:
			return false, errors.New("account keys sign in " +
				"process; a remote signer cannot also be " +
				"configured")
		}

		return true, nil
	}

	switch {
	case bundle != nil && create:
		return false, ErrBundleAndSeed

	case bundle != nil && remote == nil:
		return false, errors.New("a watch-only bundle needs a remote " +
			"signer")

	case create && remote != nil:
		return false, errors.New("a remote-signing wallet is created " +
			"from a watch-only bundle, not a seed or root key")
	}

	return create || bundle != nil, nil
}
