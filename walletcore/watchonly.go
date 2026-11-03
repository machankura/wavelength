package walletcore

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
)

var (
	// ErrBundleAndSeed is returned when a watch-only bundle is combined
	// with a seed or root key.
	ErrBundleAndSeed = errors.New("watch-only bundle is mutually " +
		"exclusive with a seed or root key")

	// ErrNotWatchOnly is returned when a wallet opened in watch-only mode
	// still holds private keys, or the reverse.
	ErrNotWatchOnly = errors.New("wallet database watch-only mode does " +
		"not match the configuration")
)

// NewWatchOnlyBtcWallet builds lnd's btcwallet wrapper for a wallet that
// holds no private keys. With a bundle it creates the database from the
// bundle's account public keys, mirroring lnd's own watch-only
// initialization; with a nil bundle it opens an existing watch-only
// database. Either way the result has cfg.WatchOnly set, so btcwallet
// skips the private unlock and creates no account it would need the master
// key for.
//
// A watch-only btcwallet has no private passphrase, so callers pass the
// user's wallet password as cfg.PublicPass: it then encrypts the addresses
// and account keys at rest and is required to open the database again.
//
// Callers must have already checked, with their database probe, that a
// bundle is only supplied when no database exists.
func NewWatchOnlyBtcWallet(cfg btcwallet.Config,
	bundle *walletdesc.WatchOnlyBundle,
	blockCache *blockcache.BlockCache) (*btcwallet.BtcWallet, error) {

	if cfg.HdSeed != nil {
		return nil, ErrBundleAndSeed
	}
	if len(cfg.PublicPass) == 0 {
		return nil, errors.New("watch-only wallet needs a password")
	}
	cfg.WatchOnly = true
	cfg.PrivatePass = nil

	loader, err := btcwallet.NewWalletLoader(
		cfg.NetParams, cfg.RecoveryWindow, cfg.LoaderOptions...,
	)
	if err != nil {
		return nil, fmt.Errorf("create wallet loader: %w", err)
	}

	if bundle == nil {
		// btcwallet.New creates a wallet with a random seed when none
		// exists, which would be a key-holding wallet nobody has the
		// seed of. Opening must find an existing database.
		exists, err := loader.WalletExists()
		if err != nil {
			return nil, fmt.Errorf("probe wallet database: %w", err)
		}
		if !exists {
			return nil, errors.New("no watch-only wallet " +
				"database to open")
		}

		btcw, err := btcwallet.New(cfg, blockCache)
		if err != nil {
			return nil, err
		}
		if !btcw.InternalWallet().AddrManager().WatchOnly() {
			_ = btcw.InternalWallet().Database().Close()

			return nil, fmt.Errorf("%w: the database holds "+
				"private keys, but a remote signer is "+
				"configured", ErrNotWatchOnly)
		}

		return btcw, nil
	}

	w, err := loader.CreateNewWatchingOnlyWallet(
		cfg.PublicPass, cfg.Birthday,
	)
	if err != nil {
		return nil, fmt.Errorf("create watch-only wallet: %w", err)
	}

	closeWallet := func() {
		w.Stop()
		w.WaitForShutdown()
		_ = w.Database().Close()
	}

	// The bundle is in import order, and btcwallet numbers each import
	// one past its scope's last account, so importing in this order
	// gives every account the number its key was derived at.
	for _, acct := range bundle.Accounts {
		scope := waddrmgr.KeyScope{
			Purpose: acct.Purpose,
			Coin:    acct.CoinType,
		}

		// An overridden slot records its own source's fingerprint.
		fingerprint := bundle.MasterFingerprint
		if acct.Origin != nil {
			fingerprint = acct.Origin.Fingerprint
		}

		props, err := w.ImportAccountWithScope(
			watchOnlyAccountName(scope, acct.Account), acct.Key,
			fingerprint, scope, watchOnlyAddrSchema(scope),
		)
		if err != nil {
			closeWallet()

			return nil, fmt.Errorf("import account %d'/%d'/%d': %w",
				acct.Purpose, acct.CoinType, acct.Account, err)
		}
		if props.AccountNumber != acct.Account {
			closeWallet()

			return nil, fmt.Errorf("import account %d'/%d'/%d': "+
				"wallet numbered it %d", acct.Purpose,
				acct.CoinType, acct.Account,
				props.AccountNumber)
		}
	}

	cfg.Wallet = w
	btcw, err := btcwallet.New(cfg, blockCache)
	if err != nil {
		closeWallet()

		return nil, err
	}

	return btcw, nil
}

// watchOnlyAccountName names an imported account the way lnd does: index
// 0 of each scope is "default", which is what the wallet's balance and
// address calls look up.
func watchOnlyAccountName(scope waddrmgr.KeyScope, account uint32) string {
	if account == 0 {
		return "default"
	}

	return fmt.Sprintf("%s/%d'", scope.String(), account)
}

// watchOnlyAddrSchema returns the address schema lnd imports an account
// with: the scope's own schema for BIP49 and BIP86, and the BIP84 witness
// schema otherwise, which covers lnd's key family scope.
func watchOnlyAddrSchema(scope waddrmgr.KeyScope) waddrmgr.ScopeAddrSchema {
	switch scope {
	case waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0086:
		return waddrmgr.ScopeAddrMap[scope]

	default:
		return waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
	}
}
