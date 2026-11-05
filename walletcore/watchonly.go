package walletcore

import (
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
)

// placeholderAccountName names the account that fills an on-chain scope a
// bundle left empty.
const placeholderAccountName = "placeholder"

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

	if err := importScopePlaceholders(
		w, cfg.NetParams, bundle,
	); err != nil {

		closeWallet()

		return nil, err
	}

	cfg.Wallet = w
	btcw, err := btcwallet.New(cfg, blockCache)
	if err != nil {
		closeWallet()

		return nil, err
	}

	return btcw, nil
}

// importScopePlaceholders gives account 0 to each of lnd's default on-chain
// scopes that the bundle leaves empty. lnd activates those scopes in every
// wallet, and btcwallet's recovery reads account 0 of each active scope, so
// one empty scope makes every sync fail with "account 0 not found".
//
// The placeholder's key is discarded, so nothing sent to it could be spent.
// Wavelength receives and takes change on BIP86 only, and BIP86 is not filled
// in here: a wallet without it must keep failing. The account's name is not
// "default", so descriptor export does not take its key for a real one.
func importScopePlaceholders(w *wallet.Wallet, params *chaincfg.Params,
	bundle *walletdesc.WatchOnlyBundle) error {

	scopes := []waddrmgr.KeyScope{
		waddrmgr.KeyScopeBIP0049Plus, waddrmgr.KeyScopeBIP0084,
	}
	for _, scope := range scopes {
		supplied := slices.ContainsFunc(
			bundle.Accounts, func(
				a walletdesc.WatchOnlyAccount) bool {

				return a.Purpose == scope.Purpose &&
					a.CoinType == scope.Coin &&
					a.Account == 0
			},
		)
		if supplied {
			continue
		}

		key, err := walletdesc.PlaceholderAccountKey(
			scope.Purpose, scope.Coin, params,
		)
		if err != nil {
			return fmt.Errorf("create placeholder for scope %v: %w",
				scope, err)
		}

		props, err := w.ImportAccountWithScope(
			placeholderAccountName, key, 0, scope,
			watchOnlyAddrSchema(scope),
		)
		if err != nil {
			return fmt.Errorf("import placeholder for scope %v: %w",
				scope, err)
		}
		if props.AccountNumber != 0 {
			return fmt.Errorf("import placeholder for scope %v: "+
				"wallet numbered it %d", scope,
				props.AccountNumber)
		}
	}

	return nil
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
