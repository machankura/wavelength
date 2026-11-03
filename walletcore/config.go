package walletcore

import (
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
)

// DefaultBlockCacheSize is the number of blocks to cache in memory.
// This prevents redundant block fetches during wallet sync.
const DefaultBlockCacheSize uint64 = 20

// SeedLen is the required length in bytes of a raw HD wallet seed.
const SeedLen = 32

// PublicWalletPassphrase encrypts btcwallet's public (watch-only)
// data: addresses, transaction history, and public keys. It is a
// static constant rather than a secret, analogous to lnd's default
// "public" passphrase. The wallet's key material is encrypted
// separately under the user-supplied private passphrase
// (Config.WalletPassword), so this constant gates nothing an
// attacker with database access could not already observe on chain.
var PublicWalletPassphrase = []byte("lwwallet")

// CoinTypeForNet returns the BIP44 coin type for the given network.
// Mainnet uses coin type 0, while all test networks use coin type 1.
func CoinTypeForNet(params *chaincfg.Params) uint32 {
	switch params.Net {
	case chaincfg.MainNetParams.Net:
		return 0

	default:
		return 1
	}
}

// Config holds the base configuration shared by all wallet backends
// that wrap btcwallet.
type Config struct {
	// Seed is the raw master seed used for HD key derivation when
	// creating a new wallet database. It must be exactly SeedLen
	// bytes when set. A nil Seed opens an existing wallet database
	// instead; the seed itself is never persisted by the wallet
	// outside btcwallet's own encrypted key store.
	Seed []byte

	// RootKey is a BIP32 master private key used instead of Seed when
	// creating a new wallet database, for wallets defined by output
	// descriptors rather than a seed. A wallet built from the master key
	// of a seed is identical to one built from the seed itself. At most
	// one of Seed and RootKey may be set, and like Seed it must be unset
	// when opening an existing database.
	RootKey *hdkeychain.ExtendedKey

	// WatchOnly is the account public keys to create a watch-only
	// wallet from, instead of a seed or root key. It requires
	// RemoteSigner and, like Seed, must be unset when opening an
	// existing database.
	WatchOnly *walletdesc.WatchOnlyBundle

	// WatchOnlyMinimal is a minimal bundle to create a split-signing
	// wallet from: fund keys remote, authentication keys local. Like
	// WatchOnly it requires RemoteSigner and excludes every other
	// creation input.
	WatchOnlyMinimal *walletdesc.MinimalBundle

	// WatchOnlyManifest is the manifest WatchOnlyMinimal came from, if
	// any. The wallet stores it, checks it on every open and reports
	// its hash.
	WatchOnlyManifest *walletdesc.Manifest

	// AccountKeys is the account-level private keys to create a wallet
	// from, instead of a seed or root key. The wallet keeps them
	// encrypted under WalletPassword and signs in process. Like Seed it
	// must be unset when opening an existing database, which recognises
	// an account-key wallet by itself.
	AccountKeys *walletdesc.AccountKeys

	// RemoteSigner, when set, runs the wallet watch-only: the database
	// holds only account public keys and every signature is requested
	// from this signer. WalletPassword then encrypts the database's
	// public data instead, since there is no private passphrase.
	RemoteSigner *RemoteSignerConfig

	// WalletPassword is the private passphrase that encrypts the
	// wallet database's key material (btcwallet's PrivatePass). It
	// is required both when creating a new wallet and when opening
	// an existing one; opening fails when it does not match the
	// passphrase the database was created with.
	WalletPassword []byte

	// Birthday is the time the wallet seed was created. When set, btcwallet
	// uses it to bound recovery rescans instead of starting from genesis.
	Birthday time.Time

	// ChainParams identifies the Bitcoin network (mainnet, testnet,
	// testnet4, regtest). Used for address encoding and HD derivation
	// paths.
	ChainParams *chaincfg.Params

	// RecoveryWindow specifies the address look-ahead for
	// discovering used addresses during wallet recovery or restart.
	// A value of 0 means no recovery is performed. Typical value:
	// 100 for restart scenarios where previously derived keys must
	// be rediscovered.
	RecoveryWindow uint32

	// DBDir is the directory for btcwallet's bbolt database. The
	// caller owns the lifecycle of this directory.
	DBDir string

	// Log is an optional logger for the wallet and all its
	// sub-components. If None, the wallet falls back to
	// btclog.Disabled.
	Log fn.Option[btclog.Logger]
}
