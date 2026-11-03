//go:build !(js && wasm)

package signerserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/aezeed"
)

// StoreFileName is the signer's key store in its data directory.
const StoreFileName = "signer.db"

// storeOpenTimeout bounds waiting for the store's file lock.
const storeOpenTimeout = 10 * time.Second

// ErrStoreExists is returned when creating a store over an existing one.
var ErrStoreExists = errors.New("signer key store already exists")

// StorePath returns the key store path in dir.
func StorePath(dir string) string {
	return filepath.Join(dir, StoreFileName)
}

// CreateStore writes keys to a new key store in dir, encrypted under
// password with btcwallet's snacl scheme.
func CreateStore(dir string, password []byte,
	keys *walletdesc.AccountKeys) error {

	path := StorePath(dir)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w at %s", ErrStoreExists, path)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	db, err := walletdb.Create("bdb", path, true, storeOpenTimeout, false)
	if err != nil {
		return fmt.Errorf("create key store: %w", err)
	}

	err = accountsigner.StoreKeys(db, password, keys, nil)
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}

	return err
}

// OpenStore decrypts the keys in dir's key store with password. The caller
// owns the result and must call Zero.
func OpenStore(dir string, password []byte,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	path := StorePath(dir)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no signer key store at %s: create "+
			"one first", path)
	}

	db, err := walletdb.Open("bdb", path, true, storeOpenTimeout, false)
	if err != nil {
		return nil, fmt.Errorf("open key store: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	return accountsigner.LoadKeys(db, password, params)
}

// KeysFromDescriptors returns the account keys of descriptor text:
// account-level private keys as given, or master-key descriptors turned
// into the account keys a btcwallet of that master key holds.
func KeysFromDescriptors(texts []string,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	if walletdesc.HasAccountKeys(texts) {
		return walletdesc.ParseAccountKeys(texts, params)
	}

	wd, err := walletdesc.Parse(texts, params)
	if err != nil {
		return nil, err
	}
	defer wd.Zero()

	return walletdesc.BtcwalletAccountKeys(wd.Root, params)
}

// KeysFromMnemonic returns the account keys of a Wavelength aezeed
// mnemonic: the keys a Wavelength daemon restored from that mnemonic
// holds. Wavelength pads the 16-byte aezeed entropy with 16 zero bytes to
// form its seed, so an lnd wallet from the same mnemonic has other keys.
func KeysFromMnemonic(words []string, passphrase []byte,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	var mnemonic aezeed.Mnemonic
	if len(words) != len(mnemonic) {
		return nil, fmt.Errorf("mnemonic must have %d words, got %d",
			len(mnemonic), len(words))
	}
	copy(mnemonic[:], words)

	cipherSeed, err := mnemonic.ToCipherSeed(passphrase)
	if err != nil {
		return nil, fmt.Errorf("decipher mnemonic: %w", err)
	}

	var seed [32]byte
	copy(seed[:], cipherSeed.Entropy[:])
	defer clear(seed[:])

	root, err := hdkeychain.NewMaster(seed[:], params)
	if err != nil {
		return nil, err
	}
	defer root.Zero()

	return walletdesc.BtcwalletAccountKeys(root, params)
}

// WriteBundle writes keys' full or minimal bundle to path. A minimal
// bundle holds private keys, so it is written owner-only and refused
// for a path that already exists readable by others.
func WriteBundle(path string, keys *walletdesc.AccountKeys,
	minimal bool) error {

	text, err := walletdesc.FormatBundle(keys, minimal)
	if err != nil {
		return err
	}
	defer clear(text)

	mode := os.FileMode(0o644)
	if minimal {
		mode = 0o600

		info, err := os.Stat(path)
		switch {
		case err == nil && info.Mode().Perm()&0o077 != 0:
			return fmt.Errorf("refusing to write a minimal "+
				"bundle, which holds private keys, to %s: it "+
				"is readable by other users (mode %04o)", path,
				info.Mode().Perm())

		case err != nil && !errors.Is(err, os.ErrNotExist):
			return err
		}
	}

	// The path is explicitly provided by the operator, and a full
	// bundle holds public keys only.
	return os.WriteFile(path, text, mode)
}
