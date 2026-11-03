package accountsigner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/keychain"
)

// keystoreVersion is the format of the encrypted key record.
const keystoreVersion = 1

var (
	// keystoreBucket is the wallet database's top-level bucket for the
	// encrypted account keys. btcwallet does not use it, and its
	// presence is what marks a watch-only database as an account-key
	// wallet.
	keystoreBucket = []byte("wavelength-account-keys")

	// keystoreParamsKey holds the marshalled snacl secret key parameters
	// (salt and scrypt cost), never the key itself.
	keystoreParamsKey = []byte("params")

	// keystoreKeysKey holds the encrypted key record.
	keystoreKeysKey = []byte("keys")

	// ErrWrongPassword is returned when the password does not open the
	// keystore.
	ErrWrongPassword = errors.New("wallet password does not open the " +
		"account keystore")

	// ErrNoKeystore is returned when the database holds no account
	// keystore.
	ErrNoKeystore = errors.New("no account keystore in the wallet database")
)

// HasKeystore reports whether db holds an account keystore.
func HasKeystore(db walletdb.DB) (bool, error) {
	var found bool
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		found = tx.ReadBucket(keystoreBucket) != nil

		return nil
	})

	return found, err
}

// StoreKeys encrypts keys under password with btcwallet's snacl scheme and
// writes them to db, which must not already hold a keystore. opts sets the
// scrypt cost; nil selects waddrmgr.DefaultScryptOptions.
func StoreKeys(db walletdb.DB, password []byte, keys *walletdesc.AccountKeys,
	opts *waddrmgr.ScryptOptions) error {

	if len(password) == 0 {
		return errors.New("account keystore needs a password")
	}
	if opts == nil {
		opts = &waddrmgr.DefaultScryptOptions
	}

	pass := bytes.Clone(password)
	defer zero(pass)
	secret, err := snacl.NewSecretKey(&pass, opts.N, opts.R, opts.P)
	if err != nil {
		return fmt.Errorf("derive keystore key: %w", err)
	}
	defer secret.Zero()

	plain, err := encodeKeys(keys)
	if err != nil {
		return err
	}
	defer zero(plain)

	sealed, err := secret.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("encrypt account keys: %w", err)
	}

	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		if tx.ReadWriteBucket(keystoreBucket) != nil {
			return errors.New("wallet database already holds an " +
				"account keystore")
		}

		bucket, err := tx.CreateTopLevelBucket(keystoreBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(
			keystoreParamsKey, secret.Marshal(),
		); err != nil {
			return err
		}

		return bucket.Put(keystoreKeysKey, sealed)
	})
}

// LoadKeys decrypts the account keys in db with password. A wrong password
// returns ErrWrongPassword; a database without a keystore returns
// ErrNoKeystore. The caller owns the result and must call Zero.
func LoadKeys(db walletdb.DB, password []byte,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	var marshalled, sealed []byte
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		bucket := tx.ReadBucket(keystoreBucket)
		if bucket == nil {
			return ErrNoKeystore
		}

		marshalled = bytes.Clone(bucket.Get(keystoreParamsKey))
		sealed = bytes.Clone(bucket.Get(keystoreKeysKey))

		return nil
	})
	if err != nil {
		return nil, err
	}
	if marshalled == nil || sealed == nil {
		return nil, errors.New("account keystore is incomplete")
	}

	var secret snacl.SecretKey
	if err := secret.Unmarshal(marshalled); err != nil {
		return nil, fmt.Errorf("read keystore parameters: %w", err)
	}
	defer secret.Zero()

	pass := bytes.Clone(password)
	defer zero(pass)
	if err := secret.DeriveKey(&pass); err != nil {
		if errors.Is(err, snacl.ErrInvalidPassword) {
			return nil, ErrWrongPassword
		}

		return nil, fmt.Errorf("derive keystore key: %w", err)
	}

	plain, err := secret.Decrypt(sealed)
	if err != nil {
		return nil, ErrWrongPassword
	}
	defer zero(plain)

	return decodeKeys(plain, params)
}

// encodeKeys serializes keys: version, fingerprint, count, then for each
// account its purpose, coin type, account and base58 private key.
func encodeKeys(keys *walletdesc.AccountKeys) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(keystoreVersion)

	write := func(v uint32) {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], v)
		buf.Write(raw[:])
	}
	write(keys.MasterFingerprint)
	write(uint32(len(keys.Accounts)))

	for _, acct := range keys.Accounts {
		write(acct.Purpose)
		write(acct.CoinType)
		write(acct.Account)

		text := acct.Key.String()
		if len(text) > 0xff {
			return nil, errors.New("account key too long")
		}
		buf.WriteByte(byte(len(text)))
		buf.WriteString(text)
	}

	return buf.Bytes(), nil
}

// decodeKeys reverses encodeKeys, refusing keys that are not private keys
// for params.
func decodeKeys(plain []byte,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	r := bytes.NewReader(plain)
	version, err := r.ReadByte()
	if err != nil || version != keystoreVersion {
		return nil, fmt.Errorf("unsupported keystore version %d",
			version)
	}

	read := func() (uint32, error) {
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return 0, err
		}

		return binary.BigEndian.Uint32(raw[:]), nil
	}

	keys := &walletdesc.AccountKeys{}
	fail := func(err error) (*walletdesc.AccountKeys, error) {
		keys.Zero()

		return nil, fmt.Errorf("decode account keystore: %w", err)
	}

	if keys.MasterFingerprint, err = read(); err != nil {
		return fail(err)
	}
	count, err := read()
	if err != nil {
		return fail(err)
	}
	if count > walletdesc.MaxBundleAccounts {
		return fail(fmt.Errorf("%d accounts", count))
	}

	for range count {
		var acct walletdesc.AccountKey
		for _, field := range []*uint32{
			&acct.Purpose, &acct.CoinType, &acct.Account,
		} {
			if *field, err = read(); err != nil {
				return fail(err)
			}
		}

		size, err := r.ReadByte()
		if err != nil {
			return fail(err)
		}
		text := make([]byte, size)
		if _, err := io.ReadFull(r, text); err != nil {
			return fail(err)
		}

		acct.Key, err = hdkeychain.NewKeyFromString(string(text))
		zero(text)
		if err != nil {
			return fail(err)
		}
		if !acct.Key.IsPrivate() || !acct.Key.IsForNet(params) {
			acct.Key.Zero()

			return fail(
				errors.New("stored key is not a private key " +
					"for this network"),
			)
		}

		keys.Accounts = append(keys.Accounts, acct)
	}
	if r.Len() != 0 {
		return fail(errors.New("trailing data"))
	}

	return keys, nil
}

// zero overwrites b.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// keystoreSuppliedKey holds the key families a minimal bundle supplied,
// remote and local. It is public, so it is stored unencrypted.
var keystoreSuppliedKey = []byte("supplied-families")

// StoreSuppliedFamilies records the key families a split-signing wallet's
// bundle supplied, next to its keystore. The keystore must already exist.
func StoreSuppliedFamilies(db walletdb.DB,
	families []keychain.KeyFamily) error {

	raw := make([]byte, 0, 4*len(families))
	for _, family := range families {
		raw = binary.BigEndian.AppendUint32(raw, uint32(family))
	}

	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		bucket := tx.ReadWriteBucket(keystoreBucket)
		if bucket == nil {
			return ErrNoKeystore
		}

		return bucket.Put(keystoreSuppliedKey, raw)
	})
}

// LoadSuppliedFamilies returns the key families StoreSuppliedFamilies
// recorded, or nil for a keystore that holds a full set of account keys.
func LoadSuppliedFamilies(db walletdb.DB) ([]keychain.KeyFamily, error) {
	var families []keychain.KeyFamily
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		bucket := tx.ReadBucket(keystoreBucket)
		if bucket == nil {
			return ErrNoKeystore
		}

		raw := bucket.Get(keystoreSuppliedKey)
		if len(raw)%4 != 0 {
			return errors.New("malformed supplied families record")
		}
		for i := 0; i < len(raw); i += 4 {
			families = append(
				families,
				keychain.KeyFamily(
					binary.BigEndian.Uint32(raw[i:]),
				),
			)
		}

		return nil
	})

	return families, err
}
