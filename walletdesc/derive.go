package walletdesc

import (
	"encoding/binary"
	"fmt"

	btcaddr "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
)

// Fingerprint returns the BIP32 fingerprint of key: the first four bytes of
// HASH160 of its compressed public key, read big-endian.
func Fingerprint(key *hdkeychain.ExtendedKey) (uint32, error) {
	pub, err := key.ECPubKey()
	if err != nil {
		return 0, fmt.Errorf("derive public key: %w", err)
	}

	hash := btcaddr.Hash160(pub.SerializeCompressed())

	return binary.BigEndian.Uint32(hash[:4]), nil
}

// deriveHardened walks a path of child indexes from key. When legacy is
// true it uses btcwallet's DeriveNonStandard, otherwise standard BIP32.
// Intermediate keys are zeroed as the walk proceeds.
func deriveHardened(key *hdkeychain.ExtendedKey, path []uint32,
	legacy bool) (*hdkeychain.ExtendedKey, error) {

	current := key
	for _, index := range path {
		var (
			child *hdkeychain.ExtendedKey
			err   error
		)
		if legacy {
			// Matching btcwallet's legacy derivation is the point.
			child, err = current.DeriveNonStandard(index)
		} else {
			child, err = current.Derive(index)
		}
		if err != nil {
			return nil, fmt.Errorf("derive child %d: %w", index,
				err)
		}

		if current != key {
			current.Zero()
		}
		current = child
	}

	return current, nil
}

// accountPublicKey derives the neutered account key at
// purpose'/coin'/account' from a master key the way btcwallet does.
func accountPublicKey(root *hdkeychain.ExtendedKey, purpose, coin,
	account uint32) (*hdkeychain.ExtendedKey, error) {

	acct, err := deriveHardened(
		root, accountPath(purpose, coin, account), true,
	)
	if err != nil {
		return nil, err
	}
	defer acct.Zero()

	return independentPublic(acct)
}

// independentPublic returns the neutered form of key as a fully separate
// value. hdkeychain's Neuter shares the chain code and public key slices
// with the private key, so wiping the private key afterwards would also
// wipe the public one. Re-parsing the serialization breaks that aliasing.
func independentPublic(key *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey,
	error) {

	pub, err := key.Neuter()
	if err != nil {
		return nil, err
	}

	return hdkeychain.NewKeyFromString(pub.String())
}

// legacyCompatible reports whether a hardened path derives the same key
// under standard BIP32 and under btcwallet's legacy derivation. They differ
// for roughly one hardened step in 256, when the parent private key has a
// leading zero byte.
func legacyCompatible(root *hdkeychain.ExtendedKey,
	path []uint32) (bool, error) {

	standard, err := deriveHardened(root, path, false)
	if err != nil {
		return false, err
	}
	defer standard.Zero()

	legacy, err := deriveHardened(root, path, true)
	if err != nil {
		return false, err
	}
	defer legacy.Zero()

	standardPub, err := standard.Neuter()
	if err != nil {
		return false, err
	}
	legacyPub, err := legacy.Neuter()
	if err != nil {
		return false, err
	}

	return standardPub.String() == legacyPub.String(), nil
}

// accountPath returns the hardened path purpose'/coin'/account'.
func accountPath(purpose, coin, account uint32) []uint32 {
	return []uint32{
		purpose + hdkeychain.HardenedKeyStart,
		coin + hdkeychain.HardenedKeyStart,
		account + hdkeychain.HardenedKeyStart,
	}
}
