package accountsigner

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/keychain"
)

// ErrUnknownKey is returned for a derivation path or key locator no
// account key covers.
var ErrUnknownKey = errors.New("no account key for this derivation path")

// privKeyAt derives the private key at a full BIP32 path
// purpose'/coin'/account'/branch/index from the matching account key. The
// two steps below the account are not hardened, so btcwallet's legacy
// derivation cannot make them differ.
func privKeyAt(keys *walletdesc.AccountKeys,
	path []uint32) (*btcec.PrivateKey, error) {

	if len(path) != 5 {
		return nil, fmt.Errorf("%w: path has %d steps, want 5",
			ErrUnknownKey, len(path))
	}
	for _, step := range path[:3] {
		if step < hdkeychain.HardenedKeyStart {
			return nil, fmt.Errorf("%w: account path is not "+
				"hardened", ErrUnknownKey)
		}
	}
	if path[3] >= hdkeychain.HardenedKeyStart ||
		path[4] >= hdkeychain.HardenedKeyStart {
		return nil, fmt.Errorf("%w: branch and index must not be "+
			"hardened", ErrUnknownKey)
	}

	purpose := path[0] - hdkeychain.HardenedKeyStart
	coin := path[1] - hdkeychain.HardenedKeyStart
	account := path[2] - hdkeychain.HardenedKeyStart

	acct, ok := keys.Account(purpose, account)
	if !ok || acct.CoinType != coin {
		return nil, fmt.Errorf("%w: %d'/%d'/%d'", ErrUnknownKey,
			purpose, coin, account)
	}

	branch, err := acct.Key.Derive(path[3])
	if err != nil {
		return nil, err
	}
	defer branch.Zero()

	child, err := branch.Derive(path[4])
	if err != nil {
		return nil, err
	}
	defer child.Zero()

	priv, err := child.ECPrivKey()
	if err != nil {
		return nil, err
	}

	// ECPrivKey shares the scalar with child, which is zeroed on
	// return, so hand back an independent copy.
	scalar := priv.Key.Bytes()
	copied, _ := btcec.PrivKeyFromBytes(scalar[:])

	return copied, nil
}

// familyPath returns the BIP32 path of a key family key.
func familyPath(coinType uint32, loc keychain.KeyLocator) []uint32 {
	return []uint32{
		keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
		coinType + hdkeychain.HardenedKeyStart,
		uint32(loc.Family) + hdkeychain.HardenedKeyStart,
		0,
		loc.Index,
	}
}
