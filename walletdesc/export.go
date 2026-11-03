package walletdesc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/keychain"
)

// BtcwalletAccountKeys returns the account keys a btcwallet built from root
// holds: the BIP86 and BIP84 accounts and every key family, derived exactly
// as btcwallet derives them, legacy quirks included. btcwallet creates each
// on-chain account and key family 0 from keys it derived in memory with
// DeriveNonStandard, which keeps a private key with a leading zero byte
// unpadded, and creates families 1 to 255 later from the coin-level key as
// stored, which is padded. A signer built from these keys therefore signs
// for exactly the addresses and keys a seed wallet of root would use. The
// caller must call Zero.
func BtcwalletAccountKeys(root *hdkeychain.ExtendedKey,
	params *chaincfg.Params) (*AccountKeys, error) {

	fp, err := Fingerprint(root)
	if err != nil {
		return nil, err
	}

	keys := &AccountKeys{MasterFingerprint: fp}
	fail := func(err error) (*AccountKeys, error) {
		keys.Zero()

		return nil, err
	}

	for _, purpose := range []uint32{
		ScriptWitnessPubKeyHash.Purpose(), ScriptTaproot.Purpose(),
	} {
		key, err := deriveHardened(
			root, accountPath(purpose, 0, 0), true,
		)
		if err != nil {
			return fail(err)
		}
		keys.Accounts = append(keys.Accounts, AccountKey{
			Purpose: purpose,
			Account: 0,
			Key:     key,
		})
	}

	coin := coinTypeForNet(params)
	coinKey, err := deriveHardened(
		root, []uint32{hardened(PurposeKeyFamily), hardened(coin)},
		true,
	)
	if err != nil {
		return fail(err)
	}
	defer coinKey.Zero()

	stored, err := hdkeychain.NewKeyFromString(coinKey.String())
	if err != nil {
		return fail(err)
	}
	defer stored.Zero()

	for family := uint32(0); family <=
		uint32(keyfamily.MaxFamily); family++ {

		parent := stored
		if family == 0 {
			parent = coinKey
		}

		// Matching btcwallet's legacy derivation is the point.
		key, err := parent.DeriveNonStandard(hardened(family))
		if err != nil {
			return fail(err)
		}
		keys.Accounts = append(keys.Accounts, AccountKey{
			Purpose:  PurposeKeyFamily,
			CoinType: coin,
			Account:  family,
			Key:      key,
		})
	}

	return keys, nil
}

// FormatBundle renders keys as bundle text, one entry per line with a
// BIP380 checksum. A full bundle carries every account as a public key,
// for a wallet that signs everything remotely. A minimal bundle carries
// the on-chain accounts and the fund families as public keys and the
// authentication families as private keys, for split signing; its text is
// as secret as those keys.
func FormatBundle(keys *AccountKeys, minimal bool) ([]byte, error) {
	origin := FormatFingerprint(keys.MasterFingerprint)
	funds := keyfamily.Families(keyfamily.Funds)
	auth := keyfamily.Families(keyfamily.Auth)

	var lines []string
	for _, acct := range keys.Accounts {
		var entry string
		switch acct.Purpose {
		case ScriptTaproot.Purpose(), ScriptWitnessPubKeyHash.Purpose():
			pub, err := independentPublic(acct.Key)
			if err != nil {
				return nil, err
			}

			function := "tr"
			if acct.Purpose == ScriptWitnessPubKeyHash.Purpose() {
				function = "wpkh"
			}
			entry = fmt.Sprintf("%s([%s/%dh/%dh/%dh]%s/<0;1>/*)",
				function, origin, acct.Purpose, acct.CoinType,
				acct.Account, pub)

		case PurposeKeyFamily:
			family := keychain.KeyFamily(acct.Account)
			key := acct.Key
			switch {
			case minimal && slices.Contains(auth, family):
			case minimal && !slices.Contains(funds, family):
				continue

			default:
				pub, err := independentPublic(acct.Key)
				if err != nil {
					return nil, err
				}
				key = pub
			}

			entry = fmt.Sprintf("[%s/%dh/%dh/%dh]%s/0/*", origin,
				acct.Purpose, acct.CoinType, acct.Account, key)

		default:
			continue
		}

		withChecksum, err := AddChecksum(entry)
		if err != nil {
			return nil, err
		}
		lines = append(lines, withChecksum)
	}

	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
