package walletdesc

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
)

var (
	// ErrAccountKeyPublic is returned for an account key entry that
	// carries a public key. Public keys alone go in a watch-only bundle,
	// which needs a remote signer.
	ErrAccountKeyPublic = errors.New("account key entries must be " +
		"private keys; public keys belong in a watch-only bundle " +
		"used with a remote signer")

	// ErrMixedFamilyKeys is returned when account keys give the key
	// families both as one coin-level key and as per-family keys.
	ErrMixedFamilyKeys = errors.New("give the key families either as one " +
		"coin-level key or as one key per family, not both")
)

// AccountKey is one account-level private key.
type AccountKey struct {
	// Purpose, CoinType and Account locate the key at
	// purpose'/coin'/account', as in WatchOnlyAccount.
	Purpose  uint32
	CoinType uint32
	Account  uint32

	// Key is the account private key, with the network's standard
	// private version bytes.
	Key *hdkeychain.ExtendedKey
}

// AccountKeys is a validated set of account-level private keys: the
// on-chain accounts plus every key family 0 to 255. It can sign everything
// a wallet built from the master key can, without the master key itself.
// It is secret: callers must call Zero when done and never log a key.
type AccountKeys struct {
	// MasterFingerprint is the master key fingerprint the entries name.
	MasterFingerprint uint32

	// Accounts are in import order, as in WatchOnlyBundle.
	Accounts []AccountKey
}

// Account returns the private key for purpose and account.
func (k *AccountKeys) Account(purpose, account uint32) (AccountKey, bool) {
	for _, acct := range k.Accounts {
		if acct.Purpose == purpose && acct.Account == account {
			return acct, true
		}
	}

	return AccountKey{}, false
}

// Bundle returns the watch-only bundle of the keys' public halves, as
// independent values that survive Zero.
func (k *AccountKeys) Bundle() (*WatchOnlyBundle, error) {
	bundle := &WatchOnlyBundle{MasterFingerprint: k.MasterFingerprint}
	for _, acct := range k.Accounts {
		pub, err := independentPublic(acct.Key)
		if err != nil {
			return nil, err
		}

		bundle.Accounts = append(bundle.Accounts, WatchOnlyAccount{
			Purpose:  acct.Purpose,
			CoinType: acct.CoinType,
			Account:  acct.Account,
			Key:      pub,
		})
	}

	return bundle, nil
}

// Zero wipes every private key.
func (k *AccountKeys) Zero() {
	for _, acct := range k.Accounts {
		acct.Key.Zero()
	}
}

// String returns a summary that is safe to log.
func (k *AccountKeys) String() string {
	return fmt.Sprintf("AccountKeys(fingerprint=%08x, accounts=%d)",
		k.MasterFingerprint, len(k.Accounts))
}

// LogValue implements slog.LogValuer without exposing key material.
func (k *AccountKeys) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String(
			"fingerprint", FormatFingerprint(
				k.MasterFingerprint,
			),
		),
		slog.Int("accounts", len(k.Accounts)),
	)
}

// accountKeyEntry is a parsed private entry before set validation.
type accountKeyEntry struct {
	path        []uint32
	key         *hdkeychain.ExtendedKey
	fingerprint uint32
}

// HasAccountKeys reports whether texts are account-level keys rather than
// master-key descriptors: some entry is a bare key expression, which a
// master-key descriptor set never contains, or carries a key origin at
// least two steps below the master key. It does not validate anything else,
// so callers still get the full error from the parser they then pick.
func HasAccountKeys(texts []string) bool {
	for _, text := range texts {
		text = strings.TrimSpace(text)
		if strings.HasPrefix(text, "[") {
			return true
		}

		raw, err := parseDescriptor(text)
		if err != nil {
			continue
		}
		raw.key.key.Zero()
		if raw.key.hasOrigin && len(raw.key.originPath) >= 2 {
			return true
		}
	}

	return false
}

// ParseAccountKeys parses account-level private keys for params. Each text
// is one of:
//
//   - tr([fp/86h/0h/0h]XPRV/<0;1>/*) or wpkh([fp/84h/0h/0h]XPRV/<0;1>/*): an
//     on-chain account private key, as other wallets export it;
//   - [fp/1017h/COINh]XPRV: the key family coin-level key, from which every
//     family is derived;
//   - [fp/1017h/COINh/FAMILYh]XPRV/0/*: one family's private key.
//
// The families come either from one coin-level key or as keys for every
// family 0 to 255, and the BIP86 account is required, exactly as for a
// watch-only bundle. The supplied keys are used as given, with standard
// BIP32 below them; see expandCoinLevel for how that compares with a seed
// wallet. Entries may carry a BIP380 checksum.
// Errors never include key material. The caller must call Zero.
func ParseAccountKeys(texts []string,
	params *chaincfg.Params) (*AccountKeys, error) {

	if len(texts) == 0 {
		return nil, ErrNoDescriptors
	}
	if len(texts) > MaxBundleAccounts {
		return nil, fmt.Errorf("%w: got %d, at most %d",
			ErrTooManyDescriptors, len(texts), MaxBundleAccounts)
	}

	var entries []accountKeyEntry
	zeroEntries := func() {
		for _, entry := range entries {
			entry.key.Zero()
		}
	}

	var coinLevel *accountKeyEntry
	for i, text := range texts {
		entry, err := parseAccountKeyLine(strings.TrimSpace(text))
		if err != nil {
			zeroEntries()

			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}

		if len(entry.path) == 2 {
			if coinLevel != nil {
				entry.key.Zero()
				zeroEntries()

				return nil, fmt.Errorf("entry %d: %w: two "+
					"coin-level keys", i+1,
					ErrBundleDuplicate)
			}
			coinLevel = entry

			continue
		}
		entries = append(entries, *entry)
	}

	if coinLevel != nil {
		for _, entry := range entries {
			if entry.path[0] == hardened(PurposeKeyFamily) {
				coinLevel.key.Zero()
				zeroEntries()

				return nil, ErrMixedFamilyKeys
			}
		}

		families, err := expandCoinLevel(*coinLevel, params)
		coinLevel.key.Zero()
		if err != nil {
			zeroEntries()

			return nil, err
		}
		entries = append(entries, families...)
	}

	keys, err := validateAccountKeys(entries, params)
	if err != nil {
		zeroEntries()

		return nil, err
	}

	return keys, nil
}

// parseAccountKeyLine parses one private entry. Coin-level entries come
// back with a two-step path.
func parseAccountKeyLine(line string) (*accountKeyEntry, error) {
	var (
		expr    keyExpr
		onChain bool
	)
	if strings.HasPrefix(line, "[") {
		body, err := splitChecksum(line)
		if err != nil {
			return nil, err
		}

		parsed, err := parseKeyExpr(body)
		if err != nil {
			return nil, err
		}
		expr = *parsed
	} else {
		desc, err := parseDescriptor(line)
		if err != nil {
			return nil, err
		}
		expr = desc.key
		onChain = true
	}

	if !expr.key.IsPrivate() {
		expr.key.Zero()

		return nil, ErrAccountKeyPublic
	}

	refuse := func(err error) (*accountKeyEntry, error) {
		expr.key.Zero()

		return nil, err
	}

	if !expr.hasOrigin {
		return refuse(
			fmt.Errorf("%w: entry needs a "+
				"[fingerprint/purpose'/coin'/account'] origin",
				ErrBundleAccountPath),
		)
	}

	switch {
	case onChain:
		if len(expr.originPath) != 3 {
			return refuse(
				fmt.Errorf("%w: account descriptor origin "+
					"must be purpose'/coin'/account'",
					ErrBundleAccountPath),
			)
		}
		if !isBranchWildcard(expr.path, true) {
			return refuse(
				fmt.Errorf("%w: account descriptor must end "+
					"in /<0;1>/*, /0/* or /1/*",
					ErrUnsupportedPath),
			)
		}

	case len(expr.originPath) == 2:
		if expr.originPath[0] != hardened(PurposeKeyFamily) {
			return refuse(
				fmt.Errorf("%w: a coin-level key must be at "+
					"1017'/coin'", ErrUnsupportedPath),
			)
		}
		if len(expr.path) != 0 {
			return refuse(
				fmt.Errorf("%w: a coin-level key takes no "+
					"derivation suffix",
					ErrUnsupportedPath),
			)
		}

	case len(expr.originPath) == 3:
		if !isBranchWildcard(expr.path, false) {
			return refuse(
				fmt.Errorf("%w: key family entry must "+
					"end in /0/*", ErrUnsupportedPath),
			)
		}

	default:
		return refuse(
			fmt.Errorf("%w: origin path must have two or "+
				"three steps", ErrBundleAccountPath),
		)
	}

	return &accountKeyEntry{
		path:        expr.originPath,
		key:         expr.key,
		fingerprint: expr.originFingerprint,
	}, nil
}

// expandCoinLevel derives every family 0 to 255 from a coin-level key.
func expandCoinLevel(coin accountKeyEntry,
	params *chaincfg.Params) ([]accountKeyEntry, error) {

	if err := checkPrivateKey(coin.key, params); err != nil {
		return nil, err
	}
	if coin.key.Depth() != 2 || coin.key.ChildIndex() != coin.path[1] {
		return nil, fmt.Errorf("%w: coin-level key is not the key at "+
			"its stated path", ErrBundleAccountPath)
	}

	// Families are derived with standard BIP32. A seed wallet built by
	// btcwallet agrees on every family except one case: when this key's
	// private scalar has a leading zero byte, btcwallet derives family 0
	// from an unpadded in-memory copy and gets a different key.
	// Wavelength never derives from family 0, so that case is accepted
	// (walletcore's TestLegacyDerivationFamilyScope pins the behaviour).
	var families []accountKeyEntry
	for family := uint32(0); family <=
		uint32(keyfamily.MaxFamily); family++ {

		key, err := coin.key.Derive(hardened(family))
		if err != nil {
			for _, entry := range families {
				entry.key.Zero()
			}

			return nil, err
		}

		families = append(families, accountKeyEntry{
			path: []uint32{
				coin.path[0], coin.path[1], hardened(family),
			},
			key:         key,
			fingerprint: coin.fingerprint,
		})
	}

	return families, nil
}

// validateAccountKeys checks each private key against its path and the
// network, then validates the public halves as a watch-only bundle so both
// imports follow one set of completeness and numbering rules.
func validateAccountKeys(entries []accountKeyEntry,
	params *chaincfg.Params) (*AccountKeys, error) {

	publics := make([]bundleEntry, 0, len(entries))
	for _, entry := range entries {
		if err := checkPrivateKey(entry.key, params); err != nil {
			return nil, err
		}

		pub, err := independentPublic(entry.key)
		if err != nil {
			return nil, err
		}
		publics = append(publics, bundleEntry{
			path:           entry.path,
			key:            pub,
			fingerprint:    entry.fingerprint,
			hasFingerprint: true,
		})
	}

	bundle, err := validateBundle(publics, params)
	if err != nil {
		return nil, err
	}

	keys := &AccountKeys{MasterFingerprint: bundle.MasterFingerprint}
	for _, acct := range bundle.Accounts {
		idx := slices.IndexFunc(entries, func(e accountKeyEntry) bool {
			return e.path[0] == hardened(acct.Purpose) &&
				e.path[2] == hardened(acct.Account)
		})
		keys.Accounts = append(keys.Accounts, AccountKey{
			Purpose:  acct.Purpose,
			CoinType: acct.CoinType,
			Account:  acct.Account,
			Key:      entries[idx].key,
		})
	}

	return keys, nil
}

// checkPrivateKey refuses a private key for another network. SLIP-132
// private versions are not accepted: account private keys are exported in
// the standard xprv or tprv form.
func checkPrivateKey(key *hdkeychain.ExtendedKey,
	params *chaincfg.Params) error {

	var version [4]byte
	copy(version[:], key.Version())
	if version != params.HDPrivateKeyID {
		return ErrNetworkMismatch
	}

	return nil
}

// hardened returns index as a hardened child index.
func hardened(index uint32) uint32 {
	return index + hdkeychain.HardenedKeyStart
}
