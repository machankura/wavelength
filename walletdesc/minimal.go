package walletdesc

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/keychain"
)

// ErrMinimalBundleFamilies is returned when a minimal bundle does not carry
// exactly the families it must: every fund family as a public key and
// every authentication family as a private key, and nothing else.
var ErrMinimalBundleFamilies = errors.New("minimal bundle families are wrong")

// MinimalBundle is a split-signing bundle: the on-chain account and the
// fund families as public keys, whose private keys stay on the remote
// signer, and the authentication families as private keys the daemon keeps.
// The families Wavelength does not use are absent; WithPlaceholders fills
// them in for import. It is secret because of Local: callers must call Zero.
type MinimalBundle struct {
	// Public holds the on-chain accounts and the fund families.
	Public *WatchOnlyBundle

	// Local holds the authentication families' private keys.
	Local *AccountKeys
}

// Supplied returns the key families the bundle carries, remote and local,
// in ascending order.
func (m *MinimalBundle) Supplied() []keychain.KeyFamily {
	var families []keychain.KeyFamily
	for _, acct := range m.Public.Accounts {
		if acct.Purpose == PurposeKeyFamily {
			families = append(
				families, keychain.KeyFamily(acct.Account),
			)
		}
	}
	for _, acct := range m.Local.Accounts {
		families = append(families, keychain.KeyFamily(acct.Account))
	}
	slices.Sort(families)

	return families
}

// PlaceholderAccountKey returns a public key for account 0 of the given
// purpose and coin type, derived from a random key that is discarded before
// returning. No private key exists for it anywhere, so a wallet must never
// hand out an address from it.
func PlaceholderAccountKey(purpose, coin uint32,
	params *chaincfg.Params) (*hdkeychain.ExtendedKey, error) {

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, err
	}
	root, err := hdkeychain.NewMaster(seed, params)
	clear(seed)
	if err != nil {
		return nil, err
	}
	defer root.Zero()

	key, err := deriveHardened(
		root, []uint32{hardened(purpose), hardened(coin), hardened(0)},
		false,
	)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	return independentPublic(key)
}

// WithPlaceholders returns the complete watch-only bundle to import: the
// supplied accounts, the local families' public halves, and a placeholder
// public key for every other family from 0 to 255, so btcwallet finds every
// account it provisions. Placeholders derive from a random key that is
// discarded before returning, so no private key exists for them anywhere;
// a wallet must therefore never derive from one.
func (m *MinimalBundle) WithPlaceholders(params *chaincfg.Params) (
	*WatchOnlyBundle, error) {

	full := &WatchOnlyBundle{MasterFingerprint: m.Public.MasterFingerprint}
	full.Accounts = append(full.Accounts, m.Public.Accounts...)

	local, err := m.Local.Bundle()
	if err != nil {
		return nil, err
	}
	full.Accounts = append(full.Accounts, local.Accounts...)

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, err
	}
	root, err := hdkeychain.NewMaster(seed, params)
	clear(seed)
	if err != nil {
		return nil, err
	}
	defer root.Zero()

	coin := coinTypeForNet(params)
	coinKey, err := deriveHardened(
		root, []uint32{hardened(PurposeKeyFamily), hardened(coin)},
		false,
	)
	if err != nil {
		return nil, err
	}
	defer coinKey.Zero()

	supplied := m.Supplied()
	for family := uint32(0); family <=
		uint32(keyfamily.MaxFamily); family++ {

		if slices.Contains(supplied, keychain.KeyFamily(family)) {
			continue
		}

		key, err := coinKey.Derive(hardened(family))
		if err != nil {
			return nil, err
		}
		pub, err := independentPublic(key)
		key.Zero()
		if err != nil {
			return nil, err
		}

		full.Accounts = append(full.Accounts, WatchOnlyAccount{
			Purpose:  PurposeKeyFamily,
			CoinType: coin,
			Account:  family,
			Key:      pub,
		})
	}

	slices.SortFunc(full.Accounts, func(a, b WatchOnlyAccount) int {
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}

		return int(a.Account) - int(b.Account)
	})

	return full, nil
}

// Zero wipes the local private keys.
func (m *MinimalBundle) Zero() {
	m.Local.Zero()
}

// String returns a summary that is safe to log.
func (m *MinimalBundle) String() string {
	return fmt.Sprintf("MinimalBundle(fingerprint=%08x, families=%v)",
		m.Public.MasterFingerprint, m.Supplied())
}

// LogValue implements slog.LogValuer without exposing key material.
func (m *MinimalBundle) LogValue() slog.Value {
	return slog.StringValue(m.String())
}

// ParseBundle parses a watch-only bundle that may be minimal. A bundle
// whose entries are all public keys is a full bundle, validated by
// ParseWatchOnlyBundle's rules, and comes back as the first result. A text
// bundle with private key entries is a minimal bundle and comes back as the
// second: it must carry the BIP86 on-chain account and every fund family
// as public keys, every authentication family as a private key, and no
// other family. lnd's account list JSON cannot carry private keys, so it is
// always a full bundle.
func ParseBundle(data []byte, params *chaincfg.Params) (*WatchOnlyBundle,
	*MinimalBundle, error) {

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] == '{' {
		full, err := ParseWatchOnlyBundle(data, params)

		return full, nil, err
	}

	entries, err := parseBundleLines(string(trimmed))
	if err != nil {
		return nil, nil, err
	}

	if !slices.ContainsFunc(entries, func(e bundleEntry) bool {
		return e.key.IsPrivate()
	}) {

		full, err := validateBundle(entries, params)

		return full, nil, err
	}

	minimal, err := validateMinimalBundle(entries, params)
	if err != nil {
		for _, entry := range entries {
			entry.key.Zero()
		}

		return nil, nil, err
	}

	return nil, minimal, nil
}

// validateMinimalBundle checks a minimal bundle's entries and splits them
// into the public and local halves.
func validateMinimalBundle(entries []bundleEntry,
	params *chaincfg.Params) (*MinimalBundle, error) {

	funds := keyfamily.Families(keyfamily.Funds)
	auth := keyfamily.Families(keyfamily.Auth)

	var (
		publics  []bundleEntry
		privates []accountKeyEntry
	)
	for _, entry := range entries {
		if len(entry.path) != 3 {
			return nil, fmt.Errorf("%w: account path must have "+
				"three steps", ErrBundleAccountPath)
		}

		purpose := entry.path[0] - hdkeychain.HardenedKeyStart
		family := keychain.KeyFamily(
			entry.path[2] - hdkeychain.HardenedKeyStart,
		)

		switch {
		case entry.key.IsPrivate():
			if purpose != PurposeKeyFamily ||
				!slices.Contains(auth, family) {
				return nil, fmt.Errorf("%w: only the "+
					"authentication families %v may be "+
					"private keys",
					ErrMinimalBundleFamilies, auth)
			}
			privates = append(privates, accountKeyEntry{
				path:        entry.path,
				key:         entry.key,
				fingerprint: entry.fingerprint,
			})

		case purpose == PurposeKeyFamily &&
			!slices.Contains(funds, family):
			return nil, fmt.Errorf("%w: family %d must not be in "+
				"a minimal bundle as a public key; only the "+
				"fund families %v are",
				ErrMinimalBundleFamilies, family, funds)

		default:
			publics = append(publics, entry)
		}
	}

	// Each half goes through the account checks of a full bundle: path,
	// depth, child index, network and coin type.
	public := &WatchOnlyBundle{}
	seen := make(map[[2]uint32]bool)
	for _, entry := range publics {
		acct, err := bundleAccount(entry, params)
		if err != nil {
			return nil, err
		}

		id := [2]uint32{acct.Purpose, acct.Account}
		if seen[id] {
			return nil, fmt.Errorf("%w: %d'/%d'/%d'",
				ErrBundleDuplicate, acct.Purpose, acct.CoinType,
				acct.Account)
		}
		seen[id] = true
		public.Accounts = append(public.Accounts, acct)
	}

	local := &AccountKeys{}
	for _, entry := range privates {
		if err := checkPrivateKey(entry.key, params); err != nil {
			return nil, err
		}
		pub, err := independentPublic(entry.key)
		if err != nil {
			return nil, err
		}
		acct, err := bundleAccount(bundleEntry{
			path: entry.path, key: pub,
		}, params)
		if err != nil {
			return nil, err
		}

		id := [2]uint32{acct.Purpose, acct.Account}
		if seen[id] {
			return nil, fmt.Errorf("%w: %d'/%d'/%d'",
				ErrBundleDuplicate, acct.Purpose, acct.CoinType,
				acct.Account)
		}
		seen[id] = true
		local.Accounts = append(local.Accounts, AccountKey{
			Purpose:  acct.Purpose,
			CoinType: acct.CoinType,
			Account:  acct.Account,
			Key:      entry.key,
		})
	}

	// Every fund and authentication family, and the BIP86 account, must
	// be present, and every entry must name the same master key.
	for _, family := range funds {
		if !seen[[2]uint32{PurposeKeyFamily, uint32(family)}] {
			return nil, fmt.Errorf("%w: fund family %d is missing",
				ErrMinimalBundleFamilies, family)
		}
	}
	for _, family := range auth {
		if !seen[[2]uint32{PurposeKeyFamily, uint32(family)}] {
			return nil, fmt.Errorf("%w: authentication family %d "+
				"is missing", ErrMinimalBundleFamilies, family)
		}
	}
	if !seen[[2]uint32{ScriptTaproot.Purpose(), 0}] {
		return nil, fmt.Errorf("%w: no BIP86 account 86'/0'/0'",
			ErrBundleIncomplete)
	}

	var (
		fingerprint    uint32
		hasFingerprint bool
	)
	for _, entry := range entries {
		if !entry.hasFingerprint {
			continue
		}
		if hasFingerprint && entry.fingerprint != fingerprint {
			return nil, ErrMixedFingerprints
		}
		fingerprint = entry.fingerprint
		hasFingerprint = true
	}
	public.MasterFingerprint = fingerprint
	local.MasterFingerprint = fingerprint

	sortAccounts := func(a, b WatchOnlyAccount) int {
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}

		return int(a.Account) - int(b.Account)
	}
	slices.SortFunc(public.Accounts, sortAccounts)
	slices.SortFunc(local.Accounts, func(a, b AccountKey) int {
		return int(a.Account) - int(b.Account)
	})

	return &MinimalBundle{Public: public, Local: local}, nil
}
