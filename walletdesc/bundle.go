package walletdesc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
)

const (
	// PurposeKeyFamily is the BIP43 purpose of lnd's key family scope,
	// m/1017'/coin'/family'.
	PurposeKeyFamily uint32 = 1017

	// PurposeNestedWitness is the BIP49 purpose, which btcwallet keeps
	// as a scope but Wavelength never spends from.
	PurposeNestedWitness uint32 = 49

	// MaxBundleAccounts bounds how many accounts one bundle may carry:
	// 256 key families plus the on-chain scopes, with slack.
	MaxBundleAccounts = 300
)

var (
	// ErrMalformedBundle is returned for bundle text that is neither
	// lnd account JSON nor one entry per line.
	ErrMalformedBundle = errors.New("malformed watch-only bundle")

	// ErrBundlePrivateKey is returned for a bundle entry that carries a
	// private key. Split signing with local authentication keys needs
	// the encrypted keystore of the account-level key milestone.
	ErrBundlePrivateKey = errors.New("watch-only bundle entries must be " +
		"public keys")

	// ErrBundleAccountPath is returned for an account whose path,
	// depth or child index does not match the account it claims to be.
	ErrBundleAccountPath = errors.New("watch-only bundle account path " +
		"mismatch")

	// ErrBundleIncomplete is returned when a bundle lacks an account
	// the wallet needs: the BIP86 on-chain account, or any key family
	// from 0 to 255.
	ErrBundleIncomplete = errors.New("watch-only bundle is incomplete")

	// ErrBundleDuplicate is returned when two entries describe the same
	// account.
	ErrBundleDuplicate = errors.New("watch-only bundle has a duplicate " +
		"account")

	// ErrMixedFingerprints is returned when bundle entries name
	// different master key fingerprints.
	ErrMixedFingerprints = errors.New("watch-only bundle entries use " +
		"different master keys")
)

// slip132Versions maps the SLIP-132 public version bytes btcwallet and lnd
// use for BIP49 and BIP84 account keys to whether they belong to a test
// network. Keys with these versions are accepted and normalized to the
// network's standard xpub or tpub.
var slip132Versions = map[[4]byte]bool{
	{0x04, 0x9d, 0x7c, 0xb2}: false, // ypub
	{0x04, 0xb2, 0x47, 0x46}: false, // zpub
	{0x04, 0x4a, 0x52, 0x62}: true,  // upub
	{0x04, 0x5f, 0x1c, 0xf6}: true,  // vpub
}

// WatchOnlyAccount is one account-level public key of a watch-only bundle.
type WatchOnlyAccount struct {
	// Purpose is the BIP43 purpose: 86, 84 or 49 for on-chain accounts,
	// PurposeKeyFamily for key families.
	Purpose uint32

	// CoinType is the coin type: 0 for on-chain accounts on every
	// network, the network's coin type for key families.
	CoinType uint32

	// Account is the account index, which for key families is the
	// family number.
	Account uint32

	// Key is the account public key at purpose'/coin'/account', with the
	// network's standard public version bytes.
	Key *hdkeychain.ExtendedKey
}

// WatchOnlyBundle is a validated set of account public keys from which a
// watch-only wallet can be built. It holds no private key material.
type WatchOnlyBundle struct {
	// MasterFingerprint is the master key fingerprint the entries name,
	// or zero when none named one.
	MasterFingerprint uint32

	// Accounts are sorted by purpose then account, which is the order
	// they must be imported in: btcwallet numbers an imported account
	// one past the last account of its scope, whatever the key's own
	// child index.
	Accounts []WatchOnlyAccount
}

// Account returns the bundle account for purpose and account.
func (b *WatchOnlyBundle) Account(purpose, account uint32) (WatchOnlyAccount,
	bool) {

	for _, acct := range b.Accounts {
		if acct.Purpose == purpose && acct.Account == account {
			return acct, true
		}
	}

	return WatchOnlyAccount{}, false
}

// IdentityKey returns the daemon identity public key the bundle implies:
// index 0 of the identity family.
func (b *WatchOnlyBundle) IdentityKey() (*hdkeychain.ExtendedKey, error) {
	acct, ok := b.Account(PurposeKeyFamily, uint32(keyfamily.Identity))
	if !ok {
		return nil, fmt.Errorf("%w: no identity family",
			ErrBundleIncomplete)
	}

	branch, err := acct.Key.Derive(0)
	if err != nil {
		return nil, err
	}

	return branch.Derive(0)
}

// String returns a summary that is safe to log.
func (b *WatchOnlyBundle) String() string {
	return fmt.Sprintf("WatchOnlyBundle(fingerprint=%08x, accounts=%d)",
		b.MasterFingerprint, len(b.Accounts))
}

// LogValue implements slog.LogValuer.
func (b *WatchOnlyBundle) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String(
			"fingerprint", FormatFingerprint(
				b.MasterFingerprint,
			),
		),
		slog.Int("accounts", len(b.Accounts)),
	)
}

// FormatFingerprint renders a master key fingerprint as eight hex
// characters, the form used in descriptor key origins.
func FormatFingerprint(fp uint32) string {
	return fmt.Sprintf("%08x", fp)
}

// bundleEntry is an account before bundle-level validation.
type bundleEntry struct {
	path           []uint32
	key            *hdkeychain.ExtendedKey
	fingerprint    uint32
	hasFingerprint bool
}

// ParseWatchOnlyBundle parses and validates a watch-only bundle for params.
// It accepts two forms: the JSON lnd prints for `lncli wallet accounts list`
// (WalletKit.ListAccounts), and text with one entry per line, where an
// entry is a tr() or wpkh() account descriptor for the on-chain accounts or
// a [fingerprint/1017h/coinh/familyh]KEY/0/* key expression for a key
// family. Text lines may carry a BIP380 checksum; empty lines and lines
// starting with "//" are ignored.
//
// The bundle must cover the BIP86 on-chain account 0 and every key family
// from 0 to 255, because the wallet pre-provisions all of them and cannot
// create a missing one without the master private key.
func ParseWatchOnlyBundle(data []byte,
	params *chaincfg.Params) (*WatchOnlyBundle, error) {

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrMalformedBundle)
	}

	var (
		entries []bundleEntry
		err     error
	)
	if trimmed[0] == '{' {
		entries, err = parseLndAccounts(trimmed)
	} else {
		entries, err = parseBundleLines(string(trimmed))
	}
	if err != nil {
		return nil, err
	}

	return validateBundle(entries, params)
}

// lndAccountList mirrors walletrpc.ListAccountsResponse as lncli prints it.
type lndAccountList struct {
	Accounts []struct {
		Name                 string `json:"name"`
		ExtendedPublicKey    string `json:"extended_public_key"`
		MasterKeyFingerprint string `json:"master_key_fingerprint"`
		DerivationPath       string `json:"derivation_path"`
	} `json:"accounts"`
}

// parseLndAccounts parses lnd's account list JSON. Each scope's imported
// pseudo-account has no key or path and is skipped.
func parseLndAccounts(data []byte) ([]bundleEntry, error) {
	var list lndAccountList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%w: account JSON: %w",
			ErrMalformedBundle, err)
	}

	var entries []bundleEntry
	for i, acct := range list.Accounts {
		if acct.ExtendedPublicKey == "" && acct.DerivationPath == "" {
			continue
		}

		path, err := parseLndPath(acct.DerivationPath)
		if err != nil {
			return nil, fmt.Errorf("account %d: %w", i, err)
		}

		key, err := parseExtendedKey(acct.ExtendedPublicKey)
		if err != nil {
			return nil, fmt.Errorf("account %d: %w", i, err)
		}

		entry := bundleEntry{path: path, key: key}
		if acct.MasterKeyFingerprint != "" {
			entry.fingerprint, err = parseJSONFingerprint(
				acct.MasterKeyFingerprint,
			)
			if err != nil {
				return nil, fmt.Errorf("account %d: %w", i, err)
			}
			entry.hasFingerprint = true
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLndPath parses lnd's m/purpose'/coin'/account' path into hardened
// indexes.
func parseLndPath(text string) ([]uint32, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(text), "m/")
	if !ok {
		return nil, fmt.Errorf("%w: derivation path must start with m/",
			ErrMalformedBundle)
	}

	var path []uint32
	for _, part := range strings.Split(rest, "/") {
		index, err := parseIndex(part)
		if err != nil {
			return nil, err
		}
		path = append(path, index)
	}

	return path, nil
}

// parseJSONFingerprint decodes a four-byte fingerprint, which lncli prints
// as hex and protojson as base64, big-endian as in key origins.
func parseJSONFingerprint(text string) (uint32, error) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 4 {
		raw, err = base64.StdEncoding.DecodeString(text)
	}
	if err != nil || len(raw) != 4 {
		return 0, fmt.Errorf("%w: master key fingerprint must be "+
			"four bytes", ErrMalformedBundle)
	}

	return uint32(raw[0])<<24 | uint32(raw[1])<<16 |
		uint32(raw[2])<<8 | uint32(raw[3]), nil
}

// parseBundleLines parses the one-entry-per-line text form.
func parseBundleLines(text string) ([]bundleEntry, error) {
	var entries []bundleEntry
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		entry, err := parseBundleLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		entries = append(entries, *entry)
	}

	return entries, nil
}

// parseBundleLine parses one text entry: an account descriptor or a key
// family key expression.
func parseBundleLine(line string) (*bundleEntry, error) {
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

	if !expr.hasOrigin || len(expr.originPath) != 3 {
		return nil, fmt.Errorf("%w: entry needs a "+
			"[fingerprint/purpose'/coin'/account'] origin",
			ErrBundleAccountPath)
	}

	// The suffix must be the derivation the wallet performs below the
	// account: receive and change for on-chain accounts, the external
	// branch only for key families, whose keys are never change.
	switch {
	case onChain && !isBranchWildcard(expr.path, true):
		return nil, fmt.Errorf("%w: account descriptor must end in "+
			"/<0;1>/*, /0/* or /1/*", ErrUnsupportedPath)

	case !onChain && !isBranchWildcard(expr.path, false):
		return nil, fmt.Errorf("%w: key family entry must end in /0/*",
			ErrUnsupportedPath)
	}

	return &bundleEntry{
		path:           expr.originPath,
		key:            expr.key,
		fingerprint:    expr.originFingerprint,
		hasFingerprint: true,
	}, nil
}

// isBranchWildcard reports whether path is BRANCH/*, where BRANCH is 0 or,
// when allowChange is set, 1 or <0;1>.
func isBranchWildcard(path []pathStep, allowChange bool) bool {
	if len(path) != 2 || !path[1].wildcard || path[0].wildcard {
		return false
	}

	values := slices.Clone(path[0].values)
	slices.Sort(values)
	switch {
	case slices.Equal(values, []uint32{0}):
		return true

	case allowChange && (slices.Equal(values, []uint32{1}) ||
		slices.Equal(values, []uint32{0, 1})):
		return true

	default:
		return false
	}
}

// validateBundle checks the entries against params and the accounts a
// watch-only wallet needs, and returns them in import order.
func validateBundle(entries []bundleEntry,
	params *chaincfg.Params) (*WatchOnlyBundle, error) {

	if len(entries) > MaxBundleAccounts {
		return nil, fmt.Errorf("%w: %d accounts, at most %d",
			ErrMalformedBundle, len(entries), MaxBundleAccounts)
	}

	bundle := &WatchOnlyBundle{}
	hasFingerprint := false
	seen := make(map[[2]uint32]bool)
	for _, entry := range entries {
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

		if entry.hasFingerprint {
			if hasFingerprint &&
				entry.fingerprint != bundle.MasterFingerprint {
				return nil, ErrMixedFingerprints
			}
			bundle.MasterFingerprint = entry.fingerprint
			hasFingerprint = true
		}

		bundle.Accounts = append(bundle.Accounts, acct)
	}

	slices.SortFunc(bundle.Accounts, func(a, b WatchOnlyAccount) int {
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}

		return int(a.Account) - int(b.Account)
	})

	// btcwallet numbers imported accounts contiguously from zero, so a
	// gap in any scope would shift every later account onto the wrong
	// number.
	next := make(map[uint32]uint32)
	for _, acct := range bundle.Accounts {
		if acct.Account != next[acct.Purpose] {
			return nil, fmt.Errorf("%w: purpose %d' skips "+
				"account %d'", ErrBundleIncomplete,
				acct.Purpose, next[acct.Purpose])
		}
		next[acct.Purpose]++
	}

	if next[ScriptTaproot.Purpose()] == 0 {
		return nil, fmt.Errorf("%w: no BIP86 account 86'/0'/0'",
			ErrBundleIncomplete)
	}
	if next[PurposeKeyFamily] != uint32(keyfamily.MaxFamily)+1 {
		return nil, fmt.Errorf("%w: key families 0 to %d are "+
			"required, got %d", ErrBundleIncomplete,
			keyfamily.MaxFamily, next[PurposeKeyFamily])
	}

	return bundle, nil
}

// bundleAccount validates one entry's path and key for params.
func bundleAccount(entry bundleEntry,
	params *chaincfg.Params) (WatchOnlyAccount, error) {

	if len(entry.path) != 3 {
		return WatchOnlyAccount{}, fmt.Errorf("%w: account path must "+
			"have three steps", ErrBundleAccountPath)
	}
	for _, step := range entry.path {
		if step < hdkeychain.HardenedKeyStart {
			return WatchOnlyAccount{}, fmt.Errorf("%w: account "+
				"path steps must be hardened",
				ErrBundleAccountPath)
		}
	}

	acct := WatchOnlyAccount{
		Purpose:  entry.path[0] - hdkeychain.HardenedKeyStart,
		CoinType: entry.path[1] - hdkeychain.HardenedKeyStart,
		Account:  entry.path[2] - hdkeychain.HardenedKeyStart,
	}
	name := strconv.Itoa(int(acct.Purpose)) + "'/" +
		strconv.Itoa(int(acct.CoinType)) + "'/" +
		strconv.Itoa(int(acct.Account)) + "'"

	switch acct.Purpose {
	case ScriptTaproot.Purpose(), ScriptWitnessPubKeyHash.Purpose(),
		PurposeNestedWitness:

		// btcwallet's on-chain scopes use coin type 0 everywhere and
		// Wavelength only spends from account 0.
		if acct.CoinType != 0 || acct.Account != 0 {
			return WatchOnlyAccount{}, fmt.Errorf("%w: on-chain "+
				"account %s must be %d'/0'/0'",
				ErrUnsupportedPath, name, acct.Purpose)
		}

	case PurposeKeyFamily:
		if acct.CoinType != coinTypeForNet(params) {
			return WatchOnlyAccount{}, fmt.Errorf("%w: key family "+
				"account %s has coin type %d', want %d'",
				ErrNetworkMismatch, name, acct.CoinType,
				coinTypeForNet(params))
		}
		if acct.Account > uint32(keyfamily.MaxFamily) {
			return WatchOnlyAccount{}, fmt.Errorf("%w: key family "+
				"%d is above %d", ErrUnsupportedPath,
				acct.Account, keyfamily.MaxFamily)
		}

	default:
		return WatchOnlyAccount{}, fmt.Errorf("%w: purpose %d' is not "+
			"used by the wallet", ErrUnsupportedPath, acct.Purpose)
	}

	key, err := normalizeAccountKey(entry.key, params)
	if err != nil {
		return WatchOnlyAccount{}, fmt.Errorf("account %s: %w", name,
			err)
	}
	if key.Depth() != 3 || key.ChildIndex() != entry.path[2] {
		return WatchOnlyAccount{}, fmt.Errorf("%w: key for %s is not "+
			"that account's key (depth %d, child %d)",
			ErrBundleAccountPath, name, key.Depth(),
			key.ChildIndex())
	}
	acct.Key = key

	return acct, nil
}

// normalizeAccountKey refuses private keys and keys for other networks,
// and returns key with the network's standard public version bytes.
func normalizeAccountKey(key *hdkeychain.ExtendedKey,
	params *chaincfg.Params) (*hdkeychain.ExtendedKey, error) {

	if key.IsPrivate() {
		return nil, ErrBundlePrivateKey
	}

	var version [4]byte
	copy(version[:], key.Version())

	isTestNet := params.HDPublicKeyID !=
		chaincfg.MainNetParams.HDPublicKeyID
	switch slipTest, isSlip := slip132Versions[version]; {
	case version == params.HDPublicKeyID:
	case isSlip && slipTest == isTestNet:
	default:
		return nil, ErrNetworkMismatch
	}

	return StandardAccountPublicKey(key, params)
}

// coinTypeForNet returns lnd's key family coin type for params: 0 on
// mainnet and 1 on every test network. It matches walletcore.CoinTypeForNet,
// which this package cannot import without pulling in btcwallet.
func coinTypeForNet(params *chaincfg.Params) uint32 {
	if params.Net == chaincfg.MainNetParams.Net {
		return 0
	}

	return 1
}
