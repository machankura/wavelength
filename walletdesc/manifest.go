package walletdesc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/keychain"
)

// ManifestVersion is the manifest format this package reads and writes.
const ManifestVersion = 1

var (
	// ErrManifestMalformed is returned for a manifest that is not the
	// expected JSON document.
	ErrManifestMalformed = errors.New("malformed wallet manifest")

	// ErrAuthFamilyOverride is returned when a manifest assigns an
	// authentication family. Those always come from the primary root:
	// they cannot move funds, and family 21 must stay restorable from
	// the primary seed.
	ErrAuthFamilyOverride = errors.New("authentication families cannot " +
		"be overridden")

	// ErrScriptDescriptorSlot is returned for a slot given as a script
	// descriptor. Ark policies hold exactly one user key beside the
	// operator's, and VTXO tree signing assumes one user cosigner.
	ErrScriptDescriptorSlot = errors.New("a fund slot must be a single " +
		"extended public key, not a script descriptor")

	// ErrDuplicateKey is returned when two slots hold the same key or
	// keys from the same account of the same root.
	ErrDuplicateKey = errors.New("two wallet slots share a key")

	// ErrIdentityOverride is returned when a manifest replaces the
	// identity family without the caller allowing it. A new identity
	// changes the wallet's mailbox and its key in every swap.
	ErrIdentityOverride = errors.New("the manifest overrides the " +
		"identity family; this changes the wallet's identity, " +
		"mailbox and swap keys, and must be allowed explicitly on a " +
		"new wallet")

	// ErrManifestIncomplete is returned when a manifest misses a fund
	// slot.
	ErrManifestIncomplete = errors.New("wallet manifest is incomplete")
)

// manifestJSON is the manifest's wire form.
type manifestJSON struct {
	Version            int               `json:"version"`
	Network            string            `json:"network"`
	PrimaryFingerprint string            `json:"primary_fingerprint"`
	OnChain            string            `json:"onchain"`
	Families           map[string]string `json:"families"`
}

// ManifestSlot is one fund slot of a manifest: the key filling it and the
// key's real origin.
type ManifestSlot struct {
	Key    *hdkeychain.ExtendedKey
	Origin KeyOrigin
}

// Manifest assigns each fund slot of a wallet, the on-chain account and
// the fund key families, a key from any source. It is public data, and
// together with every key source it is what restores a wallet whose slots
// do not all come from one root.
type Manifest struct {
	// Network is the network name the manifest was made for.
	Network string

	// PrimaryFingerprint is the root the authentication families and
	// every non-overridden slot come from.
	PrimaryFingerprint uint32

	// OnChain is the BIP86 on-chain account.
	OnChain ManifestSlot

	// Families holds the fund families, keyed by family.
	Families map[keychain.KeyFamily]ManifestSlot

	// canonical is the canonical encoding Hash covers.
	canonical []byte
}

// Hash returns the SHA-256 of the manifest's canonical encoding: sorted
// keys, no insignificant whitespace, normalized entries with checksums.
// Two manifests with the same hash assign the same keys to the same slots.
func (m *Manifest) Hash() [32]byte {
	return sha256.Sum256(m.canonical)
}

// HashHex is Hash as hex.
func (m *Manifest) HashHex() string {
	hash := m.Hash()

	return hex.EncodeToString(hash[:])
}

// Canonical returns the canonical encoding, the form a wallet stores.
func (m *Manifest) Canonical() []byte {
	return slices.Clone(m.canonical)
}

// primarySlot reports whether slot is the primary root's key at the slot's
// own path.
func (m *Manifest) primarySlot(slot ManifestSlot, path []uint32) bool {
	return slot.Origin.Fingerprint == m.PrimaryFingerprint &&
		slices.Equal(slot.Origin.Path, path)
}

// Overrides returns the slots filled from somewhere other than the primary
// root at their own path: "onchain" and family numbers.
func (m *Manifest) Overrides(params *chaincfg.Params) []string {
	var overridden []string
	if !m.primarySlot(m.OnChain, accountPath(86, 0, 0)) {
		overridden = append(overridden, "onchain")
	}

	coin := coinTypeForNet(params)
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		path := accountPath(PurposeKeyFamily, coin, uint32(family))
		if !m.primarySlot(m.Families[family], path) {
			overridden = append(
				overridden,
				strconv.Itoa(
					int(family),
				),
			)
		}
	}

	return overridden
}

// CheckIdentity refuses a manifest that overrides the identity family
// unless allowOverride is set.
func (m *Manifest) CheckIdentity(allowOverride bool,
	params *chaincfg.Params) error {

	if allowOverride || !slices.Contains(
		m.Overrides(params),
		strconv.Itoa(
			int(keyfamily.Identity),
		),
	) {
		return nil
	}

	return ErrIdentityOverride
}

// MinimalBundle combines the manifest with the authentication keys into
// the split-signing bundle a wallet imports, each slot keeping its own
// origin. auth must hold exactly the authentication families from the
// manifest's primary root; the result shares auth's keys.
func (m *Manifest) MinimalBundle(auth *AccountKeys, params *chaincfg.Params) (
	*MinimalBundle, error) {

	if err := checkAuthKeys(
		auth, m.PrimaryFingerprint, params,
	); err != nil {
		return nil, err
	}

	public := &WatchOnlyBundle{MasterFingerprint: m.PrimaryFingerprint}
	onChain := m.OnChain.Origin
	public.Accounts = append(public.Accounts, WatchOnlyAccount{
		Purpose: ScriptTaproot.Purpose(),
		Key:     m.OnChain.Key,
		Origin:  &onChain,
	})

	coin := coinTypeForNet(params)
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		slot := m.Families[family]
		origin := slot.Origin
		public.Accounts = append(public.Accounts, WatchOnlyAccount{
			Purpose:  PurposeKeyFamily,
			CoinType: coin,
			Account:  uint32(family),
			Key:      slot.Key,
			Origin:   &origin,
		})
	}

	return &MinimalBundle{Public: public, Local: auth}, nil
}

// ParseManifest parses and validates a manifest for params. Every fund slot
// must be present, as a single public key with its origin; authentication
// families must be absent; no two slots may share a key or an account of
// one root.
func ParseManifest(data []byte, params *chaincfg.Params) (*Manifest, error) {
	var raw manifestJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifestMalformed, err)
	}

	switch {
	case raw.Version != ManifestVersion:
		return nil, fmt.Errorf("%w: version %d, want %d",
			ErrManifestMalformed, raw.Version, ManifestVersion)

	case !networkMatches(raw.Network, params):
		return nil, fmt.Errorf("%w: manifest is for %q",
			ErrNetworkMismatch, raw.Network)
	}

	primary, err := parseFingerprintHex(raw.PrimaryFingerprint)
	if err != nil {
		return nil, err
	}

	m := &Manifest{
		Network:            raw.Network,
		PrimaryFingerprint: primary,
		Families:           make(map[keychain.KeyFamily]ManifestSlot),
	}

	m.OnChain, err = parseSlot(raw.OnChain, true, params)
	if err != nil {
		return nil, fmt.Errorf("onchain: %w", err)
	}

	funds := keyfamily.Families(keyfamily.Funds)
	auth := keyfamily.Families(keyfamily.Auth)
	for name, text := range raw.Families {
		number, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: family %q",
				ErrManifestMalformed, name)
		}
		family := keychain.KeyFamily(number)

		switch {
		case slices.Contains(auth, family):
			return nil, fmt.Errorf("%w: family %d",
				ErrAuthFamilyOverride, family)

		case !slices.Contains(funds, family):
			return nil, fmt.Errorf("%w: family %d is not a "+
				"fund family", ErrMinimalBundleFamilies, family)
		}

		slot, err := parseSlot(text, false, params)
		if err != nil {
			return nil, fmt.Errorf("family %d: %w", family, err)
		}
		m.Families[family] = slot
	}

	for _, family := range funds {
		if _, ok := m.Families[family]; !ok {
			return nil, fmt.Errorf("%w: fund family %d is missing",
				ErrManifestIncomplete, family)
		}
	}

	if err := m.checkDistinct(); err != nil {
		return nil, err
	}

	m.canonical, err = m.encode()
	if err != nil {
		return nil, err
	}

	return m, nil
}

// checkDistinct refuses two slots with the same key or the same origin.
func (m *Manifest) checkDistinct() error {
	slots := []ManifestSlot{m.OnChain}
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		slots = append(slots, m.Families[family])
	}

	for i := range slots {
		for j := i + 1; j < len(slots); j++ {
			a, b := slots[i], slots[j]
			sameKey := a.Key.String() == b.Key.String()
			sameOrigin := a.Origin.Fingerprint ==
				b.Origin.Fingerprint &&
				slices.Equal(a.Origin.Path, b.Origin.Path)
			if sameKey || sameOrigin {
				return ErrDuplicateKey
			}
		}
	}

	return nil
}

// parseSlot parses one slot: a tr() account descriptor for the on-chain
// account, or a ranged key expression for a family.
func parseSlot(text string, onChain bool,
	params *chaincfg.Params) (ManifestSlot, error) {

	var expr keyExpr
	text = strings.TrimSpace(text)
	switch {
	case onChain:
		desc, err := parseDescriptor(text)
		if errors.Is(err, ErrUnsupportedDescriptor) {
			return ManifestSlot{}, fmt.Errorf("%w: %w",
				ErrScriptDescriptorSlot, err)
		}
		if err != nil {
			return ManifestSlot{}, err
		}
		if desc.scriptType != ScriptTaproot {
			return ManifestSlot{}, fmt.Errorf("%w: the on-chain "+
				"slot must be a tr() descriptor",
				ErrUnsupportedPath)
		}
		if !isBranchWildcard(desc.key.path, true) {
			return ManifestSlot{}, fmt.Errorf("%w: the on-chain "+
				"slot must end in /<0;1>/*", ErrUnsupportedPath)
		}
		expr = desc.key

	case strings.HasPrefix(text, "["):
		body, err := splitChecksum(text)
		if err != nil {
			return ManifestSlot{}, err
		}
		parsed, err := parseKeyExpr(body)
		if err != nil {
			return ManifestSlot{}, err
		}
		if !isBranchWildcard(parsed.path, false) {
			return ManifestSlot{}, fmt.Errorf("%w: a family slot "+
				"must end in /0/*", ErrUnsupportedPath)
		}
		expr = *parsed

	case strings.Contains(text, "("):
		return ManifestSlot{}, ErrScriptDescriptorSlot

	default:
		return ManifestSlot{}, fmt.Errorf("%w: a family slot is a "+
			"[fingerprint/path]KEY/0/* key expression",
			ErrManifestMalformed)
	}

	if !expr.hasOrigin || len(expr.originPath) == 0 {
		return ManifestSlot{}, fmt.Errorf("%w: a slot needs a "+
			"[fingerprint/path] origin", ErrBundleAccountPath)
	}

	key, err := normalizeAccountKey(expr.key, params)
	if err != nil {
		return ManifestSlot{}, err
	}

	// The key must be the one at its stated origin path. The path itself
	// is free: the wallet derives nothing hardened below a slot.
	last := expr.originPath[len(expr.originPath)-1]
	if int(key.Depth()) != len(expr.originPath) ||
		key.ChildIndex() != last {
		return ManifestSlot{}, fmt.Errorf("%w: key is not at its "+
			"stated origin path", ErrBundleAccountPath)
	}

	return ManifestSlot{
		Key: key,
		Origin: KeyOrigin{
			Fingerprint: expr.originFingerprint,
			Path:        expr.originPath,
		},
	}, nil
}

// encode renders the canonical manifest: entries normalized and
// checksummed, keys sorted, no insignificant whitespace.
func (m *Manifest) encode() ([]byte, error) {
	onChain, err := AddChecksum(
		fmt.Sprintf(
			"tr(%s/<0;1>/*)",
			formatKeyWithOrigin(m.OnChain.Key, m.OnChain.Origin),
		),
	)
	if err != nil {
		return nil, err
	}

	families := make(map[string]string, len(m.Families))
	for family, slot := range m.Families {
		entry, err := AddChecksum(
			fmt.Sprintf(
				"%s/0/*",
				formatKeyWithOrigin(slot.Key, slot.Origin),
			),
		)
		if err != nil {
			return nil, err
		}
		families[strconv.Itoa(int(family))] = entry
	}

	// encoding/json writes map keys in sorted order, so a map gives
	// the canonical key order at both levels.
	return json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"network":             m.Network,
		"primary_fingerprint": FormatFingerprint(m.PrimaryFingerprint),
		"onchain":             onChain,
		"families":            families,
	})
}

// formatKeyWithOrigin renders [fingerprint/path]KEY.
func formatKeyWithOrigin(key *hdkeychain.ExtendedKey, origin KeyOrigin) string {
	parts := []string{FormatFingerprint(origin.Fingerprint)}
	for _, step := range origin.Path {
		if step >= hdkeychain.HardenedKeyStart {
			index := uint64(step - hdkeychain.HardenedKeyStart)
			parts = append(
				parts, strconv.FormatUint(index, 10)+"h",
			)

			continue
		}
		parts = append(parts, strconv.FormatUint(uint64(step), 10))
	}

	return "[" + strings.Join(parts, "/") + "]" + key.String()
}

// networkMatches reports whether a manifest network name is params.
func networkMatches(name string, params *chaincfg.Params) bool {
	switch name {
	case params.Name:
		return true

	case "testnet":
		return params.Name == chaincfg.TestNet3Params.Name

	default:
		return false
	}
}

// parseFingerprintHex parses eight hex characters.
func parseFingerprintHex(text string) (uint32, error) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 4 {
		return 0, fmt.Errorf("%w: primary_fingerprint must be 8 hex "+
			"characters", ErrManifestMalformed)
	}

	return uint32(raw[0])<<24 | uint32(raw[1])<<16 |
		uint32(raw[2])<<8 | uint32(raw[3]), nil
}

// checkAuthKeys requires exactly the authentication families as private
// keys from the primary root at their own paths.
func checkAuthKeys(auth *AccountKeys, primary uint32,
	params *chaincfg.Params) error {

	if auth == nil {
		return fmt.Errorf("%w: authentication keys are required",
			ErrMinimalBundleFamilies)
	}

	want := keyfamily.Families(keyfamily.Auth)
	if len(auth.Accounts) != len(want) {
		return fmt.Errorf("%w: want authentication families %v",
			ErrMinimalBundleFamilies, want)
	}
	for _, acct := range auth.Accounts {
		if acct.Purpose != PurposeKeyFamily ||
			!slices.Contains(
				want, keychain.KeyFamily(acct.Account),
			) {
			return fmt.Errorf("%w: want authentication families %v",
				ErrMinimalBundleFamilies, want)
		}
		if !acct.Key.IsPrivate() {
			return ErrAccountKeyPublic
		}
		if acct.Origin != nil {
			return fmt.Errorf("%w: family %d",
				ErrAuthFamilyOverride, acct.Account)
		}
	}
	if auth.MasterFingerprint != primary {
		return fmt.Errorf("%w: authentication keys are not from the "+
			"manifest's primary root", ErrMixedFingerprints)
	}
	if err := checkPrivateKey(auth.Accounts[0].Key, params); err != nil {
		return err
	}

	return nil
}

// ParseAuthKeys parses the authentication keys file that accompanies a
// manifest: a JSON object mapping "21" and "43" to their
// [fingerprint/1017h/COINh/FAMILYh]XPRV/0/* entries. It is secret; the
// caller must call Zero.
func ParseAuthKeys(data []byte, params *chaincfg.Params) (*AccountKeys, error) {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: authentication keys: %w",
			ErrManifestMalformed, err)
	}

	keys := &AccountKeys{}
	hasFingerprint := false
	for name, text := range raw {
		entry, err := parseAccountKeyLine(strings.TrimSpace(text))
		if err != nil {
			keys.Zero()

			return nil, fmt.Errorf("family %s: %w", name, err)
		}

		pub, err := independentPublic(entry.key)
		if err == nil {
			_, err = bundleAccount(bundleEntry{
				path: entry.path, key: pub,
			}, params)
		}
		if err == nil {
			err = checkPrivateKey(entry.key, params)
		}
		if err == nil && strconv.Itoa(
			int(
				entry.path[2]-hdkeychain.HardenedKeyStart,
			),
		) != name {

			err = fmt.Errorf("%w: entry %s is for another family",
				ErrBundleAccountPath, name)
		}
		if err == nil && hasFingerprint &&
			entry.fingerprint != keys.MasterFingerprint {

			err = ErrMixedFingerprints
		}
		if err != nil {
			entry.key.Zero()
			keys.Zero()

			return nil, err
		}

		keys.MasterFingerprint = entry.fingerprint
		hasFingerprint = true
		keys.Accounts = append(keys.Accounts, AccountKey{
			Purpose:  PurposeKeyFamily,
			CoinType: entry.path[1] - hdkeychain.HardenedKeyStart,
			Account:  entry.path[2] - hdkeychain.HardenedKeyStart,
			Key:      entry.key,
		})
	}
	slices.SortFunc(keys.Accounts, func(a, b AccountKey) int {
		return int(a.Account) - int(b.Account)
	})

	return keys, nil
}

// FormatManifest renders the manifest of a signer's account keys: the
// on-chain account and every fund family with its real origin, slots
// without one at their own path under the primary root.
func FormatManifest(keys *AccountKeys,
	params *chaincfg.Params) ([]byte, error) {

	slot := func(acct AccountKey, path []uint32) (ManifestSlot, error) {
		pub, err := independentPublic(acct.Key)
		if err != nil {
			return ManifestSlot{}, err
		}

		origin := KeyOrigin{
			Fingerprint: keys.MasterFingerprint,
			Path:        path,
		}
		if acct.Origin != nil {
			origin = *acct.Origin
		}

		return ManifestSlot{Key: pub, Origin: origin}, nil
	}

	m := &Manifest{
		Network:            params.Name,
		PrimaryFingerprint: keys.MasterFingerprint,
		Families:           make(map[keychain.KeyFamily]ManifestSlot),
	}

	onChain, ok := keys.Account(ScriptTaproot.Purpose(), 0)
	if !ok {
		return nil, fmt.Errorf("%w: no BIP86 account",
			ErrBundleIncomplete)
	}
	var err error
	m.OnChain, err = slot(onChain, accountPath(86, 0, 0))
	if err != nil {
		return nil, err
	}

	coin := coinTypeForNet(params)
	for _, family := range keyfamily.Families(keyfamily.Funds) {
		acct, ok := keys.Account(PurposeKeyFamily, uint32(family))
		if !ok {
			return nil, fmt.Errorf("%w: no family %d",
				ErrBundleIncomplete, family)
		}
		m.Families[family], err = slot(
			acct,
			accountPath(
				PurposeKeyFamily, coin, uint32(family),
			),
		)
		if err != nil {
			return nil, err
		}
	}

	if err := m.checkDistinct(); err != nil {
		return nil, err
	}

	return m.encode()
}

// FormatAuthKeys renders the authentication keys file for keys' primary
// root. Its text is secret.
func FormatAuthKeys(keys *AccountKeys) ([]byte, error) {
	origin := FormatFingerprint(keys.MasterFingerprint)

	entries := make(map[string]string)
	for _, family := range keyfamily.Families(keyfamily.Auth) {
		acct, ok := keys.Account(PurposeKeyFamily, uint32(family))
		if !ok {
			return nil, fmt.Errorf("%w: no family %d",
				ErrBundleIncomplete, family)
		}
		if acct.Origin != nil {
			return nil, fmt.Errorf("%w: family %d",
				ErrAuthFamilyOverride, family)
		}

		entry, err := AddChecksum(
			fmt.Sprintf("[%s/%dh/%dh/%dh]%s/0/*", origin,
				acct.Purpose, acct.CoinType, acct.Account,
				acct.Key),
		)
		if err != nil {
			return nil, err
		}
		entries[strconv.Itoa(int(family))] = entry
	}

	return json.MarshalIndent(entries, "", "  ")
}

// ParseKeySource parses the private key that fills an overridden slot:
// either [fingerprint/path]XPRV, an account-level key used as given, or
// XPRV/path, a master key and the hardened path to derive with standard
// BIP32. It returns the slot key and its real origin. The caller must zero
// the key.
func ParseKeySource(text string, params *chaincfg.Params) (
	*hdkeychain.ExtendedKey, KeyOrigin, error) {

	body, err := splitChecksum(strings.TrimSpace(text))
	if err != nil {
		return nil, KeyOrigin{}, err
	}

	if strings.HasPrefix(body, "[") {
		expr, err := parseKeyExpr(body)
		if err != nil {
			return nil, KeyOrigin{}, err
		}

		refuse := func(err error) (*hdkeychain.ExtendedKey, KeyOrigin,
			error) {

			expr.key.Zero()

			return nil, KeyOrigin{}, err
		}
		switch {
		case !expr.key.IsPrivate():
			return refuse(ErrAccountKeyPublic)

		case len(expr.originPath) == 0 || len(expr.path) != 0:
			return refuse(
				fmt.Errorf("%w: give [fingerprint/path]XPRV "+
					"with no suffix", ErrBundleAccountPath),
			)

		case int(expr.key.Depth()) != len(expr.originPath) ||
			expr.key.ChildIndex() !=
				expr.originPath[len(expr.originPath)-1]:
			return refuse(
				fmt.Errorf("%w: key is not at its stated "+
					"origin path", ErrBundleAccountPath),
			)
		}
		if err := checkPrivateKey(expr.key, params); err != nil {
			return refuse(err)
		}

		return expr.key, KeyOrigin{
			Fingerprint: expr.originFingerprint,
			Path:        expr.originPath,
		}, nil
	}

	keyText, pathText, _ := strings.Cut(body, "/")
	root, err := parseExtendedKey(keyText)
	if err != nil {
		return nil, KeyOrigin{}, err
	}
	defer root.Zero()

	switch {
	case !root.IsPrivate() || root.Depth() != 0:
		return nil, KeyOrigin{}, fmt.Errorf("%w: give a master XPRV "+
			"followed by its path", ErrNotRootKey)

	case pathText == "":
		return nil, KeyOrigin{}, fmt.Errorf("%w: a master key needs "+
			"the path to the slot key", ErrBundleAccountPath)
	}
	if err := checkPrivateKey(root, params); err != nil {
		return nil, KeyOrigin{}, err
	}

	var path []uint32
	for _, part := range strings.Split(pathText, "/") {
		index, err := parseIndex(part)
		if err != nil {
			return nil, KeyOrigin{}, err
		}
		if index < hdkeychain.HardenedKeyStart {
			return nil, KeyOrigin{}, fmt.Errorf("%w: a slot key's "+
				"path must be hardened", ErrBundleAccountPath)
		}
		path = append(path, index)
	}

	key, err := deriveHardened(root, path, false)
	if err != nil {
		return nil, KeyOrigin{}, err
	}
	fp, err := Fingerprint(root)
	if err != nil {
		key.Zero()

		return nil, KeyOrigin{}, err
	}

	return key, KeyOrigin{Fingerprint: fp, Path: path}, nil
}

// ApplyOverride fills slot of keys with key from origin: "onchain" for the
// BIP86 account, or a fund family number. Authentication families and
// families outside the registry cannot be overridden. The old key is
// wiped, and keys takes ownership of key.
func ApplyOverride(keys *AccountKeys, slot string, key *hdkeychain.ExtendedKey,
	origin KeyOrigin) error {

	purpose, account := ScriptTaproot.Purpose(), uint32(0)
	if slot != "onchain" {
		number, err := strconv.ParseUint(slot, 10, 32)
		if err != nil {
			return fmt.Errorf("%w: slot %q is \"onchain\" or a "+
				"family number", ErrManifestMalformed, slot)
		}

		family := keychain.KeyFamily(number)
		auth := keyfamily.Families(keyfamily.Auth)
		switch {
		case slices.Contains(auth, family):
			return fmt.Errorf("%w: family %d",
				ErrAuthFamilyOverride, family)

		case !slices.Contains(
			keyfamily.Families(keyfamily.Funds), family,
		):
			return fmt.Errorf("%w: family %d is not a fund family",
				ErrMinimalBundleFamilies, family)
		}
		purpose, account = PurposeKeyFamily, uint32(number)
	}

	for i, acct := range keys.Accounts {
		if acct.Purpose != purpose || acct.Account != account {
			continue
		}

		acct.Key.Zero()
		keys.Accounts[i].Key = key
		keys.Accounts[i].Origin = &origin

		return nil
	}

	return fmt.Errorf("%w: no slot %s", ErrBundleIncomplete, slot)
}
