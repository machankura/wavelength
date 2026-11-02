package walletdesc

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

// ScriptType is the output script family a descriptor describes.
type ScriptType uint8

const (
	// ScriptTaproot is a BIP86 taproot key-path output, tr(KEY).
	ScriptTaproot ScriptType = iota + 1

	// ScriptWitnessPubKeyHash is a BIP84 native segwit output, wpkh(KEY).
	ScriptWitnessPubKeyHash
)

// Purpose returns the BIP43 purpose btcwallet uses for the script type.
func (s ScriptType) Purpose() uint32 {
	switch s {
	case ScriptTaproot:
		return 86

	case ScriptWitnessPubKeyHash:
		return 84

	default:
		return 0
	}
}

// String returns the descriptor function name.
func (s ScriptType) String() string {
	switch s {
	case ScriptTaproot:
		return "tr"

	case ScriptWitnessPubKeyHash:
		return "wpkh"

	default:
		return "unknown"
	}
}

const (
	// walletCoinType is the coin type btcwallet's on-chain scopes use on
	// every network. Only lnd's m/1017' scope follows the network.
	walletCoinType = 0

	// walletAccount is the only account btcwallet creates per scope.
	walletAccount = 0
)

// Descriptor is one validated descriptor. It holds either the wallet's
// master private key or an account-level public key, never prints key
// material through fmt or slog, and renders text only through Render.
type Descriptor struct {
	scriptType ScriptType

	// key is the master private key when keyIsRoot is true, otherwise
	// the neutered account key.
	key       *hdkeychain.ExtendedKey
	keyIsRoot bool

	// fingerprint is the master key fingerprint, valid when
	// hasFingerprint is true.
	fingerprint    uint32
	hasFingerprint bool

	// branches are the non-hardened branch indexes, 0 and/or 1.
	branches []uint32
}

// NewAccountDescriptor builds a public descriptor from an account-level key
// at purpose'/0'/0', for example one read back from btcwallet. A private
// accountKey is neutered. When hasFingerprint is false the descriptor is
// rendered without a key origin, which BIP380 allows.
func NewAccountDescriptor(scriptType ScriptType,
	accountKey *hdkeychain.ExtendedKey, fingerprint uint32,
	hasFingerprint bool) (*Descriptor, error) {

	if scriptType.Purpose() == 0 {
		return nil, fmt.Errorf("unknown script type %d", scriptType)
	}

	if accountKey.Depth() != 3 {
		return nil, fmt.Errorf("account key must be at depth 3, got %d",
			accountKey.Depth())
	}

	// Keep an independent copy so the caller may wipe accountKey.
	pub, err := independentPublic(accountKey)
	if err != nil {
		return nil, err
	}

	return &Descriptor{
		scriptType:     scriptType,
		key:            pub,
		fingerprint:    fingerprint,
		hasFingerprint: hasFingerprint,
		branches: []uint32{
			0,
			1,
		},
	}, nil
}

// CanonicalPublic returns the account-level public descriptors a wallet
// built from root watches and spends from: tr for purpose 86 and wpkh for
// purpose 84, each covering receive and change.
func CanonicalPublic(root *hdkeychain.ExtendedKey,
	params *chaincfg.Params) ([]Descriptor, error) {

	if !root.IsForNet(params) {
		return nil, ErrNetworkMismatch
	}

	fp, err := Fingerprint(root)
	if err != nil {
		return nil, err
	}

	types := []ScriptType{ScriptTaproot, ScriptWitnessPubKeyHash}
	out := make([]Descriptor, 0, len(types))
	for _, scriptType := range types {
		acct, err := accountPublicKey(
			root, scriptType.Purpose(), walletCoinType,
			walletAccount,
		)
		if err != nil {
			return nil, err
		}

		out = append(out, Descriptor{
			scriptType:     scriptType,
			key:            acct,
			fingerprint:    fp,
			hasFingerprint: true,
			branches:       []uint32{0, 1},
		})
	}

	return out, nil
}

// CanonicalPrivate returns the private tr (86) and wpkh (84) descriptors of
// a wallet built from root, covering receive and change. A script type
// whose account path derives the same key under standard BIP32 and
// btcwallet's legacy derivation is rendered in master-key form, which any
// descriptor wallet can import. One that hits the legacy edge case is
// rendered as the account-level private key btcwallet actually uses, with
// its origin, because below the account every wallet derives identically;
// a master-key rendering would describe different addresses. The returned
// master-key descriptors share root, so wiping root makes them unusable.
func CanonicalPrivate(root *hdkeychain.ExtendedKey,
	params *chaincfg.Params) ([]Descriptor, error) {

	if !root.IsPrivate() || root.Depth() != 0 {
		return nil, ErrNotRootKey
	}
	if !root.IsForNet(params) {
		return nil, ErrNetworkMismatch
	}

	fp, err := Fingerprint(root)
	if err != nil {
		return nil, err
	}

	types := []ScriptType{ScriptTaproot, ScriptWitnessPubKeyHash}
	out := make([]Descriptor, 0, len(types))
	for _, scriptType := range types {
		path := accountPath(
			scriptType.Purpose(), walletCoinType, walletAccount,
		)

		compatible, err := legacyCompatible(root, path)
		if err != nil {
			return nil, err
		}

		desc := Descriptor{
			scriptType:     scriptType,
			key:            root,
			keyIsRoot:      true,
			fingerprint:    fp,
			hasFingerprint: true,
			branches: []uint32{
				0,
				1,
			},
		}
		if !compatible {
			acct, err := deriveHardened(root, path, true)
			if err != nil {
				return nil, err
			}
			desc.key = acct
			desc.keyIsRoot = false
		}

		out = append(out, desc)
	}

	return out, nil
}

// ScriptType returns the descriptor's script type.
func (d *Descriptor) ScriptType() ScriptType {
	return d.scriptType
}

// Fingerprint returns the master key fingerprint and whether it is known.
func (d *Descriptor) Fingerprint() (uint32, bool) {
	return d.fingerprint, d.hasFingerprint
}

// Branches returns the branch indexes the descriptor covers.
func (d *Descriptor) Branches() []uint32 {
	return slices.Clone(d.branches)
}

// HasPrivateKey reports whether Render can produce a private descriptor.
func (d *Descriptor) HasPrivateKey() bool {
	return d.key.IsPrivate()
}

// Render returns the descriptor text with its checksum. A private rendering
// of a master-key descriptor uses the master key followed by the full path;
// a private rendering of an account-key descriptor, and every public
// rendering, uses the account key with a [fingerprint/path] origin. Callers
// must treat a private rendering as seed-equivalent and never log it.
func (d *Descriptor) Render(includePrivate bool) (string, error) {
	purpose := d.scriptType.Purpose()
	branches := renderBranches(d.branches)

	var body string
	switch {
	case includePrivate && !d.HasPrivateKey():
		return "", fmt.Errorf("descriptor has no private key")

	case includePrivate && d.keyIsRoot:
		body = fmt.Sprintf("%s(%s/%dh/%dh/%dh/%s/*)", d.scriptType,
			d.key.String(), purpose, walletCoinType, walletAccount,
			branches)

	case includePrivate:
		body = fmt.Sprintf("%s(%s%s/%s/*)", d.scriptType, d.origin(),
			d.key.String(), branches)

	default:
		// A public rendering must never carry a private key, whether
		// the descriptor holds the master key or an account key.
		var (
			acct *hdkeychain.ExtendedKey
			err  error
		)
		switch {
		case d.keyIsRoot:
			acct, err = accountPublicKey(
				d.key, purpose, walletCoinType, walletAccount,
			)

		default:
			acct, err = independentPublic(d.key)
		}
		if err != nil {
			return "", err
		}

		body = fmt.Sprintf("%s(%s%s/%s/*)", d.scriptType, d.origin(),
			acct.String(), branches)
	}

	return AddChecksum(body)
}

// origin returns the [fingerprint/purpose'/0'/0'] key origin, or nothing
// when the fingerprint is unknown.
func (d *Descriptor) origin() string {
	if !d.hasFingerprint {
		return ""
	}

	return fmt.Sprintf("[%08x/%dh/%dh/%dh]", d.fingerprint,
		d.scriptType.Purpose(), walletCoinType, walletAccount)
}

// String returns a redacted summary that is safe to log.
func (d *Descriptor) String() string {
	fp := "unknown"
	if d.hasFingerprint {
		fp = fmt.Sprintf("%08x", d.fingerprint)
	}

	return fmt.Sprintf("%s descriptor (fingerprint %s, branches %s)",
		d.scriptType, fp, renderBranches(d.branches))
}

// LogValue implements slog.LogValuer without exposing key material.
func (d *Descriptor) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("script_type", d.scriptType.String()),
		slog.String("fingerprint", fmt.Sprintf("%08x", d.fingerprint)),
		slog.Bool("private", d.HasPrivateKey()),
	)
}

// renderBranches renders a branch set as "0", "1" or "<0;1>".
func renderBranches(branches []uint32) string {
	if len(branches) == 1 {
		return fmt.Sprintf("%d", branches[0])
	}

	parts := make([]string, len(branches))
	for i, b := range branches {
		parts[i] = fmt.Sprintf("%d", b)
	}

	return "<" + strings.Join(parts, ";") + ">"
}

// WalletDescriptors is a validated descriptor set and the master key they
// share. It is seed-equivalent: callers must call Zero when done and never
// log Root.
type WalletDescriptors struct {
	// Root is the master private key shared by every descriptor.
	Root *hdkeychain.ExtendedKey

	// Fingerprint is the master key fingerprint.
	Fingerprint uint32

	// Descriptors are the validated descriptors in the order given.
	Descriptors []Descriptor
}

// Zero wipes the master key. The descriptors share it, so they become
// unusable too.
func (w *WalletDescriptors) Zero() {
	if w.Root != nil {
		w.Root.Zero()
	}
}

// String returns a redacted summary that is safe to log.
func (w *WalletDescriptors) String() string {
	return fmt.Sprintf("%d descriptors (fingerprint %08x)",
		len(w.Descriptors), w.Fingerprint)
}

// LogValue implements slog.LogValuer without exposing key material.
func (w *WalletDescriptors) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("count", len(w.Descriptors)),
		slog.String("fingerprint", fmt.Sprintf("%08x", w.Fingerprint)),
	)
}
