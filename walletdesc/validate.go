package walletdesc

import (
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

// MaxDescriptors bounds how many descriptors one wallet may be created from.
// Two script types times two branches is four; the slack allows a mix of
// multipath and single-branch forms.
const MaxDescriptors = 8

// branchKey identifies one script type and branch for duplicate detection.
type branchKey struct {
	scriptType ScriptType
	branch     uint32
}

// Parse parses and validates descriptor text for the given network and
// returns the master key every descriptor shares. Errors wrap one of this
// package's sentinel errors and never include key material. The caller owns
// the result and must call Zero on it.
func Parse(texts []string,
	params *chaincfg.Params) (*WalletDescriptors, error) {

	switch {
	case len(texts) == 0:
		return nil, ErrNoDescriptors

	case len(texts) > MaxDescriptors:
		return nil, fmt.Errorf("%w: got %d, at most %d",
			ErrTooManyDescriptors, len(texts), MaxDescriptors)
	}

	// Parsed keys are distinct objects even when they encode the same
	// master key, so every one of them is wiped unless it becomes the
	// returned root.
	var (
		raws []*rawDescriptor
		root *hdkeychain.ExtendedKey
	)
	defer func() {
		for _, raw := range raws {
			if raw.key.key != root {
				raw.key.key.Zero()
			}
		}
	}()

	for i, text := range texts {
		raw, err := parseDescriptor(text)
		if err != nil {
			return nil, fmt.Errorf("descriptor %d: %w", i+1, err)
		}
		raws = append(raws, raw)
	}

	result := &WalletDescriptors{}
	seen := make(map[branchKey]struct{})
	var rootText string

	for i, raw := range raws {
		branches, err := validateDescriptor(raw, params)
		if err != nil {
			return nil, fmt.Errorf("descriptor %d: %w", i+1, err)
		}

		// The first descriptor fixes the master key; every later one
		// must carry the same key.
		keyText := raw.key.key.String()
		if i == 0 {
			rootText = keyText
			result.Fingerprint, err = Fingerprint(raw.key.key)
			if err != nil {
				return nil, err
			}
		} else if keyText != rootText {
			return nil, fmt.Errorf("descriptor %d: %w", i+1,
				ErrMixedRootKeys)
		}

		for _, branch := range branches {
			k := branchKey{raw.scriptType, branch}
			if _, ok := seen[k]; ok {
				return nil, fmt.Errorf("descriptor %d: %w: %s "+
					"branch %d appears twice", i+1,
					ErrDuplicateDescriptor, raw.scriptType,
					branch)
			}
			seen[k] = struct{}{}
		}

		result.Descriptors = append(result.Descriptors, Descriptor{
			scriptType:     raw.scriptType,
			keyIsRoot:      true,
			fingerprint:    result.Fingerprint,
			hasFingerprint: true,
			branches:       branches,
		})
	}

	// Every descriptor references the one surviving root key.
	root = raws[0].key.key
	result.Root = root
	for i := range result.Descriptors {
		result.Descriptors[i].key = root
	}

	return result, nil
}

// validateDescriptor applies the per-descriptor rules in a fixed order so
// the first failing rule is the one reported, and returns the branches the
// descriptor covers.
func validateDescriptor(raw *rawDescriptor,
	params *chaincfg.Params) ([]uint32, error) {

	key := raw.key.key

	if !key.IsPrivate() {
		return nil, ErrWatchOnlyDescriptor
	}

	if err := validateRoot(&raw.key); err != nil {
		return nil, err
	}

	if !key.IsForNet(params) {
		return nil, fmt.Errorf("%w: daemon network is %s",
			ErrNetworkMismatch, params.Name)
	}

	branches, err := validatePath(raw.scriptType, raw.key.path, params)
	if err != nil {
		return nil, err
	}

	compatible, err := legacyCompatible(
		key,
		accountPath(
			raw.scriptType.Purpose(), walletCoinType, walletAccount,
		),
	)
	if err != nil {
		return nil, err
	}
	if !compatible {
		return nil, ErrLegacyDerivationMismatch
	}

	return branches, nil
}

// validateRoot checks that a key expression is a master key: depth zero and,
// when an origin is present, an empty origin path and the key's own
// fingerprint.
func validateRoot(expr *keyExpr) error {
	if expr.key.Depth() != 0 {
		return fmt.Errorf("%w: key is at depth %d", ErrNotRootKey,
			expr.key.Depth())
	}

	if !expr.hasOrigin {
		return nil
	}

	if len(expr.originPath) != 0 {
		return fmt.Errorf("%w: key origin has a path", ErrNotRootKey)
	}

	fp, err := Fingerprint(expr.key)
	if err != nil {
		return err
	}
	if fp != expr.originFingerprint {
		return fmt.Errorf("%w: key origin fingerprint %08x does not "+
			"match the key", ErrNotRootKey, expr.originFingerprint)
	}

	return nil
}

// validatePath checks the steps after the master key are exactly
// purpose'/0'/0'/branch/* for the script type, and returns the branches.
func validatePath(scriptType ScriptType, path []pathStep,
	params *chaincfg.Params) ([]uint32, error) {

	purpose := scriptType.Purpose()
	if len(path) != 5 {
		return nil, fmt.Errorf("%w: expected %s(KEY/%dh/0h/0h/<0;1>/*)",
			ErrUnsupportedPath, scriptType, purpose)
	}

	hardenedStep := func(step pathStep, want uint32, name string) error {
		if len(step.values) != 1 || step.wildcard {
			return fmt.Errorf("%w: %s must be a single "+
				"hardened step", ErrUnsupportedPath, name)
		}

		got := step.values[0]
		if got != want+hdkeychain.HardenedKeyStart {
			return fmt.Errorf("%w: %s must be %dh",
				ErrUnsupportedPath, name, want)
		}

		return nil
	}

	if err := hardenedStep(path[0], purpose, "purpose"); err != nil {
		return nil, err
	}

	// Test-network wallets such as Bitcoin Core use coin type 1', but
	// btcwallet watches 0' everywhere; say so instead of a bare refusal.
	if err := hardenedStep(
		path[1], walletCoinType, "coin type",
	); err != nil {

		coin := path[1].values
		if len(coin) == 1 &&
			coin[0] == 1+hdkeychain.HardenedKeyStart &&
			params.Net != chaincfg.MainNetParams.Net {
			return nil, fmt.Errorf("%w: coin type must be 0h; "+
				"this wallet uses coin type 0' on every "+
				"network, unlike test-network wallets "+
				"that use 1'", ErrUnsupportedPath)
		}

		return nil, err
	}

	if err := hardenedStep(path[2], walletAccount, "account"); err != nil {
		return nil, err
	}

	branchStep := path[3]
	if branchStep.wildcard || len(branchStep.values) == 0 {
		return nil, fmt.Errorf("%w: missing branch step",
			ErrUnsupportedPath)
	}

	branches := slices.Clone(branchStep.values)
	for i, branch := range branches {
		if branch > 1 {
			return nil, fmt.Errorf("%w: branch must be 0, 1 "+
				"or <0;1>", ErrUnsupportedPath)
		}
		if slices.Contains(branches[:i], branch) {
			return nil, fmt.Errorf("%w: branch %d repeated",
				ErrUnsupportedPath, branch)
		}
	}

	if !path[4].wildcard {
		return nil, fmt.Errorf("%w: path must end in /*",
			ErrUnsupportedPath)
	}

	return branches, nil
}
