package walletdesc

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
)

// unsupportedFunctions maps descriptor functions Wavelength recognises but
// refuses to the reason given back to the user.
var unsupportedFunctions = map[string]string{
	"sh":            "nested segwit (sh) is not watched by the wallet",
	"wsh":           "script descriptors (wsh) are not supported",
	"pkh":           "legacy pkh descriptors are not supported",
	"pk":            "bare pk descriptors are not supported",
	"combo":         "combo descriptors are not supported",
	"multi":         "multisig descriptors are not supported",
	"sortedmulti":   "multisig descriptors are not supported",
	"multi_a":       "multisig descriptors are not supported",
	"sortedmulti_a": "multisig descriptors are not supported",
	"rawtr":         "rawtr descriptors are not supported",
	"addr":          "addr descriptors carry no key",
	"raw":           "raw descriptors carry no key",
}

// pathStep is one element of a derivation path. A step holds a single
// child index, several indexes for a BIP389 multipath step, or a wildcard.
type pathStep struct {
	// values holds the child index, or every alternative of a multipath
	// step. Hardened indexes include hdkeychain.HardenedKeyStart.
	values []uint32

	// wildcard marks the final '*' step.
	wildcard bool
}

// keyExpr is a parsed descriptor key expression.
type keyExpr struct {
	// hasOrigin reports whether a [fingerprint/path] origin was present.
	hasOrigin bool

	// originFingerprint is the origin's master key fingerprint.
	originFingerprint uint32

	// originPath is the path from the origin's master key to key.
	originPath []uint32

	// key is the extended key itself.
	key *hdkeychain.ExtendedKey

	// path holds the steps that follow the key.
	path []pathStep
}

// rawDescriptor is a descriptor after parsing but before validation.
type rawDescriptor struct {
	scriptType ScriptType
	key        keyExpr
}

// parseDescriptor parses one descriptor, verifying its checksum when it
// carries one. Error messages never include key material.
func parseDescriptor(text string) (*rawDescriptor, error) {
	body, err := splitChecksum(strings.TrimSpace(text))
	if err != nil {
		return nil, err
	}

	open := strings.IndexByte(body, '(')
	if open <= 0 || !strings.HasSuffix(body, ")") {
		return nil, fmt.Errorf("%w: expected FUNCTION(...)",
			ErrMalformedDescriptor)
	}

	name := body[:open]
	inner := body[open+1 : len(body)-1]

	var scriptType ScriptType
	switch name {
	case "tr":
		if strings.ContainsAny(inner, ",{}") {
			return nil, fmt.Errorf("%w: tr with a script tree is "+
				"not supported", ErrUnsupportedDescriptor)
		}
		scriptType = ScriptTaproot

	case "wpkh":
		scriptType = ScriptWitnessPubKeyHash

	default:
		if reason, ok := unsupportedFunctions[name]; ok {
			return nil, fmt.Errorf("%w: %s",
				ErrUnsupportedDescriptor, reason)
		}

		return nil, fmt.Errorf("%w: unknown function %q",
			ErrMalformedDescriptor, name)
	}

	if strings.ContainsAny(inner, "()") {
		return nil, fmt.Errorf("%w: nested descriptors are not "+
			"supported", ErrUnsupportedDescriptor)
	}

	key, err := parseKeyExpr(inner)
	if err != nil {
		return nil, err
	}

	return &rawDescriptor{
		scriptType: scriptType,
		key:        *key,
	}, nil
}

// parseKeyExpr parses [origin]KEY/path.
func parseKeyExpr(text string) (*keyExpr, error) {
	var expr keyExpr

	if strings.HasPrefix(text, "[") {
		end := strings.IndexByte(text, ']')
		if end < 0 {
			return nil, fmt.Errorf("%w: unterminated key origin",
				ErrMalformedDescriptor)
		}

		fp, path, err := parseOrigin(text[1:end])
		if err != nil {
			return nil, err
		}

		expr.hasOrigin = true
		expr.originFingerprint = fp
		expr.originPath = path
		text = text[end+1:]
	}

	keyText, pathText, _ := strings.Cut(text, "/")
	key, err := parseExtendedKey(keyText)
	if err != nil {
		return nil, err
	}
	expr.key = key

	if pathText != "" {
		expr.path, err = parsePath(pathText)
		if err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(text, "/") {
		return nil, fmt.Errorf("%w: empty path step",
			ErrMalformedDescriptor)
	}

	return &expr, nil
}

// parseOrigin parses the inside of a [fingerprint/path] key origin.
func parseOrigin(text string) (uint32, []uint32, error) {
	fpText, pathText, hasPath := strings.Cut(text, "/")

	raw, err := hex.DecodeString(fpText)
	if err != nil || len(raw) != 4 {
		return 0, nil, fmt.Errorf("%w: key origin fingerprint must be "+
			"8 hex characters", ErrMalformedDescriptor)
	}
	fp := uint32(raw[0])<<24 | uint32(raw[1])<<16 |
		uint32(raw[2])<<8 | uint32(raw[3])

	if !hasPath {
		return fp, nil, nil
	}

	var path []uint32
	for _, part := range strings.Split(pathText, "/") {
		index, err := parseIndex(part)
		if err != nil {
			return 0, nil, err
		}
		path = append(path, index)
	}

	return fp, path, nil
}

// parseExtendedKey parses a base58 extended key. Bare public keys and WIF
// private keys are refused because an HD wallet needs a chain code.
func parseExtendedKey(text string) (*hdkeychain.ExtendedKey, error) {
	if text == "" {
		return nil, fmt.Errorf("%w: missing key",
			ErrMalformedDescriptor)
	}

	key, err := hdkeychain.NewKeyFromString(text)
	if err != nil {

		// The underlying error never echoes the key, but the text
		// itself may be a secret, so it is deliberately left out.
		return nil, fmt.Errorf("%w: key must be an extended key "+
			"(xprv, tprv, xpub or tpub): %v",
			ErrUnsupportedDescriptor, err)
	}

	return key, nil
}

// parsePath parses the steps after a key, enforcing at most one multipath
// step and a wildcard only in last position.
func parsePath(text string) ([]pathStep, error) {
	parts := strings.Split(text, "/")
	steps := make([]pathStep, 0, len(parts))
	multipath := false

	for i, part := range parts {
		last := i == len(parts)-1

		switch {
		case part == "*":
			if !last {
				return nil, fmt.Errorf("%w: wildcard must be "+
					"the last path step",
					ErrMalformedDescriptor)
			}
			steps = append(steps, pathStep{wildcard: true})

		case part == "*h" || part == "*H" || part == "*'":
			return nil, fmt.Errorf("%w: hardened wildcards are "+
				"not supported", ErrUnsupportedDescriptor)

		case strings.HasPrefix(part, "<"):
			if multipath {
				return nil, fmt.Errorf("%w: at most one "+
					"multipath step is allowed",
					ErrUnsupportedDescriptor)
			}
			multipath = true

			values, err := parseMultipath(part)
			if err != nil {
				return nil, err
			}
			steps = append(steps, pathStep{values: values})

		default:
			index, err := parseIndex(part)
			if err != nil {
				return nil, err
			}
			steps = append(steps, pathStep{
				values: []uint32{index},
			})
		}
	}

	return steps, nil
}

// parseMultipath parses a BIP389 <a;b;...> step.
func parseMultipath(text string) ([]uint32, error) {
	if !strings.HasSuffix(text, ">") {
		return nil, fmt.Errorf("%w: unterminated multipath step",
			ErrMalformedDescriptor)
	}

	parts := strings.Split(text[1:len(text)-1], ";")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: multipath step needs at least "+
			"two values", ErrMalformedDescriptor)
	}

	values := make([]uint32, 0, len(parts))
	for _, part := range parts {
		index, err := parseIndex(part)
		if err != nil {
			return nil, err
		}
		values = append(values, index)
	}

	return values, nil
}

// parseIndex parses one decimal child index with an optional hardened
// marker (h, H or ').
func parseIndex(text string) (uint32, error) {
	hardened := false
	if n := len(text); n > 0 {
		switch text[n-1] {
		case 'h', 'H', '\'':
			hardened = true
			text = text[:n-1]
		}
	}

	if text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, fmt.Errorf("%w: invalid path step",
			ErrMalformedDescriptor)
	}

	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value >= hdkeychain.HardenedKeyStart {
		return 0, fmt.Errorf("%w: path step out of range",
			ErrMalformedDescriptor)
	}

	index := uint32(value)
	if hardened {
		index += hdkeychain.HardenedKeyStart
	}

	return index, nil
}
