package walletdesc

import "errors"

var (
	// ErrMalformedDescriptor is returned for descriptor text that does not
	// follow the descriptor grammar at all.
	ErrMalformedDescriptor = errors.New("malformed descriptor")

	// ErrBadChecksum is returned when a descriptor carries a checksum that
	// does not match its text.
	ErrBadChecksum = errors.New("descriptor checksum mismatch")

	// ErrUnsupportedDescriptor is returned for well-formed descriptor
	// constructs that Wavelength cannot build a wallet from, such as
	// multisig, script trees or bare keys.
	ErrUnsupportedDescriptor = errors.New("unsupported descriptor")

	// ErrNoDescriptors is returned when no descriptor is supplied.
	ErrNoDescriptors = errors.New("no descriptors supplied")

	// ErrTooManyDescriptors is returned when more descriptors are supplied
	// than a wallet can use.
	ErrTooManyDescriptors = errors.New("too many descriptors")

	// ErrDuplicateDescriptor is returned when two descriptors describe the
	// same script type and branch.
	ErrDuplicateDescriptor = errors.New("duplicate descriptor")

	// ErrWatchOnlyDescriptor is returned for descriptors that carry only
	// public keys. Ark participation is interactive signing, so a wallet
	// built from public keys alone could never move its funds.
	ErrWatchOnlyDescriptor = errors.New("watch-only descriptors are not " +
		"supported: Wavelength must sign Ark rounds, so the " +
		"descriptor needs a private key")

	// ErrNotRootKey is returned when a descriptor's private key is not a
	// BIP32 master key. Every Ark key is derived under
	// m/1017'/coin'/family' with hardened family steps, which only the
	// master private key can produce.
	ErrNotRootKey = errors.New("descriptor key must be the BIP32 master " +
		"key: Ark keys are derived under m/1017' and cannot come " +
		"from an account-level key")

	// ErrMixedRootKeys is returned when descriptors in one set use
	// different master keys.
	ErrMixedRootKeys = errors.New("descriptors use different master keys")

	// ErrNetworkMismatch is returned when a key's version bytes belong to
	// a different network than the daemon's.
	ErrNetworkMismatch = errors.New("descriptor key is for a different " +
		"network")

	// ErrUnsupportedPath is returned for derivation paths btcwallet does
	// not watch. Accepting one would silently hide funds.
	ErrUnsupportedPath = errors.New("unsupported derivation path")

	// ErrLegacyDerivationMismatch is returned when the hardened part of a
	// path derives a different key under standard BIP32 than under the
	// legacy derivation btcwallet uses, so the wallet would watch other
	// addresses than the descriptor describes.
	ErrLegacyDerivationMismatch = errors.New("descriptor path hits a " +
		"BIP32 compatibility edge case (btcutil issue 172): the " +
		"wallet would derive different addresses than this " +
		"descriptor describes")
)
