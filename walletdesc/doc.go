// Package walletdesc parses, checksums and validates the output descriptors
// that a self-managed Wavelength wallet can be created from.
//
// The accepted grammar is deliberately small. A descriptor is either
// tr(KEY) with no script tree or wpkh(KEY), where KEY is a BIP32 master
// private key followed by the path purpose'/0'/0'/branch/*, with purpose 86
// for tr and 84 for wpkh. The branch is 0, 1, or the BIP389 multipath
// <0;1>. That is exactly what btcwallet watches: its on-chain key scopes use
// coin type 0 on every network and only account 0.
//
// Every descriptor in a set must share one master key, because every Ark key
// Wavelength uses is derived under m/1017'/coin'/family' with hardened
// family steps, which only the master private key can produce. Parse returns
// that master key so the wallet backends can build a btcwallet from it.
package walletdesc
