package walletdesc

import (
	"encoding/hex"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

// The bytes a threshold group's wallet opens with, as a Kotlin implementation
// outside this repository computes them from a group's public key. A daemon
// change that stops accepting them, or hashes them differently, is what these
// vectors exist to catch: the hash is signed into the group's statement.
const (
	groupManifest = `{"families":{"202":"[61504962/1017h/1h/202h]tpubDC2Q4xK4XH7BAenNARz6U8TAL11UqC9iqKTQMLwPUHkcaVskrJcaLPtVkHM73HzBtjBvs6xSMwwrKdfnPm7LEjcwGD1XuHeVnxM2bhxrex2/0/*#4cjxxt0d","42":"[61504962/1017h/1h/42h]tpubDC2Q4xK4XH747ybuRVuvViz8zat5GVWYr3odo1Yh9AmyWo3kS3ca5pyuGvb95QKPsbdaK46XJfddvWx9eGvRnH325f18Cz8FZ6Vu8YirRSK/0/*#d4xku9au","44":"[61504962/1017h/1h/44h]tpubDC2Q4xK4XH74D3owKbc1dk7VcgGVcyktHQ6R12u3QF585V2MDuSKDWoNSK1hte5wnysFN2c1oVVXJHsEf7a663Aygqfyvh4ZNk9kpmkjPdX/0/*#pw6xg84u","45":"[61504962/1017h/1h/45h]tpubDC2Q4xK4XH74G6VpFhDtCyqVkLKi86gn3mhaeikCZSGDozkLXn7iYZVL2c8BNiMdBkJAWqJ7NuPLuVGoq2JRZ9FF8RjBbznzrqLFSu8KMcN/0/*#x3j0eh0v","6":"[ac04f47d/1017h/1h/6h]tpubDC5MkyuEv1GqMW7urZE7cbSSr2v5gMd8UFEiqJqpcvx6dY6yj1okzVVVTuWuj5WqZJqchNCGCs69obGbXvZebs3U1jDtprGoRLey2gmcrjG/0/*#62zpkr4s"},"network":"regtest","onchain":"tr([61504962/86h/0h/0h]tpubDC2Q4xK4XH72Gn5JVi6ggnB5aESmPj6d22iRN7c3S2eS5wE3y8hoF8NBQ3mwkzAhtgGaFz25uT1vbkoyjJRGr8qwDjL3A3ysWJL8RQuSHkD/\u003c0;1\u003e/*)#kcs89q9g","primary_fingerprint":"ac04f47d","version":1}`

	groupManifestHash = "89e6321901c9e4c1368408d745b2bdd9810d4895acb82938d1b86787cf81abb5"

	groupAuthKeys = `{"21":"[ac04f47d/1017h/1h/21h]tprv8fPKcZrzmdbB8gfvwSzkDyxrzqnw4WmuBurpP2focvj1NjhremtpMeJPesF7FZp3J54sSMo7DDiLdqzScH65p7ShJJre5zQk7LTem3cY8ss/0/*#th4x60fh","43":"[ac04f47d/1017h/1h/43h]tprv8fPKcZrzmdbC6vPRNGzTeAUZCx2sKH9KH4rbAsW6oUw7yJUrLrcmGckiVk4eAaA4Pnxv3NfYfJeqYaU8JQiJwnayP83qRWACghdVAdK3zqh/0/*#ly6rasx0"}`

	groupOwnerKeyAt5 = "02c7488fe04b5cf02a306d3486a09b76dc90cae2efd97b6c5359cd069e2c844ae6"

	groupTreeSigner   = "02cbf1d77f89b324093ec1244bb9206d9a7942d74d74775f7ef345adf75a125df5"
	groupTreeOperator = "033147903b63ce276507c59628b21d37c13aa70fb6526a3ee2a3f83db82b5e2d2d"
	groupTreeRoot     = "dfd33796972c3baa5e1c065390e7e75cf9ac8fb637dd031aa86490f063e79784"
	groupTreeKey      = "e2672be8cc169d2843822742abcaf8b6b70a38acfc89769427fcf615319a50c6"
)

// TestGroupManifestRoundTrip proves an externally computed manifest parses, is
// already canonical, and hashes as its author expects.
func TestGroupManifestRoundTrip(t *testing.T) {
	params := &chaincfg.RegressionNetParams

	manifest, err := ParseManifest([]byte(groupManifest), params)
	require.NoError(t, err)
	require.Equal(t, groupManifest, string(manifest.Canonical()))
	require.Equal(t, groupManifestHash, manifest.HashHex())

	// The identity family stays at its own path under the primary root,
	// which is what the authentication keys come from, and every other
	// slot is an override with the group's own origin.
	require.NoError(t, manifest.CheckIdentity(false, params))
	require.Len(t, manifest.Overrides(params), 5)
}

// TestGroupAuthKeysJoinManifest proves the secret half joins the public half
// into the split-signing bundle a wallet imports.
func TestGroupAuthKeysJoinManifest(t *testing.T) {
	params := &chaincfg.RegressionNetParams

	manifest, err := ParseManifest([]byte(groupManifest), params)
	require.NoError(t, err)

	auth, err := ParseAuthKeys([]byte(groupAuthKeys), params)
	require.NoError(t, err)
	defer auth.Zero()

	bundle, err := manifest.MinimalBundle(auth, params)
	require.NoError(t, err)
	require.Len(
		t, bundle.Public.Accounts,
		len(keyfamily.Families(keyfamily.Funds))+1,
	)
}

// TestGroupOwnerKeyDerivation proves a daemon derives the same child from a
// slot's xpub as the group's cache signs for.
func TestGroupOwnerKeyDerivation(t *testing.T) {
	manifest, err := ParseManifest(
		[]byte(groupManifest), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	branch, err := manifest.Families[keyfamily.VTXOOwner].Key.Derive(0)
	require.NoError(t, err)
	child, err := branch.Derive(5)
	require.NoError(t, err)
	pub, err := child.ECPubKey()
	require.NoError(t, err)

	require.Equal(
		t, groupOwnerKeyAt5, hex.EncodeToString(pub.SerializeCompressed()),
	)
}

// TestGroupTreeKeyAggregation proves lnd's MuSig2, as a tree session uses it,
// aggregates a group's key with an operator's to the key the group signs for.
func TestGroupTreeKeyAggregation(t *testing.T) {
	parse := func(text string) *btcec.PublicKey {
		raw, err := hex.DecodeString(text)
		require.NoError(t, err)
		key, err := btcec.ParsePubKey(raw)
		require.NoError(t, err)

		return key
	}

	root, err := hex.DecodeString(groupTreeRoot)
	require.NoError(t, err)

	keys := []*btcec.PublicKey{
		parse(groupTreeSigner), parse(groupTreeOperator),
	}
	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i].SerializeCompressed()) <
			string(keys[j].SerializeCompressed())
	})

	combined, err := input.MuSig2CombineKeys(
		input.MuSig2Version100RC2, keys, true,
		&input.MuSig2Tweaks{TaprootTweak: root},
	)
	require.NoError(t, err)
	require.Equal(
		t, groupTreeKey, hex.EncodeToString(
			combined.FinalKey.SerializeCompressed()[1:],
		),
	)
}
