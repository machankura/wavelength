package walletdesc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// testSeed returns a deterministic 32-byte seed for index i.
func testSeed(i uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], i)
	sum := sha256.Sum256(append([]byte("walletdesc test seed"), buf[:]...))

	return sum[:]
}

// testRoot returns the master key for seed i on params.
func testRoot(t *testing.T, i uint32,
	params *chaincfg.Params) *hdkeychain.ExtendedKey {

	t.Helper()

	root, err := hdkeychain.NewMaster(testSeed(i), params)
	require.NoError(t, err)

	return root
}

// compatibleSeed returns the first seed index whose BIP86 and BIP84 account
// paths derive identically under standard and legacy BIP32, so tests that
// are not about that edge case never trip over it.
func compatibleSeed(t *testing.T, params *chaincfg.Params) uint32 {
	t.Helper()

	for i := uint32(0); i < 1000; i++ {
		root := testRoot(t, i, params)

		ok86, err := legacyCompatible(root, accountPath(86, 0, 0))
		require.NoError(t, err)
		ok84, err := legacyCompatible(root, accountPath(84, 0, 0))
		require.NoError(t, err)

		if ok86 && ok84 {
			return i
		}
	}

	t.Fatal("no compatible seed found")

	return 0
}

// accountKey derives the private account key at path from root.
func accountKey(t *testing.T, root *hdkeychain.ExtendedKey,
	path ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	key, err := deriveHardened(root, path, true)
	require.NoError(t, err)

	return key
}

// TestChecksumVector pins the BIP380 checksum algorithm to the published
// test vector.
func TestChecksumVector(t *testing.T) {
	t.Parallel()

	sum, err := Checksum("raw(deadbeef)")
	require.NoError(t, err)
	require.Equal(t, "89f8spxm", sum)

	body, err := splitChecksum("raw(deadbeef)#89f8spxm")
	require.NoError(t, err)
	require.Equal(t, "raw(deadbeef)", body)

	_, err = splitChecksum("raw(deadbeef)#89f8spxn")
	require.ErrorIs(t, err, ErrBadChecksum)

	_, err = splitChecksum("raw(deadbeef)#89f8sp")
	require.ErrorIs(t, err, ErrBadChecksum)

	_, err = Checksum("raw(dead\x01beef)")
	require.ErrorIs(t, err, ErrMalformedDescriptor)
}

// TestFingerprintBIP32Vector pins Fingerprint to BIP32 test vector 1, whose
// master key fingerprint is 3442193e.
func TestFingerprintBIP32Vector(t *testing.T) {
	t.Parallel()

	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)

	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	fp, err := Fingerprint(root)
	require.NoError(t, err)
	require.Equal(t, uint32(0x3442193e), fp)
}

// TestParseAccepts covers every accepted descriptor shape.
func TestParseAccepts(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)
	fp, err := Fingerprint(root)
	require.NoError(t, err)
	k := root.String()

	tests := []struct {
		name     string
		texts    []string
		branches [][]uint32
	}{{
		name: "taproot multipath",
		texts: []string{
			"tr(" + k + "/86h/0h/0h/<0;1>/*)",
		},
		branches: [][]uint32{
			{
				0,
				1,
			},
		},
	}, {
		name: "taproot separate branches",
		texts: []string{
			"tr(" + k + "/86h/0h/0h/0/*)",
			"tr(" + k + "/86h/0h/0h/1/*)",
		},
		branches: [][]uint32{
			{
				0,
			},
			{
				1,
			},
		},
	}, {
		name: "wpkh",
		texts: []string{
			"wpkh(" + k + "/84h/0h/0h/<0;1>/*)",
		},
		branches: [][]uint32{
			{
				0,
				1,
			},
		},
	}, {
		name: "both script types",
		texts: []string{
			"tr(" + k + "/86h/0h/0h/<0;1>/*)",
			"wpkh(" + k + "/84h/0h/0h/<0;1>/*)",
		},
		branches: [][]uint32{
			{
				0,
				1,
			},
			{
				0,
				1,
			},
		},
	}, {
		name: "own fingerprint origin and other markers",
		texts: []string{
			fmt.Sprintf("tr([%08x]%s/86'/0H/0h/<1;0>/*)", fp, k),
		},
		branches: [][]uint32{
			{
				1,
				0,
			},
		},
	}, {
		name: "surrounding whitespace",
		texts: []string{
			"  tr(" + k + "/86h/0h/0h/0/*)\n",
		},
		branches: [][]uint32{
			{
				0,
			},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Every case must also pass with a checksum.
			for _, withSum := range []bool{false, true} {
				texts := tc.texts
				if withSum {
					texts = make([]string, len(tc.texts))
					for i, text := range tc.texts {
						texts[i], err = AddChecksum(
							strings.TrimSpace(text),
						)
						require.NoError(t, err)
					}
				}

				wd, err := Parse(texts, params)
				require.NoError(t, err)
				require.Equal(t, fp, wd.Fingerprint)
				require.Equal(t, k, wd.Root.String())
				require.Len(t, wd.Descriptors, len(tc.branches))

				for i, want := range tc.branches {
					require.Equal(
						t, want,
						wd.Descriptors[i].Branches(),
					)
				}
			}
		})
	}
}

// TestParseRejects covers every refusal, each with its sentinel error.
func TestParseRejects(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)
	k := root.String()

	other := testRoot(t, compatibleSeed(t, params)+1000, params)
	mainnet := testRoot(
		t, compatibleSeed(t, &chaincfg.MainNetParams),
		&chaincfg.MainNetParams,
	)

	fp, err := Fingerprint(root)
	require.NoError(t, err)

	xpub, err := root.Neuter()
	require.NoError(t, err)

	acct := accountKey(
		t, root, accountPath(86, 0, 0)...,
	)

	secrets := []string{
		k, other.String(), mainnet.String(), xpub.String(),
		acct.String(),
	}

	tr := func(key, path string) string {
		return "tr(" + key + "/" + path + ")"
	}

	tooMany := make([]string, MaxDescriptors+1)
	for i := range tooMany {
		tooMany[i] = tr(k, "86h/0h/0h/0/*")
	}

	tests := []struct {
		name  string
		texts []string
		want  error
	}{
		{
			"none",
			nil,
			ErrNoDescriptors,
		},
		{
			"too many",
			tooMany,
			ErrTooManyDescriptors,
		},
		{
			"not a function",
			[]string{
				k,
			},
			ErrMalformedDescriptor,
		},
		{"unknown function", []string{
			"foo(" + k + ")",
		},
			ErrMalformedDescriptor},
		{"nested segwit", []string{
			"sh(wpkh(" + k + "/49h/0h/0h/0/*))"},
			ErrUnsupportedDescriptor},
		{"wsh", []string{
			"wsh(pk(" + k + "))",
		},
			ErrUnsupportedDescriptor},
		{"multisig", []string{
			"multi(1," + k + ")",
		},
			ErrUnsupportedDescriptor},
		{"pkh", []string{
			"pkh(" + k + "/44h/0h/0h/0/*)",
		},
			ErrUnsupportedDescriptor},
		{"addr", []string{
			"addr(bcrt1qexample)",
		},
			ErrUnsupportedDescriptor},
		{"tr script tree", []string{
			"tr(" + k + "/86h/0h/0h/0/*,{pk(" + k + ")})"},
			ErrUnsupportedDescriptor},
		{"bare public key", []string{
			"tr(" + strings.Repeat("ab", 32) + ")"},
			ErrUnsupportedDescriptor},
		{"hardened wildcard", []string{
			tr(k, "86h/0h/0h/0/*h"),
		},
			ErrUnsupportedDescriptor},
		{"two multipaths", []string{
			tr(k, "86h/0h/<0;1>/<0;1>/*"),
		},
			ErrUnsupportedDescriptor},
		{"bad checksum", []string{
			tr(k, "86h/0h/0h/0/*") + "#aaaaaaaa",
		},
			ErrBadChecksum},
		{"watch-only", []string{
			tr(xpub.String(), "86h/0h/0h/0/*"),
		},
			ErrWatchOnlyDescriptor},
		{"account-level key", []string{fmt.Sprintf(
			"tr([%08x/86h/0h/0h]%s/0/*)", fp, acct.String())},
			ErrNotRootKey},
		{"origin with path", []string{fmt.Sprintf(
			"tr([%08x/86h]%s/86h/0h/0h/0/*)", fp, k)},
			ErrNotRootKey},
		{"wrong origin fingerprint", []string{
			"tr([00000000]" + k + "/86h/0h/0h/0/*)"},
			ErrNotRootKey},
		{"mixed roots", []string{
			tr(k, "86h/0h/0h/0/*"),
			tr(other.String(), "86h/0h/0h/1/*")},
			ErrMixedRootKeys},
		{"mainnet key on regtest", []string{
			tr(mainnet.String(), "86h/0h/0h/0/*")},
			ErrNetworkMismatch},
		{"purpose for other script", []string{
			tr(k, "84h/0h/0h/0/*")}, ErrUnsupportedPath},
		{"purpose 49", []string{
			"wpkh(" + k + "/49h/0h/0h/0/*)"}, ErrUnsupportedPath},
		{"test-network coin type", []string{
			tr(k, "86h/1h/0h/0/*")}, ErrUnsupportedPath},
		{"account 1", []string{
			tr(k, "86h/0h/1h/0/*"),
		},
			ErrUnsupportedPath},
		{"branch 2", []string{
			tr(k, "86h/0h/0h/2/*"),
		},
			ErrUnsupportedPath},
		{"hardened branch", []string{
			tr(k, "86h/0h/0h/0h/*"),
		},
			ErrUnsupportedPath},
		{"no wildcard", []string{
			tr(k, "86h/0h/0h/0/5"),
		},
			ErrUnsupportedPath},
		{"short path", []string{
			tr(k, "86h/0h/*"),
		},
			ErrUnsupportedPath},
		{
			"no path",
			[]string{
				"tr(" + k + ")",
			},
			ErrUnsupportedPath,
		},
		{"duplicate branch", []string{
			tr(k, "86h/0h/0h/<0;1>/*"),
			tr(k, "86h/0h/0h/1/*")},
			ErrDuplicateDescriptor},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wd, err := Parse(tc.texts, params)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, wd)

			// No error message may carry key material.
			for _, secret := range secrets {
				require.NotContains(t, err.Error(), secret)
			}
		})
	}
}

// TestCoinTypeMessage checks the refusal of a coin type 1' path on a test
// network explains why, since that is what Bitcoin Core's test-network
// descriptors use.
func TestCoinTypeMessage(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)

	_, err := Parse(
		[]string{"tr(" + root.String() + "/86h/1h/0h/<0;1>/*)"}, params,
	)
	require.ErrorIs(t, err, ErrUnsupportedPath)
	require.Contains(t, err.Error(), "coin type 0' on every network")
}

// TestRenderRoundTrip checks that a private rendering parses back to the
// same wallet and that renderings are canonical and checksummed.
func TestRenderRoundTrip(t *testing.T) {
	t.Parallel()

	for _, params := range []*chaincfg.Params{
		&chaincfg.RegressionNetParams, &chaincfg.MainNetParams,
	} {
		root := testRoot(t, compatibleSeed(t, params), params)
		k := root.String()

		wd, err := Parse([]string{
			"tr(" + k + "/86'/0'/0'/<0;1>/*)",
			"wpkh(" + k + "/84H/0H/0H/0/*)",
		}, params)
		require.NoError(t, err)

		var private []string
		for i := range wd.Descriptors {
			text, err := wd.Descriptors[i].Render(true)
			require.NoError(t, err)
			private = append(private, text)
		}
		require.Equal(
			t, "tr("+k+"/86h/0h/0h/<0;1>/*)",
			strings.Split(private[0], "#")[0],
		)
		require.Equal(
			t, "wpkh("+k+"/84h/0h/0h/0/*)",
			strings.Split(private[1], "#")[0],
		)

		again, err := Parse(private, params)
		require.NoError(t, err)
		require.Equal(t, wd.Fingerprint, again.Fingerprint)
		require.Equal(t, wd.Root.String(), again.Root.String())

		for i := range again.Descriptors {
			text, err := again.Descriptors[i].Render(true)
			require.NoError(t, err)
			require.Equal(t, private[i], text)
		}
	}
}

// TestRenderPublic checks the public rendering uses the account key with an
// origin, matches CanonicalPublic, and never contains a private key.
func TestRenderPublic(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)
	fp, err := Fingerprint(root)
	require.NoError(t, err)

	wd, err := Parse([]string{
		"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
	}, params)
	require.NoError(t, err)

	public, err := wd.Descriptors[0].Render(false)
	require.NoError(t, err)
	require.NotContains(t, public, "prv")

	acct, err := accountPublicKey(root, 86, 0, 0)
	require.NoError(t, err)
	want, err := AddChecksum(
		fmt.Sprintf(
			"tr([%08x/86h/0h/0h]%s/<0;1>/*)", fp, acct.String(),
		),
	)
	require.NoError(t, err)
	require.Equal(t, want, public)

	canonical, err := CanonicalPublic(root, params)
	require.NoError(t, err)
	require.Len(t, canonical, 2)

	got, err := canonical[0].Render(false)
	require.NoError(t, err)
	require.Equal(t, want, got)

	_, err = canonical[0].Render(true)
	require.Error(t, err)

	// A descriptor rebuilt from the account key alone renders the same,
	// and without a known fingerprint it drops the origin.
	fromAcct, err := NewAccountDescriptor(ScriptTaproot, acct, fp, true)
	require.NoError(t, err)
	got, err = fromAcct.Render(false)
	require.NoError(t, err)
	require.Equal(t, want, got)

	noOrigin, err := NewAccountDescriptor(ScriptTaproot, acct, 0, false)
	require.NoError(t, err)
	got, err = noOrigin.Render(false)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(got, "tr("+acct.String()+"/"))

	_, err = CanonicalPublic(root, &chaincfg.MainNetParams)
	require.ErrorIs(t, err, ErrNetworkMismatch)
}

// TestLegacyDerivationMismatch finds a master key whose BIP86 or BIP84
// account path is affected by the legacy derivation difference and checks
// Parse refuses it.
func TestLegacyDerivationMismatch(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	for i := uint32(0); i < 5000; i++ {
		root := testRoot(t, i, params)

		for _, scriptType := range []ScriptType{
			ScriptTaproot, ScriptWitnessPubKeyHash,
		} {
			purpose := scriptType.Purpose()
			ok, err := legacyCompatible(
				root, accountPath(purpose, 0, 0),
			)
			require.NoError(t, err)
			if ok {
				continue
			}

			text := fmt.Sprintf("%s(%s/%dh/0h/0h/0/*)", scriptType,
				root.String(), purpose)
			_, err = Parse([]string{text}, params)
			require.ErrorIs(t, err, ErrLegacyDerivationMismatch)

			return
		}
	}

	t.Fatal("no affected master key found in the search range")
}

// TestRedaction checks the fmt and slog renderings of parsed values never
// carry key material.
func TestRedaction(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)

	wd, err := Parse([]string{
		"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
	}, params)
	require.NoError(t, err)

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("parsed", "wallet", wd, "first", &wd.Descriptors[0])

	for _, out := range []string{
		fmt.Sprintf("%v", wd),
		fmt.Sprintf("%s", wd),
		fmt.Sprintf("%v", &wd.Descriptors[0]),
		fmt.Sprintf("%+v", wd.Descriptors[0]),
		logged.String(),
	} {
		require.NotContains(t, out, "prv")
	}

	wd.Zero()
	_, err = wd.Descriptors[0].Render(true)
	require.Error(t, err)
}

// FuzzParse checks Parse never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	root, err := hdkeychain.NewMaster(
		testSeed(0), &chaincfg.RegressionNetParams,
	)
	if err != nil {
		f.Fatal(err)
	}
	k := root.String()

	for _, seed := range []string{
		"tr(" + k + "/86h/0h/0h/<0;1>/*)",
		"wpkh(" + k + "/84h/0h/0h/0/*)#00000000",
		"tr([00000000/1h]" + k + "/86h)",
		"sh(wpkh(" + k + "))",
		"tr(<;>/*h)",
		"raw(deadbeef)#89f8spxm",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		wd, err := Parse(
			[]string{text}, &chaincfg.RegressionNetParams,
		)
		if err == nil {
			wd.Zero()
		}
	})
}

// TestPublicKeyIndependent pins the public rendering to an independent
// derivation: the rendered account xpub's first receive key must equal the
// key derived from the master key along the full path, and must survive the
// caller wiping the key it was built from. hdkeychain's Neuter shares byte
// slices with the private key, which once made the rendered xpub carry a
// zeroed chain code.
func TestPublicKeyIndependent(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	root := testRoot(t, compatibleSeed(t, params), params)

	wd, err := Parse([]string{
		"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
	}, params)
	require.NoError(t, err)

	public, err := wd.Descriptors[0].Render(false)
	require.NoError(t, err)

	start := strings.Index(public, "]") + 1
	end := strings.Index(public[start:], "/") + start
	acctPub, err := hdkeychain.NewKeyFromString(public[start:end])
	require.NoError(t, err)
	require.Equal(t, uint8(3), acctPub.Depth())
	require.NotEqual(t, make([]byte, 32), acctPub.ChainCode())

	receive, err := acctPub.Derive(0)
	require.NoError(t, err)
	first, err := receive.Derive(0)
	require.NoError(t, err)
	gotPub, err := first.ECPubKey()
	require.NoError(t, err)

	// Derive the same key straight from the master key, with no wiping
	// anywhere along the way.
	key := root
	for _, index := range append(accountPath(86, 0, 0), 0, 0) {
		key, err = key.DeriveNonStandard(index)
		require.NoError(t, err)
	}
	wantPub, err := key.ECPubKey()
	require.NoError(t, err)
	require.True(t, wantPub.IsEqual(gotPub))

	// A descriptor built from a caller's account key keeps working after
	// the caller wipes that key.
	acctPriv := accountKey(t, root, accountPath(86, 0, 0)...)
	fp, err := Fingerprint(root)
	require.NoError(t, err)
	fromAcct, err := NewAccountDescriptor(ScriptTaproot, acctPriv, fp, true)
	require.NoError(t, err)
	acctPriv.Zero()

	again, err := fromAcct.Render(false)
	require.NoError(t, err)
	require.Equal(t, public, again)
}
