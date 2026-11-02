package wavewalletdk

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/stretchr/testify/require"
)

// testDescriptorWallet returns private descriptors for the first fixed seed
// that passes descriptor validation, with the master key and the identity
// they derive on regtest.
func testDescriptorWallet(t *testing.T) ([]string, *hdkeychain.ExtendedKey,
	string) {

	t.Helper()

	params := &chaincfg.RegressionNetParams
	for i := 0; i < 256; i++ {
		seed := make([]byte, 32)
		for j := 0; j < 16; j++ {
			seed[j] = byte(0x30 + i + j)
		}

		root, err := hdkeychain.NewMaster(seed, params)
		require.NoError(t, err)

		texts := []string{
			"tr(" + root.String() + "/86h/0h/0h/<0;1>/*)",
			"wpkh(" + root.String() + "/84h/0h/0h/<0;1>/*)",
		}
		if _, err := walletdesc.Parse(texts, params); err != nil {
			continue
		}

		identity, err := waved.WalletIdentityPubKeyFromRootKey(
			root, "regtest",
		)
		require.NoError(t, err)

		return texts, root, identity
	}

	t.Fatal("no compatible seed found")

	return nil, nil, ""
}

// TestDescriptorDBPasswordGoldenVector pins the database password derivation:
// changing it would lock every existing descriptor wallet out of its
// database. It must also differ from the external-seed scheme.
func TestDescriptorDBPasswordGoldenVector(t *testing.T) {
	t.Parallel()

	seed, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f",
	)
	require.NoError(t, err)
	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	password := deriveDescriptorDBPassword(root)
	require.Len(t, password, 64)
	require.Equal(t, password, deriveDescriptorDBPassword(root))
	require.Equal(t, descriptorDBPasswordGolden, string(password))

	var entropy [16]byte
	copy(entropy[:], seed)
	require.NotEqual(
		t,
		string(
			deriveExternalSeedDBPassword(entropy),
		),
		string(password),
	)
}

// TestOpenWalletFromDescriptorsImport checks an empty daemon imports the
// descriptors with the derived password and birthday, and the result
// carries the public descriptors.
func TestOpenWalletFromDescriptorsImport(t *testing.T) {
	t.Parallel()

	texts, root, identity := testDescriptorWallet(t)
	stub := &stubDaemonServer{
		state: waverpc.WalletState_WALLET_STATE_NONE,
		initResp: &waverpc.InitWalletResponse{
			IdentityPubkey:  identity,
			RootFingerprint: "abcd0123",
			Descriptors: []string{
				"tr([abcd0123/86h/0h/0h]tpub)",
			},
		},
	}
	client := newStubClient(t, stub)

	birthday := time.Unix(1_700_000_000, 0)
	result, err := client.openWalletFromDescriptors(
		t.Context(), DescriptorWalletRequest{
			Descriptors: texts,
			Birthday:    birthday,
		}, deriveDescriptorDBPassword(root), identity,
	)
	require.NoError(t, err)
	require.True(t, result.Imported)
	require.Equal(t, identity, result.IdentityPubKey)
	require.Equal(t, "abcd0123", result.RootFingerprint)
	require.Len(t, result.Descriptors, 1)

	require.Equal(t, texts, stub.lastInitReq.GetDescriptors())
	require.Equal(t, birthday.Unix(), stub.lastInitReq.GetBirthdayUnix())
	require.Empty(t, stub.lastInitReq.GetMnemonic())
	require.Equal(
		t, deriveDescriptorDBPassword(root),
		stub.lastInitReq.GetWalletPassword(),
	)
}

// TestOpenWalletFromDescriptorsUnlock checks a locked daemon is unlocked
// with the derived password and its public descriptors are listed.
func TestOpenWalletFromDescriptorsUnlock(t *testing.T) {
	t.Parallel()

	texts, root, identity := testDescriptorWallet(t)
	stub := &stubDaemonServer{
		state:          waverpc.WalletState_WALLET_STATE_LOCKED,
		unlockIdentity: identity,
		listDescriptorsResp: &waverpc.ListWalletDescriptorsResponse{
			RootFingerprint: "abcd0123",
			Descriptors: []string{
				"tr(tpub)",
				"wpkh(tpub)",
			},
		},
	}
	client := newStubClient(t, stub)

	result, err := client.openWalletFromDescriptors(
		t.Context(), DescriptorWalletRequest{
			Descriptors: texts,
		},
		deriveDescriptorDBPassword(root),
		identity,
	)
	require.NoError(t, err)
	require.False(t, result.Imported)
	require.Equal(t, "abcd0123", result.RootFingerprint)
	require.Len(t, result.Descriptors, 2)
	require.False(t, stub.initCalled)
	require.Equal(
		t, deriveDescriptorDBPassword(root),
		stub.lastUnlockReq.GetWalletPassword(),
	)
	require.False(t, stub.listDescriptorsReq.GetIncludePrivate())
}

// TestOpenWalletFromDescriptorsRefuses checks the identity check and the
// already-unlocked refusal.
func TestOpenWalletFromDescriptorsRefuses(t *testing.T) {
	t.Parallel()

	texts, root, identity := testDescriptorWallet(t)

	mismatch := newStubClient(t, &stubDaemonServer{
		state:          waverpc.WalletState_WALLET_STATE_LOCKED,
		unlockIdentity: "someone-else",
	})
	_, err := mismatch.openWalletFromDescriptors(
		t.Context(), DescriptorWalletRequest{
			Descriptors: texts,
		},
		deriveDescriptorDBPassword(root),
		identity,
	)
	require.ErrorContains(t, err, "identity mismatch")

	ready := newStubClient(t, &stubDaemonServer{
		state: waverpc.WalletState_WALLET_STATE_READY,
	})
	_, err = ready.openWalletFromDescriptors(
		t.Context(), DescriptorWalletRequest{
			Descriptors: texts,
		},
		deriveDescriptorDBPassword(root),
		identity,
	)
	require.ErrorContains(t, err, "already unlocked")
}

// TestStartDescriptorWalletValidatesBeforeStartup checks every refusal that
// must happen before the daemon starts or touches the data directory.
func TestStartDescriptorWalletValidatesBeforeStartup(t *testing.T) {
	t.Setenv(wavedSeedEnvVar, "")
	t.Setenv(wavedPasswordEnvVar, "")

	texts, _, _ := testDescriptorWallet(t)

	requireRefusedBeforeStart := func(cfg Config,
		req DescriptorWalletRequest, want string) {

		t.Helper()

		client, result, err := StartDescriptorWallet(
			t.Context(), cfg, req,
		)
		require.ErrorContains(t, err, want)
		require.Nil(t, client)
		require.Nil(t, result)

		if cfg.DataDir == "" {
			return
		}
		entries, err := os.ReadDir(cfg.DataDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	}

	requireRefusedBeforeStart(
		Config{
			Network: "regtest",
		}, DescriptorWalletRequest{
			Descriptors: texts,
		}, "explicit final data directory",
	)
	requireRefusedBeforeStart(
		Config{
			DataDir: t.TempDir(),
			Network: "regtest",
		},
		DescriptorWalletRequest{}, "at least one descriptor",
	)
	requireRefusedBeforeStart(
		Config{DataDir: t.TempDir(), Network: "regtest"},
		DescriptorWalletRequest{
			Descriptors: []string{"sh(wpkh(x))"},
		},
		"invalid descriptors",
	)
	requireRefusedBeforeStart(
		Config{DataDir: t.TempDir(), Network: "regtest"},
		DescriptorWalletRequest{
			Descriptors:            texts,
			ExpectedIdentityPubKey: "wrong-id",
		},
		"identity mismatch",
	)
	requireRefusedBeforeStart(
		Config{
			DataDir: t.TempDir(), Network: "regtest",
			WalletType: waved.WalletTypeLnd,
		},
		DescriptorWalletRequest{Descriptors: texts},
		"cannot be used for descriptor wallets",
	)

	t.Setenv(wavedSeedEnvVar, "00")
	requireRefusedBeforeStart(
		Config{
			DataDir: t.TempDir(),
			Network: "regtest",
		}, DescriptorWalletRequest{
			Descriptors: texts,
		}, "must be unset",
	)
}

// descriptorDBPasswordGolden is the password derived from BIP32 test
// vector 1's master key. It was cross-checked with an independent HKDF over
// the vector's published private key and chain code.
const descriptorDBPasswordGolden = "5b10f401e149623dc7d35d80ebe783602cd8" +
	"91fd1dcd6c8793b9290b1c735fe1"

// TestDescriptorWalletAccountKeys checks a descriptor wallet request with
// account-level private keys is accepted, implies the same identity as the
// master key they were exported from, and derives a stable database
// password distinct from the master-key scheme's.
func TestDescriptorWalletAccountKeys(t *testing.T) {
	t.Parallel()

	_, root, identity := testDescriptorWallet(t)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	derive := func(path ...uint32) string {
		key := root
		for _, step := range path {
			key, err = key.Derive(
				hdkeychain.HardenedKeyStart + step,
			)
			require.NoError(t, err)
		}

		return key.String()
	}
	texts := []string{
		"tr([" + origin + "/86h/0h/0h]" + derive(86, 0, 0) +
			"/<0;1>/*)",
		"[" + origin + "/1017h/1h]" + derive(1017, 1),
	}

	source, err := parseDescriptorWalletRequest(
		DescriptorWalletRequest{
			Descriptors: texts,
		}, "regtest",
	)
	require.NoError(t, err)
	defer source.zero()
	require.Nil(t, source.root)
	require.NotNil(t, source.keys)

	got, err := source.identity("regtest")
	require.NoError(t, err)
	require.Equal(t, identity, got)

	first, err := source.dbPassword()
	require.NoError(t, err)
	second, err := source.dbPassword()
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Len(t, first, 64)
	require.NotEqual(t, deriveDescriptorDBPassword(root), first)
}
