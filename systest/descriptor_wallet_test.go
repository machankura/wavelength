//go:build systest

package systest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/wavelength/harness"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/walletdesc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// descriptorTestPassword encrypts the test wallets' databases.
var descriptorTestPassword = []byte("descriptor-systest-password")

// descriptorTestSeed returns the first deterministic aezeed-shaped seed (16
// bytes of entropy then zeros) whose master key passes descriptor
// validation, together with that master key.
func descriptorTestSeed(t *testing.T) ([]byte, *hdkeychain.ExtendedKey) {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	for i := 0; i < 256; i++ {
		seed := make([]byte, 32)
		for j := 0; j < 16; j++ {
			seed[j] = byte(0x60 + i + j)
		}

		root, err := hdkeychain.NewMaster(seed, params)
		require.NoError(t, err)

		private, err := walletdesc.CanonicalPrivate(root, params)
		require.NoError(t, err)

		texts := make([]string, len(private))
		for k := range private {
			texts[k], err = private[k].Render(true)
			require.NoError(t, err)
		}
		if _, err := walletdesc.Parse(texts, params); err == nil {
			return seed, root
		}
	}

	t.Fatal("no compatible seed found")

	return nil, nil
}

// newDescriptorTestWallet creates an lwwallet from either a seed or a root
// key in its own directory.
func newDescriptorTestWallet(t *testing.T, esploraURL string, seed []byte,
	root *hdkeychain.ExtendedKey) *lwwallet.Wallet {

	t.Helper()

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(&testWriter{t: t}))
	logger.SetLevel(btclog.LevelInfo)

	w, err := lwwallet.New(lwwallet.Config{
		Seed:           seed,
		RootKey:        root,
		WalletPassword: descriptorTestPassword,
		EsploraURL:     esploraURL,
		ChainParams:    &chaincfg.RegressionNetParams,
		PollInterval:   time.Second,
		RecoveryWindow: 100,
		DBDir:          t.TempDir(),
		Log:            fn.Some[btclog.Logger](logger),
	})
	require.NoError(t, err)
	require.NoError(t, w.Start())
	t.Cleanup(w.Stop)

	return w
}

// waitForConfirmedBalance polls until the wallet reports want confirmed.
func waitForConfirmedBalance(t *testing.T, ctx context.Context,
	w *lwwallet.Wallet, want btcutil.Amount) {

	t.Helper()

	require.NoError(t, w.WaitForSync(ctx))
	require.Eventually(t, func() bool {
		confirmed, _, err := w.Balance(ctx)
		if err != nil {
			t.Logf("balance error: %v", err)

			return false
		}

		return confirmed == want
	}, 2*time.Minute, 250*time.Millisecond,
		"wallet never reached confirmed balance %v", want)
}

// TestDescriptorWalletRestoresSeedWalletFunds funds a seed-created wallet,
// renders its private descriptors, rebuilds the wallet from those
// descriptors alone in a fresh directory, and checks the rebuilt wallet sees
// the same funds and continues the same address chain.
func TestDescriptorWalletRestoresSeedWalletFunds(t *testing.T) {
	h := harness.NewHarness(t, nil)
	h.Start()
	t.Cleanup(h.Stop)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	const fundAmount = btcutil.Amount(75_000)
	seed, root := descriptorTestSeed(t)

	original := newDescriptorTestWallet(t, h.EsploraURL, seed, nil)
	require.NoError(t, original.WaitForSync(ctx))

	addr, err := original.NewAddress(ctx)
	require.NoError(t, err)
	h.Faucet(addr.String(), fundAmount)
	h.Generate(1)
	waitForConfirmedBalance(t, ctx, original, fundAmount)

	identityLoc := keychain.KeyLocator{Family: keychain.KeyFamilyNodeKey}
	wantIdentity, err := original.DeriveKey(ctx, identityLoc)
	require.NoError(t, err)
	wantNext, err := original.NewAddress(ctx)
	require.NoError(t, err)

	// Export: render the private descriptors and parse them back as an
	// importing daemon would.
	params := &chaincfg.RegressionNetParams
	private, err := walletdesc.CanonicalPrivate(root, params)
	require.NoError(t, err)
	texts := make([]string, len(private))
	for i := range private {
		texts[i], err = private[i].Render(true)
		require.NoError(t, err)
	}
	wd, err := walletdesc.Parse(texts, params)
	require.NoError(t, err)

	rebuilt := newDescriptorTestWallet(t, h.EsploraURL, nil, wd.Root)
	waitForConfirmedBalance(t, ctx, rebuilt, fundAmount)

	gotIdentity, err := rebuilt.DeriveKey(ctx, identityLoc)
	require.NoError(t, err)
	require.True(t, wantIdentity.PubKey.IsEqual(gotIdentity.PubKey))

	// The rebuilt wallet saw the first address used, so its next
	// address matches the original's second.
	gotFirst, err := rebuilt.NewAddress(ctx)
	require.NoError(t, err)
	require.Equal(t, wantNext.String(), gotFirst.String())
}

// TestDescriptorWalletSeesCoreDerivedFunds checks interoperability with
// Bitcoin Core: Core derives the first receive addresses from the public
// descriptors a root-key wallet reports, the harness pays them, and the
// wallet must see both payments.
func TestDescriptorWalletSeesCoreDerivedFunds(t *testing.T) {
	h := harness.NewHarness(t, nil)
	h.Start()
	t.Cleanup(h.Stop)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	params := &chaincfg.RegressionNetParams
	_, root := descriptorTestSeed(t)

	public, err := walletdesc.CanonicalPublic(root, params)
	require.NoError(t, err)

	rpc, err := h.BitcoinRPCClient()
	require.NoError(t, err)
	t.Cleanup(rpc.Shutdown)

	const perAddress = btcutil.Amount(40_000)
	for i := range public {
		text, err := public[i].Render(false)
		require.NoError(t, err)

		descArg, err := json.Marshal(text)
		require.NoError(t, err)
		rangeArg, err := json.Marshal([]int{0, 0})
		require.NoError(t, err)

		raw, err := rpc.RawRequest(
			"deriveaddresses", []json.RawMessage{descArg, rangeArg},
		)
		require.NoError(t, err)

		// A multipath descriptor yields one list per path; index 0
		// of the receive path is the first one.
		var perPath [][]string
		require.NoError(t, json.Unmarshal(raw, &perPath))
		require.NotEmpty(t, perPath)
		require.NotEmpty(t, perPath[0])

		t.Logf(
			"%s index 0 per Core: %s", public[i].ScriptType(),
			perPath[0][0],
		)
		h.Faucet(perPath[0][0], perAddress)
	}
	h.Generate(1)

	w := newDescriptorTestWallet(t, h.EsploraURL, nil, root)
	waitForConfirmedBalance(
		t, ctx, w, perAddress*btcutil.Amount(len(public)),
	)
}
