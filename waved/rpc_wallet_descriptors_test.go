//go:build !test_postgres

package waved

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/wavelength/db"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/lightningnetwork/lnd/clock"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newDescriptorTestEsplora serves the three endpoints a fresh regtest
// lwwallet needs to start: an empty chain at genesis.
func newDescriptorTestEsplora(t *testing.T) *httptest.Server {
	t.Helper()

	tipHash := chaincfg.RegressionNetParams.GenesisHash.String()
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = w.Write([]byte("0"))

		case "/block-height/0":
			_, _ = w.Write([]byte(tipHash))

		case "/block/" + tipHash:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        tipHash,
				"height":    0,
				"timestamp": 1,
			})

		default:
			http.NotFound(w, r)
		}
	}
	esplora := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(esplora.Close)

	return esplora
}

// startDescriptorTestWallet creates and starts an lwwallet from input and
// wraps it in a ready RPC server backed by a SQLite daemon database.
func startDescriptorTestWallet(t *testing.T, esploraURL string,
	input walletCreateInput) *RPCServer {

	t.Helper()

	w, err := lwwallet.New(lwwallet.Config{
		Seed:           input.seed,
		RootKey:        input.rootKey,
		Birthday:       input.birthday,
		WalletPassword: []byte(testDescriptorPassword),
		EsploraURL:     esploraURL,
		ChainParams:    &chaincfg.RegressionNetParams,
		PollInterval:   time.Hour,
		RecoveryWindow: 10,
		DBDir:          t.TempDir(),
		Log:            fn.None[btclog.Logger](),
	})
	require.NoError(t, err)
	require.NoError(t, w.Start())
	t.Cleanup(w.Stop)

	ready := make(chan struct{})
	close(ready)

	server := &Server{
		cfg: &Config{
			Network: "regtest",
			Wallet: &WalletConfig{
				Type: WalletTypeLwwallet,
			},
		},
		chainParams: &chaincfg.RegressionNetParams,
		lwWallet:    fn.Some(w),
		walletReady: ready,
		clk:         clock.NewTestClock(time.Unix(1_700_000_000, 0)),
		db:          db.NewTestDB(t),
		log:         btclog.Disabled,
	}
	server.walletState.Store(int32(WalletStateReady))

	return NewRPCServer(server)
}

// TestListWalletDescriptorsExportAndRoundTrip exercises the export RPC on a
// mnemonic wallet created before fingerprints were recorded: public export
// without origins, refusals, private export authorized by the mnemonic
// with fingerprint backfill, and a wallet rebuilt from the exported
// descriptors that matches the original.
func TestListWalletDescriptorsExportAndRoundTrip(t *testing.T) {
	t.Parallel()

	esplora := newDescriptorTestEsplora(t)
	mnemonic, root := compatibleTestMnemonic(t)
	seed, birthday, err := MnemonicToSeedWithBirthday(mnemonic, nil)
	require.NoError(t, err)

	original := startDescriptorTestWallet(t, esplora.URL, walletCreateInput{
		seed: seed[:], birthday: birthday,
	})
	ctx := t.Context()

	// Public export with no recorded fingerprint omits key origins.
	public, err := original.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{},
	)
	require.NoError(t, err)
	require.Empty(t, public.GetRootFingerprint())
	require.False(t, public.GetIncludesPrivate())
	require.Len(t, public.GetDescriptors(), 2)
	require.True(
		t, strings.HasPrefix(public.GetDescriptors()[0], "tr(tpub"),
	)
	for _, text := range public.GetDescriptors() {
		require.NotContains(t, text, "prv")
	}

	// Requests that mix or omit seed material are refused.
	for _, req := range []*waverpc.ListWalletDescriptorsRequest{
		{
			IncludePrivate: true,
		},
		{
			Mnemonic: mnemonic[:],
		},
		{IncludePrivate: true, Mnemonic: mnemonic[:],
			Descriptors: []string{
				"tr(x)",
			}},
		{
			SeedPassphrase: []byte("p"),
		},
	} {
		_, err := original.ListWalletDescriptors(ctx, req)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	// Another wallet's mnemonic does not authorize private export.
	otherMnemonic, err := GenerateSeed(nil)
	require.NoError(t, err)
	_, err = original.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{
			IncludePrivate: true, Mnemonic: otherMnemonic[:],
		},
	)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.ErrorContains(t, err, errWrongWalletSecret.Error())

	// The right mnemonic does, and backfills the fingerprint.
	private, err := original.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{
			IncludePrivate: true, Mnemonic: mnemonic[:],
		},
	)
	require.NoError(t, err)
	require.True(t, private.GetIncludesPrivate())

	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	require.Equal(t, FormatFingerprint(fp), private.GetRootFingerprint())

	wd, err := walletdesc.Parse(
		private.GetDescriptors(), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, root.String(), wd.Root.String())

	public, err = original.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, FormatFingerprint(fp), public.GetRootFingerprint())
	require.Contains(t, public.GetDescriptors()[0], FormatFingerprint(fp))

	// The exported descriptors also authorize export themselves.
	again, err := original.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{
			IncludePrivate: true,
			Descriptors:    private.GetDescriptors(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, private.GetDescriptors(), again.GetDescriptors())

	// A wallet rebuilt from the exported descriptors is the same wallet.
	prepared, err := prepareWalletCreateInput(
		&waverpc.InitWalletRequest{
			Descriptors:    private.GetDescriptors(),
			WalletPassword: []byte(testDescriptorPassword),
		}, "regtest",
	)
	require.NoError(t, err)
	defer prepared.zero()

	rebuilt := startDescriptorTestWallet(t, esplora.URL, prepared.input)

	wantID, err := original.deriveIdentityPubkey(ctx)
	require.NoError(t, err)
	gotID, err := rebuilt.deriveIdentityPubkey(ctx)
	require.NoError(t, err)
	require.Equal(t, wantID, gotID)

	wantAddr, err := original.server.lwWallet.UnsafeFromSome().NewAddress(
		ctx,
	)
	require.NoError(t, err)
	gotAddr, err := rebuilt.server.lwWallet.UnsafeFromSome().NewAddress(ctx)
	require.NoError(t, err)
	require.Equal(t, wantAddr.String(), gotAddr.String())

	require.Equal(
		t, public.GetDescriptors()[1], prepared.publicDescriptors[1],
	)
}
