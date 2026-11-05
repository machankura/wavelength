package lwwallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btclog/v2"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestWaitForSyncWaitsForCommit checks WaitForSync does not return while a
// write transaction is open. btcwallet moves its sync height before that
// transaction commits, so returning early lets a caller read the wallet
// without the transactions of the block it just waited for.
func TestWaitForSyncWaitsForCommit(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams

	idx := newFakeIndex()
	idx.addGenesis(params)
	for height := int32(1); height < 5; height++ {
		idx.addBlock(t, height)
	}

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 41)
	}

	w, err := New(Config{
		WalletPassword: []byte("wait-for-sync-password"),
		Seed:           seed[:],
		EsploraURL:     idx.start(t),
		ChainParams:    params,
		PollInterval:   time.Hour,
		RecoveryWindow: 10,
		DBDir:          t.TempDir(),
		Log:            fn.None[btclog.Logger](),
	})
	require.NoError(t, err)
	require.NoError(t, w.Start())
	t.Cleanup(w.Stop)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	require.NoError(t, w.WaitForSync(ctx))

	// Stand in for a writer that has moved the sync height and has not
	// committed yet.
	tx, err := w.BtcWallet.InternalWallet().Database().BeginReadWriteTx()
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- w.WaitForSync(ctx)
	}()

	select {
	case err := <-done:
		require.NoError(t, tx.Rollback())
		require.Fail(t, "returned during a write", "err: %v", err)

	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
}
