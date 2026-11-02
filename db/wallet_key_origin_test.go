package db

import (
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/stretchr/testify/require"
)

// TestWalletKeyOriginStore verifies the single-row wallet key origin is
// absent on a fresh database, round-trips the full uint32 fingerprint
// range, and is replaced on a second write.
func TestWalletKeyOriginStore(t *testing.T) {
	t.Parallel()

	sqlDB := NewTestDB(t)
	store := NewStore(
		sqlDB.DB, sqlDB.Queries, sqlDB.Backend(), btclog.Disabled,
	).NewWalletKeyOriginStore()
	ctx := t.Context()

	got, err := store.Get(ctx)
	require.NoError(t, err)
	require.True(t, got.IsNone())

	first := WalletKeyOrigin{
		RootFingerprint: 0xffffffff,
		Source:          WalletKeySourceSeed,
	}
	require.NoError(t, store.Put(ctx, first, time.Unix(100, 0)))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, first, got.UnwrapOrFail(t))

	second := WalletKeyOrigin{
		RootFingerprint: 0x3442193e,
		Source:          WalletKeySourceDescriptors,
	}
	require.NoError(t, store.Put(ctx, second, time.Unix(200, 0)))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, second, got.UnwrapOrFail(t))

	// A watch-only bundle may name no fingerprint at all.
	third := WalletKeyOrigin{
		RootFingerprint: 0,
		Source:          WalletKeySourceWatchOnly,
	}
	require.NoError(t, store.Put(ctx, third, time.Unix(300, 0)))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, third, got.UnwrapOrFail(t))

	fourth := WalletKeyOrigin{
		RootFingerprint: 0x01020304,
		Source:          WalletKeySourceAccountKeys,
	}
	require.NoError(t, store.Put(ctx, fourth, time.Unix(400, 0)))

	got, err = store.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, fourth, got.UnwrapOrFail(t))
}
