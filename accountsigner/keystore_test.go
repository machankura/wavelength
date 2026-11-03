//go:build !(js && wasm)

package accountsigner_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/stretchr/testify/require"
)

// TestKeystoreRoundTrip stores account keys under a password and reads
// them back, and checks the refusals: a wrong password, a database with no
// keystore, and a second keystore.
func TestKeystoreRoundTrip(t *testing.T) {
	t.Parallel()

	db, err := walletdb.Create(
		"bdb",
		filepath.Join(
			t.TempDir(),
			"wallet.db",
		),
		true,
		time.Minute,
		false,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	has, err := accountsigner.HasKeystore(db)
	require.NoError(t, err)
	require.False(t, has)
	_, err = accountsigner.LoadKeys(db, []byte("pw"), testParams)
	require.ErrorIs(t, err, accountsigner.ErrNoKeystore)

	root := testRoot(t)
	keys := testAccountKeys(t, root)
	password := []byte("keystore-password")

	// An overridden slot keeps its real origin through the store.
	keys.Accounts[3].Origin = &walletdesc.KeyOrigin{
		Fingerprint: 0xb2c3d4e5,
		Path: []uint32{
			hdkeychain.HardenedKeyStart + 9000,
			hdkeychain.HardenedKeyStart + 7,
		},
	}
	err = accountsigner.StoreKeys(
		db, password, keys, &waddrmgr.FastScryptOptions,
	)
	require.NoError(t, err)

	has, err = accountsigner.HasKeystore(db)
	require.NoError(t, err)
	require.True(t, has)

	loaded, err := accountsigner.LoadKeys(db, password, testParams)
	require.NoError(t, err)
	require.Equal(t, keys.MasterFingerprint, loaded.MasterFingerprint)
	require.Len(t, loaded.Accounts, len(keys.Accounts))
	for i := range keys.Accounts {
		require.Equal(
			t, keys.Accounts[i].Purpose, loaded.Accounts[i].Purpose,
		)
		require.Equal(
			t, keys.Accounts[i].Account, loaded.Accounts[i].Account,
		)
		require.Equal(
			t, keys.Accounts[i].Key.String(),
			loaded.Accounts[i].Key.String(),
		)
		require.Equal(
			t, keys.Accounts[i].Origin, loaded.Accounts[i].Origin,
		)
	}
	loaded.Zero()

	_, err = accountsigner.LoadKeys(db, []byte("wrong"), testParams)
	require.ErrorIs(t, err, accountsigner.ErrWrongPassword)

	err = accountsigner.StoreKeys(
		db, password, keys, &waddrmgr.FastScryptOptions,
	)
	require.ErrorContains(t, err, "already holds")
	keys.Zero()
}
