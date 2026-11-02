//go:build systest

package systest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// accountKeysPassword is the wallet password of the account-key wallet.
const accountKeysPassword = "account-keys-systest-pw"

// accountKeysRoot is the master key the test exports account keys from. It
// stands in for other wallet software holding the seed.
func accountKeysRoot(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x90 + i)
	}
	root, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return root
}

// deriveFamilyKey returns the public key at m/1017'/1'/family'/0/index.
func deriveFamilyKey(t *testing.T, root *hdkeychain.ExtendedKey,
	loc keychain.KeyLocator) keychain.KeyDescriptor {

	t.Helper()

	key := root
	for _, step := range []uint32{1017, 1, uint32(loc.Family)} {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}
	for _, step := range []uint32{0, loc.Index} {
		var err error
		key, err = key.Derive(step)
		require.NoError(t, err)
	}
	pub, err := key.ECPubKey()
	require.NoError(t, err)

	return keychain.KeyDescriptor{KeyLocator: loc, PubKey: pub}
}

// accountKeyTexts exports root's account keys as a user would hand them to
// `wavecli create --descriptor-file`: the BIP86 and BIP84 account xprvs and
// the coin-level key family xprv.
func accountKeyTexts(t *testing.T, root *hdkeychain.ExtendedKey) []string {
	t.Helper()

	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	derive := func(path ...uint32) *hdkeychain.ExtendedKey {
		key := root
		for _, step := range path {
			key, err = key.Derive(
				hdkeychain.HardenedKeyStart + step,
			)
			require.NoError(t, err)
		}

		return key
	}

	return []string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			derive(86, 0, 0)),
		fmt.Sprintf("wpkh([%s/84h/0h/0h]%s/<0;1>/*)", origin,
			derive(84, 0, 0)),
		fmt.Sprintf("[%s/1017h/1h]%s", origin, derive(1017, 1)),
	}
}

// newAccountKeysFixture starts a full waved instance with
// wallet.type=lwwallet over a wallet created from account-level private
// keys: no lnd and no remote signer anywhere, every signature made in the
// daemon's process from keys kept in its encrypted keystore.
func newAccountKeysFixture(t *testing.T) *directedSendFixture {
	t.Helper()

	root := accountKeysRoot(t)

	return newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			keys, err := walletdesc.ParseAccountKeys(
				accountKeyTexts(t, root),
				&chaincfg.RegressionNetParams,
			)
			require.NoError(t, err)
			defer keys.Zero()

			require.NoError(t, os.MkdirAll(cfg.NetworkDir(), 0o700))
			w, err := lwwallet.New(lwwallet.Config{
				AccountKeys:    keys,
				WalletPassword: []byte(accountKeysPassword),
				EsploraURL:     h.Harness.EsploraURL,
				ChainParams:    &chaincfg.RegressionNetParams,
				PollInterval:   time.Second,
				DBDir:          cfg.NetworkDir(),
			})
			require.NoError(t, err)
			require.NoError(t, w.Start())
			w.Stop()

			passwordFile := filepath.Join(t.TempDir(), "password")
			require.NoError(
				t,
				os.WriteFile(
					passwordFile,
					[]byte(accountKeysPassword), 0o600,
				),
			)

			cfg.Wallet.Type = waved.WalletTypeLwwallet
			cfg.Wallet.EsploraURL = h.Harness.EsploraURL
			cfg.Wallet.PollInterval = time.Second
			cfg.Wallet.PasswordFile = passwordFile
		},
	)
}

// TestAccountKeysDaemon is the W0 scenario on a wallet built from
// account-level private keys with no master key and no remote signer. The
// daemon reopens the wallet from its password file, recognising it by its
// keystore, derives the exporter's identity key, and boards, sends out of
// round and sweeps a boarding exit, every signature made in process.
func TestAccountKeysDaemon(t *testing.T) {
	ParallelN(t)

	fixture := newAccountKeysFixture(t)
	root := accountKeysRoot(t)

	ownedOutpoint := seedOwnedVTXO(
		t, fixture,
		deriveFamilyKey(
			t, root, keychain.KeyLocator{
				Family: types.VTXOOwnerKeyFamily,
				Index:  7,
			},
		),
	)
	requireIdentity(
		t, fixture.client,
		deriveFamilyKey(t, root, keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
		}).PubKey,
	)

	runRemoteSignerFlows(t, fixture, ownedOutpoint)
}
