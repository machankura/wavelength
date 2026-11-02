package walletcore_test

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/stretchr/testify/require"
)

// standardChild derives a hardened path from key with standard BIP32.
func standardChild(t *testing.T, key *hdkeychain.ExtendedKey,
	path ...uint32) *hdkeychain.ExtendedKey {

	t.Helper()

	for _, step := range path {
		var err error
		key, err = key.Derive(hdkeychain.HardenedKeyStart + step)
		require.NoError(t, err)
	}

	return key
}

// hasLeadingZero reports whether key's private scalar starts with a zero
// byte, the condition behind btcwallet's legacy derivation quirk.
func hasLeadingZero(t *testing.T, key *hdkeychain.ExtendedKey) bool {
	t.Helper()

	priv, err := key.ECPrivKey()
	require.NoError(t, err)

	return priv.Key.Bytes()[0] == 0
}

// TestLegacyDerivationFamilyScope pins how far btcwallet's legacy hardened
// derivation reaches into the key family accounts of a seed wallet, which
// decides what an account-level key import can promise. With no leading
// zero byte on the path every family matches standard BIP32. A leading zero
// on the coin-level key m/1017'/coin' changes family 0 only: btcwallet
// derives account 0 from its unpadded in-memory key while creating the
// scope, and every later account from the stored, padded key. A leading
// zero on m/1017' changes every family, because the coin-level key itself
// differs, which no import of that coin-level key can detect.
func TestLegacyDerivationFamilyScope(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	seeds := make(map[string][]byte)
	for i := 0; i < 1<<20 && len(seeds) < 3; i++ {
		seed := make([]byte, walletcore.SeedLen)
		seed[0], seed[1], seed[2] = byte(i), byte(i>>8), byte(i>>16)
		root, err := hdkeychain.NewMaster(seed, params)
		require.NoError(t, err)

		purposeZero := hasLeadingZero(t, standardChild(t, root, 1017))
		coinZero := hasLeadingZero(t, standardChild(t, root, 1017, 1))
		var name string
		switch {
		case !purposeZero && !coinZero:
			name = "none"

		case coinZero && !purposeZero:
			name = "coin"

		case purposeZero && !coinZero:
			name = "purpose"

		default:
			continue
		}
		if seeds[name] == nil {
			seeds[name] = seed
		}
	}
	require.Len(t, seeds, 3)

	wantDiffering := map[string]int{"none": 0, "coin": 1, "purpose": 256}
	for name, seed := range seeds {
		w, _ := createTestWallet(
			t, params, func(l *wallet.Loader) (*wallet.Wallet,
				error) {

				return l.CreateNewWallet(
					walletcore.PublicWalletPassphrase,
					testPrivPass, seed, time.Now(),
				)
			},
		)
		scope := familyScope(params)
		mgr, err := w.AddrManager().FetchScopedKeyManager(scope)
		require.NoError(t, err)
		require.NoError(t, w.InitAccounts(mgr, false, 255))

		root, err := hdkeychain.NewMaster(seed, params)
		require.NoError(t, err)

		var differing []uint32
		for family := uint32(0); family <= 255; family++ {
			props, err := w.AccountProperties(scope, family)
			require.NoError(t, err)
			pub, err := standardChild(
				t, root, 1017, 1, family,
			).Neuter()
			require.NoError(t, err)
			if pub.String() != props.AccountPubKey.String() {
				differing = append(differing, family)
			}
		}

		require.Len(t, differing, wantDiffering[name], name)
		if name == "coin" {
			require.Equal(t, []uint32{0}, differing)
		}
	}

}
