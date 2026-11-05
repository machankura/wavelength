package lwwallet

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// recoveryTestPassword encrypts the wallets in the recovery tests.
var recoveryTestPassword = []byte("recovery-test-password")

// taprootOnlyAccountKeys returns account-level keys with no BIP49 or BIP84
// account, which is what a wallet exported as tr() plus key families holds.
func taprootOnlyAccountKeys(t *testing.T, params *chaincfg.Params,
	seed []byte) *walletdesc.AccountKeys {

	t.Helper()

	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	origin := walletdesc.FormatFingerprint(fp)

	child := func(path ...uint32) *hdkeychain.ExtendedKey {
		key := root
		for _, index := range path {
			key, err = key.Derive(
				hdkeychain.HardenedKeyStart + index,
			)
			require.NoError(t, err)
		}

		return key
	}

	coin := walletcore.CoinTypeForNet(params)
	keys, err := walletdesc.ParseAccountKeys([]string{
		fmt.Sprintf("tr([%s/86h/0h/0h]%s/<0;1>/*)", origin,
			child(86, 0, 0)),
		fmt.Sprintf("[%s/1017h/%dh]%s", origin, coin,
			child(1017, coin)),
	}, params)
	require.NoError(t, err)

	return keys
}

// recoveryFund returns a confirmed-style funding transaction paying script.
// Its input is not null, so the wallet does not treat it as a coinbase.
func recoveryFund(script []byte, value int64) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: chainhash.Hash{0xaa, byte(value)},
		},
	})
	tx.AddTxOut(wire.NewTxOut(value, script))

	return tx
}

// TestRestoreSeesFullySpentOutputAsSpent restores wallets over a chain where
// one output is spent with nothing paid back to the wallet and another stays
// unspent. The restored wallet must finish syncing, and must report only the
// unspent output. It covers two failures: a wallet with no BIP49 or BIP84
// account never finishing recovery, and a spend that pays the wallet nothing
// going unnoticed, which counted the spent output as still there.
func TestRestoreSeesFullySpentOutputAsSpent(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 11)
	}

	tests := []struct {
		name   string
		source func(cfg *Config)
	}{{
		name: "seed",
		source: func(cfg *Config) {
			cfg.Seed = seed[:]
		},
	}, {
		name: "account keys without bip49 or bip84",
		source: func(cfg *Config) {
			cfg.AccountKeys = taprootOnlyAccountKeys(
				t, params, seed[:],
			)
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			idx := newFakeIndex()
			idx.addGenesis(params)
			for height := int32(1); height < 20; height++ {
				idx.addBlock(t, height)
			}
			url := idx.start(t)

			config := func(dir string) Config {
				return Config{
					WalletPassword: recoveryTestPassword,
					EsploraURL:     url,
					ChainParams:    params,
					PollInterval:   time.Hour,
					RecoveryWindow: 10,
					DBDir:          dir,
					Log:            fn.None[btclog.Logger](),
				}
			}

			// A throwaway wallet supplies the address, so the
			// wallet under test starts with no knowledge of it.
			cfg := config(t.TempDir())
			test.source(&cfg)
			first, err := New(cfg)
			require.NoError(t, err)
			require.NoError(t, first.Start())
			addr, err := first.NewAddress(t.Context())
			require.NoError(t, err)
			first.Stop()

			script, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)
			strangerScript, _ := testScript(t, 0x7a)

			// Fund the address, spend that output paying only a
			// stranger, then fund it again.
			spent := recoveryFund(script, 50_000)
			meta := idx.addBlock(t, 20, spent)
			idx.addTx(t, spent, 20, meta.Hash)

			spend := wire.NewMsgTx(2)
			spend.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash: spent.TxHash(),
				},
			})
			spend.AddTxOut(wire.NewTxOut(49_000, strangerScript))
			meta = idx.addBlock(t, 21, spend)
			idx.addTx(t, spend, 21, meta.Hash, script)

			kept := recoveryFund(script, 30_000)
			meta = idx.addBlock(t, 22, kept)
			idx.addTx(t, kept, 22, meta.Hash)

			requireOnlyKept := func(w *Wallet) {
				ctx, cancel := context.WithTimeout(
					t.Context(), 30*time.Second,
				)
				defer cancel()
				require.NoError(
					t, w.WaitForSync(ctx),
					"wallet did not finish syncing",
				)

				utxos, err := w.BtcWallet.ListUnspentWitness(
					0, math.MaxInt32, "default",
				)
				require.NoError(t, err)
				require.Len(t, utxos, 1)
				require.Equal(
					t, kept.TxHash(),
					utxos[0].OutPoint.Hash,
				)
			}

			// Restore into an empty directory.
			dir := t.TempDir()
			cfg = config(dir)
			test.source(&cfg)
			restored, err := New(cfg)
			require.NoError(t, err)
			require.NoError(t, restored.Start())
			requireOnlyKept(restored)
			restored.Stop()

			// Recovery runs again on every start, so the reopened
			// wallet must get through it as well.
			reopened, err := New(config(dir))
			require.NoError(t, err)
			require.NoError(t, reopened.Start())
			requireOnlyKept(reopened)
			reopened.Stop()
		})
	}
}
