package lwwallet

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	btcaddr "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/blockcache"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/stretchr/testify/assert"
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

// TestRestoredWalletSeesLaterPayments restores a wallet whose addresses have
// never been used, then mines payments to addresses it has not issued. They
// must be credited: another copy of the wallet, or an earlier life of this
// one, may have handed those addresses out, and a payer can be mid-flight
// while the restore runs. Nothing else tells btcwallet about them, because
// once recovery ends it watches only the addresses it has issued.
func TestRestoredWalletSeesLaterPayments(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams

	const window = 10

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 41)
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
					PollInterval:   20 * time.Millisecond,
					RecoveryWindow: window,
					DBDir:          dir,
					Log:            fn.None[btclog.Logger](),
				}
			}

			// A throwaway wallet supplies the receive addresses in
			// order, so the wallet under test has issued none.
			cfg := config(t.TempDir())
			test.source(&cfg)
			first, err := New(cfg)
			require.NoError(t, err)
			require.NoError(t, first.Start())
			scripts := make([][]byte, 2*window+5)
			for i := range scripts {
				addr, err := first.NewAddress(t.Context())
				require.NoError(t, err)
				scripts[i], err = txscript.PayToAddrScript(addr)
				require.NoError(t, err)
			}
			first.Stop()

			dir := t.TempDir()
			cfg = config(dir)
			test.source(&cfg)
			restored, err := New(cfg)
			require.NoError(t, err)
			require.NoError(t, restored.Start())
			defer func() {
				if restored != nil {
					restored.Stop()
				}
			}()

			ctx, cancel := context.WithTimeout(
				t.Context(), 30*time.Second,
			)
			defer cancel()
			require.NoError(t, restored.WaitForSync(ctx))

			height := int32(20)
			mine := func(txs ...*wire.MsgTx) {
				meta := idx.addBlock(t, height, txs...)
				for _, tx := range txs {
					idx.addTx(
						t, tx, int64(height), meta.Hash,
					)
				}
				height++
			}
			requireUtxos := func(w *Wallet, want ...*wire.MsgTx) {
				t.Helper()

				wantHashes := make([]chainhash.Hash, len(want))
				for i, tx := range want {
					wantHashes[i] = tx.TxHash()
				}
				require.Eventually(t, func() bool {
					btcw := w.BtcWallet
					utxos, err := btcw.ListUnspentWitness(
						0, math.MaxInt32, "default",
					)
					if err != nil {
						return false
					}

					got := make(
						[]chainhash.Hash, len(utxos),
					)
					for i, utxo := range utxos {
						got[i] = utxo.OutPoint.Hash
					}

					return assert.ElementsMatch(
						noopT{}, wantHashes, got,
					)
				}, 30*time.Second, 20*time.Millisecond)
			}

			// A payment to the very first address, which is what a
			// deposit pending during the restore looks like.
			atFirst := recoveryFund(scripts[0], 50_000)
			mine(atFirst)
			requireUtxos(restored, atFirst)

			// Payments in one block where the second brings the
			// first inside the window.
			atMiddle := recoveryFund(scripts[window-1], 40_000)
			chained := recoveryFund(scripts[window+3], 30_000)
			mine(chained, atMiddle)
			requireUtxos(restored, atFirst, atMiddle, chained)

			// An address outside the window stays out of reach,
			// because the window is the gap limit a restore
			// honours.
			outside := recoveryFund(scripts[2*window+4], 20_000)
			mine(outside)
			marker := recoveryFund(scripts[window+4], 10_000)
			mine(marker)
			requireUtxos(
				restored, atFirst, atMiddle, chained, marker,
			)

			// A spend paying the wallet nothing is seen, so the
			// claimed output is tracked like any other.
			strangerScript, _ := testScript(t, 0x7b)
			spend := wire.NewMsgTx(2)
			spend.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash: atFirst.TxHash(),
				},
			})
			spend.AddTxOut(wire.NewTxOut(49_000, strangerScript))
			mine(spend)
			requireUtxos(restored, atMiddle, chained, marker)

			// A change address is claimed as well, since a spend
			// made by another copy of the wallet pays one.
			changeScripts, err := restored.deriveBranchScripts(
				scopeBranch{
					scope:  waddrmgr.KeyScopeBIP0086,
					branch: internalBranch,
				}, 2, 1,
			)
			require.NoError(t, err)
			change := recoveryFund(changeScripts[0], 5_000)
			mine(change)
			requireUtxos(
				restored, atMiddle, chained, marker, change,
			)

			// Addresses already claimed are never handed out again.
			next, err := restored.NewAddress(t.Context())
			require.NoError(t, err)
			nextScript, err := txscript.PayToAddrScript(next)
			require.NoError(t, err)
			require.Equal(t, scripts[window+5], nextScript)

			// All of it survives a restart.
			restored.Stop()
			reopened, err := New(config(dir))
			restored = nil
			require.NoError(t, err)
			require.NoError(t, reopened.Start())
			defer reopened.Stop()
			requireUtxos(
				reopened, atMiddle, chained, marker, change,
			)
		})
	}
}

// TestAddressLookaheadOnWatchOnlyWallet runs the lookahead over a watch-only
// wallet, whose address manager holds no private keys and is never unlocked.
func TestAddressLookaheadOnWatchOnlyWallet(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 71)
	}

	keys := taprootOnlyAccountKeys(t, params, seed[:])
	bundle, err := keys.Bundle()
	require.NoError(t, err)

	opts, _, err := newWalletLoaderOptions(Config{DBDir: t.TempDir()})
	require.NoError(t, err)
	btcw, err := walletcore.NewWatchOnlyBtcWallet(
		btcwallet.Config{
			PublicPass:    recoveryTestPassword,
			NetParams:     params,
			CoinType:      walletcore.CoinTypeForNet(params),
			LoaderOptions: opts,
		}, bundle, blockcache.NewBlockCache(10),
	)
	require.NoError(t, err)

	wallet := btcw.InternalWallet()
	defer func() {
		require.NoError(t, wallet.Database().Close())
	}()
	mgr := wallet.AddrManager()
	require.True(t, mgr.WatchOnly())
	scoped, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0086)
	require.NoError(t, err)

	receiveScript := func(index uint32) []byte {
		var addr btcaddr.Address
		err := walletdb.View(
			wallet.Database(), func(tx walletdb.ReadTx) error {
				var err error
				addr, err = deriveChildAddress(
					tx.ReadBucket(waddrmgrNamespaceKey),
					scoped, externalBranch, index,
				)

				return err
			},
		)
		require.NoError(t, err)

		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		return script
	}
	block := func(scripts ...[]byte) *wire.MsgBlock {
		msg := &wire.MsgBlock{}
		for i, script := range scripts {
			msg.Transactions = append(
				msg.Transactions,
				recoveryFund(
					script, int64(1_000+i),
				),
			)
		}

		return msg
	}

	lookahead := newAddressLookahead(wallet, 5)

	// Nothing paid, nothing claimed.
	claimed, err := lookahead.claim(block())
	require.NoError(t, err)
	require.Empty(t, claimed)

	// A payment issues its address and those before it.
	claimed, err = lookahead.claim(block(receiveScript(3)))
	require.NoError(t, err)
	require.Len(t, claimed, 4)

	// Seeing it again claims nothing new, which is what a block delivered
	// a second time after a reorg looks like.
	claimed, err = lookahead.claim(block(receiveScript(3)))
	require.NoError(t, err)
	require.Empty(t, claimed)

	// Next index 4 and a window of 5 cover indexes 4 to 8.
	claimed, err = lookahead.claim(block(receiveScript(9)))
	require.NoError(t, err)
	require.Empty(t, claimed)

	claimed, err = lookahead.claim(block(receiveScript(8)))
	require.NoError(t, err)
	require.Len(t, claimed, 5)
}

// noopT discards the failures of an assertion used as a predicate.
type noopT struct{}

// Errorf implements assert.TestingT.
func (noopT) Errorf(string, ...interface{}) {}
