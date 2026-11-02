//go:build systest

package systest

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/wavelength/db"
	"github.com/lightninglabs/wavelength/harness"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/lwwallet"
	"github.com/lightninglabs/wavelength/vtxo"
	"github.com/lightninglabs/wavelength/walletcore"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// remoteBoardAmountSat funds the boarding address that joins a round.
	remoteBoardAmountSat = 150_000

	// remoteExitAmountSat funds the boarding address that is swept back
	// through its CSV exit path. It differs from remoteBoardAmountSat so
	// the sweep preview can tell the two outputs apart.
	remoteExitAmountSat = 70_000

	// signerSamples is how many times each signing operation is timed.
	signerSamples = 20

	// remoteSignerRequestTimeout is lnd's default bound on one remote
	// signer request (remotesigner.timeout). A remote signature slower
	// than this fails inside lnd before waved's own timeouts apply.
	remoteSignerRequestTimeout = 5 * time.Second

	// remoteBoardingExitDelay is the fake operator's boarding CSV delay,
	// matching BoardingExitDelay in newDirectedSendFixtureWithSetup.
	remoteBoardingExitDelay = 144

	// roundJoinAuthKeyFamily is the round join authorization key family,
	// unexported in the round package (round/join_auth.go).
	roundJoinAuthKeyFamily keychain.KeyFamily = 43

	// roundAdmissionBudget is the default accepted-round participation
	// budget from docs/round_admission_deadlines.md.
	roundAdmissionBudget = 30 * time.Minute
)

// remoteSignerNodes are the two lnd nodes behind a remote-signing setup: the
// watch-only node waved talks to and the signer that holds the keys.
type remoteSignerNodes struct {
	watchOnly *harness.LndInstance
	signer    *harness.LndInstance
}

// newRemoteSignerFixture starts a full waved instance with wallet.type=lnd
// against a watch-only lnd whose private keys live in a separate lnd remote
// signer, so every signature waved asks for crosses the remote signer RPC.
func newRemoteSignerFixture(t *testing.T) (*directedSendFixture,
	*remoteSignerNodes) {

	t.Helper()

	nodes := &remoteSignerNodes{}
	fixture := newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			nodes.watchOnly = h.Harness.StartAdditionalWatchOnlyLND(
				"watch-only",
			)
			nodes.signer = h.Harness.GetAdditionalLND(
				"watch-only-signer",
			)

			cfg.Lnd.Host = net.JoinHostPort(
				"localhost", nodes.watchOnly.GRPCPort,
			)
			cfg.Lnd.TLSPath = nodes.watchOnly.TLSCert
			cfg.Lnd.MacaroonPath = nodes.watchOnly.Macaroon
		},
	)

	return fixture, nodes
}

// TestRemoteSignerDaemon runs waved with wallet.type=lnd against a watch-only
// lnd paired with an lnd remote signer. It drives every fund-moving flow the
// fake operator can complete: boarding into a round, an out-of-round send,
// and a unilateral exit of a boarding output through its CSV path. It also
// times the signer operations a round needs, through the remote signer and
// against the signer node directly, and checks the remote cost fits the
// round admission budget.
func TestRemoteSignerDaemon(t *testing.T) {
	ParallelN(t)

	fixture, nodes := newRemoteSignerFixture(t)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	ownedOutpoint := seedSignerOwnedVTXO(t, fixture, nodes.signer)
	requireSignerIdentity(t, fixture.client, nodes.signer)
	runRemoteSignerFlows(t, fixture, ownedOutpoint)

	// Signing latency: time the operations a round runs per signature,
	// through the watch-only node (remote) and on the signer node itself
	// (local), so the difference is the remote signer hop.
	remote := measureRoundSigning(ctx, t, nodes.watchOnly, nodes.signer)
	local := measureRoundSigning(ctx, t, nodes.signer, nodes.signer)

	for _, op := range []string{opJoinAuth, opMuSig2} {
		t.Logf(
			"%s: remote p50=%v p95=%v max=%v, local p50=%v p95=%v",
			op, percentile(remote[op], 50),
			percentile(remote[op], 95), slices.Max(remote[op]),
			percentile(local[op], 50), percentile(local[op], 95),
		)

		require.Less(
			t, percentile(remote[op], 95),
			remoteSignerRequestTimeout, "%s p95 exceeds lnd's "+
				"remote signer timeout", op,
		)
	}

	// A wallet signs one join authorization per round and one MuSig2
	// partial signature per tree node on each of its leaves' paths. A
	// wallet with 32 leaves in a 4096-leaf tree signs at most 32*12 nodes;
	// forfeits are SignOutputRaw calls of the same cost class as the
	// MuSig2 step, so count one per leaf.
	const (
		leaves    = 32
		treeDepth = 12
	)
	perRound := percentile(remote[opJoinAuth], 95) +
		time.Duration(leaves*treeDepth+leaves)*
			percentile(remote[opMuSig2], 95)
	t.Logf(
		"projected remote signing per round (%d leaves, depth %d, "+
			"p95): %v of a %v budget", leaves, treeDepth, perRound,
		roundAdmissionBudget,
	)
	require.Less(t, perRound, roundAdmissionBudget/10)
}

// seedSignerOwnedVTXO replaces the fixture's seeded VTXO with one owned by
// the signer's key and relaunches the daemon, returning its outpoint.
func seedSignerOwnedVTXO(t *testing.T, fixture *directedSendFixture,
	signer *harness.LndInstance) wire.OutPoint {

	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	// The fixture seeds a VTXO paying a random key. The watch-only node
	// verifies every signature the remote signer returns, so a spend of
	// that VTXO fails where a plain lnd would return an unusable
	// signature. Retire it and seed one the wallet owns, at the locator
	// the daemon will ask the signer for.
	ownerKey, err := signer.Client.WalletKit.DeriveKey(
		ctx, &keychain.KeyLocator{
			Family: types.VTXOOwnerKeyFamily,
			Index:  7,
		},
	)
	require.NoError(t, err)

	fixture.shutdown()
	setSeededVTXOStatus(
		t, fixture.cfg, fixture.seededOutpoint, vtxo.VTXOStatusSpent,
	)
	ownedOutpoint := seedVTXOWithOwner(
		t, fixture.cfg, fixture.operatorKey, *ownerKey,
		btcutil.Amount(testSeededAmountSat),
		"remote-owned", vtxo.VTXOStatusLive,
	)
	fixture.launch()

	return ownedOutpoint
}

// requireSignerIdentity checks the daemon's identity key is the signer's
// family 6 index 0 key.
func requireSignerIdentity(t *testing.T, client waverpc.DaemonServiceClient,
	signer *harness.LndInstance) {

	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	// The daemon identity (family 6, index 0) is derived through the
	// watch-only node, so it must equal the signer's key: the watch-only
	// node holds only the imported account xpubs.
	info, err := client.GetInfo(ctx, &waverpc.GetInfoRequest{})
	require.NoError(t, err)

	signerIdentity, err := signer.Client.WalletKit.DeriveKey(
		ctx, &keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	require.NoError(t, err)
	require.Equal(
		t,
		hex.EncodeToString(
			signerIdentity.PubKey.SerializeCompressed(),
		),
		info.GetIdentityPubkey(),
	)
}

// runRemoteSignerFlows drives every fund-moving flow the fake operator can
// carry, each signed through the remote signer: a board up to the JoinRound
// request, an out-of-round send of ownedOutpoint up to SubmitPackage, and a
// matured boarding output swept on chain through its exit leaf.
func runRemoteSignerFlows(t *testing.T, fixture *directedSendFixture,
	ownedOutpoint wire.OutPoint) {

	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	h := fixture.harness.Harness
	client := fixture.client

	// Board: fund a boarding address (family 42), wait for the daemon to
	// see it confirmed, and join a round. The JoinRound request carries
	// the boarding intent signed through the remote signer.
	boardAddr, err := client.NewAddress(ctx, &waverpc.NewAddressRequest{})
	require.NoError(t, err)
	h.Faucet(boardAddr.GetAddress(), remoteBoardAmountSat)
	h.Generate(1)
	waitForBoardingConfirmed(t, client, remoteBoardAmountSat)

	start := time.Now()
	boardResp, err := client.Board(ctx, &waverpc.BoardRequest{})
	require.NoError(t, err)
	t.Logf(
		"Board returned %q in %v", boardResp.GetStatus(),
		time.Since(start),
	)

	require.Eventually(t, func() bool {
		return len(fixture.mailboxServer.joinRoundRequests()) >= 1
	}, 30*time.Second, 200*time.Millisecond,
		"board did not publish a JoinRound request")
	t.Logf("Board reached JoinRound egress in %v", time.Since(start))

	// Send out of round: the seeded VTXO (owner family 44) is spent in an
	// Ark transaction signed through the remote signer and submitted to
	// the operator. The spend is exact because a change output registers
	// a receive script with the indexer, which the fake operator does not
	// serve.
	recipientPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	start = time.Now()
	oorResp, err := client.SendOOR(ctx, &waverpc.SendOORRequest{
		Recipients: []*waverpc.Output{
			oorPolicyRecipient(
				t, recipientPriv.PubKey(), fixture.operatorKey,
				testSeededAmountSat,
			),
		},
	})
	require.NoError(t, err)
	require.Equal(t, "submitted", oorResp.GetStatus())

	require.Eventually(t, func() bool {
		return len(fixture.mailboxServer.oorSubmitPackages()) == 1
	}, 30*time.Second, 200*time.Millisecond,
		"OOR send did not reach the operator")
	require.Equal(
		t, waverpc.VTXOStatus_VTXO_STATUS_SPENDING, findVTXOByOutpoint(
			listAllVTXOs(t, client), ownedOutpoint,
		).GetStatus(),
	)
	t.Logf("SendOOR reached SubmitPackage in %v", time.Since(start))

	// Exit: fund a second boarding address after the round join, let its
	// CSV exit delay mature, and sweep it back to the wallet. The sweep is
	// an on-chain transaction whose input is signed by the remote signer
	// through the boarding exit leaf.
	exitAddr, err := client.NewAddress(ctx, &waverpc.NewAddressRequest{})
	require.NoError(t, err)
	h.Faucet(exitAddr.GetAddress(), remoteExitAmountSat)
	h.Generate(1)
	waitForBoardingConfirmed(
		t, client, remoteBoardAmountSat+remoteExitAmountSat,
	)
	h.Generate(remoteBoardingExitDelay)

	exitOutpoint := waitForSweepableAmount(
		t, client, remoteExitAmountSat,
	)

	start = time.Now()
	sweepResp, err := client.SweepBoardingUTXOs(
		ctx, &waverpc.SweepBoardingUTXOsRequest{
			Outpoints:          []string{exitOutpoint},
			Broadcast:          true,
			FeeRateSatPerVbyte: 2,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, sweepResp.GetTxid())
	t.Logf(
		"SweepBoardingUTXOs signed and broadcast %s in %v",
		sweepResp.GetTxid(), time.Since(start),
	)

	h.WaitMempoolTx(sweepResp.GetTxid())
	h.Generate(6)

	var sweepStatus string
	require.Eventually(t, func() bool {
		resp, err := client.ListBoardingSweeps(
			ctx, &waverpc.ListBoardingSweepsRequest{},
		)
		if err != nil {
			return false
		}

		for _, sweep := range resp.GetSweeps() {
			if sweep.GetTxid() == sweepResp.GetTxid() {
				sweepStatus = sweep.GetStatus()
			}
		}

		return sweepStatus == "confirmed"
	}, 30*time.Second, 200*time.Millisecond,
		"boarding sweep status %q, want confirmed", sweepStatus)
}

// Signing operations measured by measureRoundSigning.
const (
	opJoinAuth = "schnorr join auth (family 43)"
	opMuSig2   = "musig2 session+sign (family 45)"
)

// measureRoundSigning times the round signing operations against node. keys
// is the node that can derive public keys for the locators, which for a
// watch-only node is its signer.
func measureRoundSigning(ctx context.Context, t *testing.T,
	node, keys *harness.LndInstance) map[string][]time.Duration {

	t.Helper()

	signer := node.Client.Signer
	result := make(map[string][]time.Duration)

	authLoc := keychain.KeyLocator{
		Family: roundJoinAuthKeyFamily,
		Index:  0,
	}
	msg := chainhash.HashB([]byte("remote signer latency"))
	for range signerSamples {
		start := time.Now()
		_, err := signer.SignMessage(
			ctx, msg, authLoc, lndclient.SignSchnorr(nil),
		)
		require.NoError(t, err)
		result[opJoinAuth] = append(
			result[opJoinAuth], time.Since(start),
		)
	}

	treeLoc := keychain.KeyLocator{
		Family: types.VTXOSigningKeyFamily,
		Index:  0,
	}
	treeKey, err := keys.Client.WalletKit.DeriveKey(ctx, &treeLoc)
	require.NoError(t, err)

	for range signerSamples {
		cosigner, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		cosignerNonces, err := musig2.GenNonces(
			musig2.WithPublicKey(
				cosigner.PubKey(),
			),
		)
		require.NoError(t, err)

		start := time.Now()
		session, err := signer.MuSig2CreateSession(
			ctx, input.MuSig2Version100RC2, &treeLoc,
			[][]byte{
				treeKey.PubKey.SerializeCompressed(),
				cosigner.PubKey().SerializeCompressed(),
			},
		)
		require.NoError(t, err)

		_, err = signer.MuSig2RegisterNonces(
			ctx, session.SessionID,
			[][musig2.PubNonceSize]byte{cosignerNonces.PubNonce},
		)
		require.NoError(t, err)

		_, err = signer.MuSig2Sign(
			ctx, session.SessionID, chainhash.HashH(msg), true,
		)
		require.NoError(t, err)
		result[opMuSig2] = append(result[opMuSig2], time.Since(start))
	}

	return result
}

// percentile returns the p-th percentile of samples by nearest rank.
func percentile(samples []time.Duration, p int) time.Duration {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)

	rank := (p*len(sorted) + 99) / 100
	if rank < 1 {
		rank = 1
	}

	return sorted[rank-1]
}

// waitForBoardingConfirmed waits until the daemon reports want sats of
// confirmed boarding balance.
func waitForBoardingConfirmed(t *testing.T, client waverpc.DaemonServiceClient,
	want btcutil.Amount) {

	t.Helper()

	require.Eventually(t, func() bool {
		bal, err := client.GetBalance(
			t.Context(), &waverpc.GetBalanceRequest{},
		)
		if err != nil {
			return false
		}

		return bal.GetBoardingConfirmedSat() >= int64(want)
	}, 60*time.Second, 250*time.Millisecond,
		"boarding balance did not reach %v", want)
}

// waitForSweepableAmount previews a boarding sweep until an output of amount
// is mature, and returns its outpoint.
func waitForSweepableAmount(t *testing.T, client waverpc.DaemonServiceClient,
	amount btcutil.Amount) string {

	t.Helper()

	var outpoint string
	require.Eventually(t, func() bool {
		resp, err := client.SweepBoardingUTXOs(
			t.Context(), &waverpc.SweepBoardingUTXOsRequest{
				FeeRateSatPerVbyte: 2,
			},
		)
		if err != nil {
			return false
		}

		for _, out := range resp.GetSweepableOutputs() {
			if out.GetAmountSat() == int64(amount) {
				outpoint = out.GetOutpoint()

				return true
			}
		}

		return false
	}, 60*time.Second, 500*time.Millisecond,
		"no mature boarding output of %v", amount)

	return outpoint
}

// setSeededVTXOStatus changes a seeded VTXO's status in the daemon database
// while the daemon is not running.
func setSeededVTXOStatus(t *testing.T, cfg *waved.Config,
	outpoint wire.OutPoint, status vtxo.VTXOStatus) {

	t.Helper()

	sqliteStore, err := db.NewSqliteStore(
		db.DefaultSqliteConfig(
			cfg.NetworkDir(),
		),
		btclog.Disabled,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, sqliteStore.Close())
	}()

	store := db.NewStore(
		sqliteStore.DB, sqliteStore.Queries, sqliteStore.Backend(),
		btclog.Disabled,
	)
	err = store.NewVTXOStore(clock.NewDefaultClock()).UpdateVTXOStatus(
		t.Context(), outpoint, status,
	)
	require.NoError(t, err)
}

// nativeRemoteSignerPassword is the wallet password of the watch-only
// wallet in TestNativeRemoteSignerDaemon.
const nativeRemoteSignerPassword = "native-remote-signer-pw"

// signerBundle exports signer's accounts as the JSON `lncli wallet accounts
// list` prints, the form a user hands the daemon.
func signerBundle(ctx context.Context, t *testing.T,
	signer *harness.LndInstance) []byte {

	t.Helper()

	accounts, err := signer.Client.WalletKit.ListAccounts(
		ctx, "", walletrpc.AddressType_UNKNOWN,
	)
	require.NoError(t, err)

	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(
		&walletrpc.ListAccountsResponse{
			Accounts: accounts,
		},
	)
	require.NoError(t, err)

	return data
}

// newNativeRemoteSignerFixture starts a full waved instance with
// wallet.type=lwwallet and wallet.remotesigner pointing at a plain lnd used
// only as a signer: no lnd sits behind the daemon. The watch-only wallet is
// created from the signer's exported accounts before the daemon starts, and
// the daemon opens it with its password file.
func newNativeRemoteSignerFixture(t *testing.T) (*directedSendFixture,
	*harness.LndInstance) {

	t.Helper()

	var signer *harness.LndInstance
	fixture := newDirectedSendFixtureWithSetup(
		t, func(h *SysTestHarness, cfg *waved.Config) {
			ctx := h.Context()
			signer = h.Harness.StartAdditionalLND("signer")

			remote := &walletcore.RemoteSignerConfig{
				RPCHost: net.JoinHostPort(
					"localhost", signer.GRPCPort,
				),
				MacaroonPath: signer.Macaroon,
				TLSCertPath:  signer.TLSCert,
			}

			bundle, err := walletdesc.ParseWatchOnlyBundle(
				signerBundle(ctx, t, signer),
				&chaincfg.RegressionNetParams,
			)
			require.NoError(t, err)

			// Create the watch-only database the way the
			// daemon's InitWallet does, and start it once so the
			// signer check runs before the daemon ever does.
			require.NoError(t, os.MkdirAll(cfg.NetworkDir(), 0o700))
			w, err := lwwallet.New(lwwallet.Config{
				WatchOnly:    bundle,
				RemoteSigner: remote,
				WalletPassword: []byte(
					nativeRemoteSignerPassword,
				),
				EsploraURL:   h.Harness.EsploraURL,
				ChainParams:  &chaincfg.RegressionNetParams,
				PollInterval: time.Second,
				DBDir:        cfg.NetworkDir(),
			})
			require.NoError(t, err)
			require.NoError(t, w.Start())
			w.Stop()

			passwordFile := filepath.Join(t.TempDir(), "password")
			require.NoError(
				t,
				os.WriteFile(
					passwordFile,
					[]byte(nativeRemoteSignerPassword),
					0o600,
				),
			)

			cfg.Wallet.Type = waved.WalletTypeLwwallet
			cfg.Wallet.EsploraURL = h.Harness.EsploraURL
			cfg.Wallet.PollInterval = time.Second
			cfg.Wallet.PasswordFile = passwordFile
			cfg.Wallet.RemoteSigner = waved.RemoteSignerConfig{
				Enable:       true,
				RPCHost:      remote.RPCHost,
				MacaroonPath: remote.MacaroonPath,
				TLSCertPath:  remote.TLSCertPath,
			}
		},
	)

	return fixture, signer
}

// TestNativeRemoteSignerDaemon is the W0 scenario on the native watch-only
// backend: waved runs wallet.type=lwwallet with every private key on a
// remote signer and no lnd behind it. Identity derivation, boarding into a
// round, an out-of-round send and a boarding exit sweep all sign through
// the signer, and the daemon reports the signer's account descriptors.
func TestNativeRemoteSignerDaemon(t *testing.T) {
	ParallelN(t)

	fixture, signer := newNativeRemoteSignerFixture(t)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	ownedOutpoint := seedSignerOwnedVTXO(t, fixture, signer)
	requireSignerIdentity(t, fixture.client, signer)

	// The public descriptors come from the imported xpubs, so the BIP86
	// one must carry the signer's account key.
	descs, err := fixture.client.ListWalletDescriptors(
		ctx, &waverpc.ListWalletDescriptorsRequest{},
	)
	require.NoError(t, err)
	accounts, err := signer.Client.WalletKit.ListAccounts(
		ctx, "default", walletrpc.AddressType_TAPROOT_PUBKEY,
	)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.NotEmpty(t, descs.GetDescriptors())
	require.Contains(
		t,
		strings.Join(
			descs.GetDescriptors(),
			"\n",
		),
		accounts[0].GetExtendedPublicKey(),
	)

	runRemoteSignerFlows(t, fixture, ownedOutpoint)
}
