//go:build wavewalletrpc && swapruntime

package wavewalletdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/lightninglabs/wavelength/callbacksigner"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/stretchr/testify/require"
)

// censusHost answers a hosted wallet's requests from a root key and counts
// them, by kind, family and tag, which is what a threshold group would pay.
type censusHost struct {
	t      *testing.T
	root   *hdkeychain.ExtendedKey
	coin   uint32
	mu     sync.Mutex
	counts map[string]int
}

// key derives the private key a request names, as a btcwallet of root would.
func (h *censusHost) key(req *callbacksigner.Request) (*btcec.PrivateKey,
	error) {

	const hardened = hdkeychain.HardenedKeyStart
	path := []uint32{1017 + hardened, h.coin + hardened,
		uint32(req.Family) + hardened, 0, req.Index}
	if req.Family < 0 {
		path = []uint32{86 + hardened, hardened, hardened, req.Branch,
			req.Index}
	}

	key := h.root
	for _, step := range path {
		var err error
		key, err = key.Derive(step)
		if err != nil {
			return nil, err
		}
	}

	return key.ECPrivKey()
}

// Handle implements callbacksigner.Host.
func (h *censusHost) Handle(raw []byte) ([]byte, error) {
	var req callbacksigner.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	h.mu.Lock()
	h.counts[fmt.Sprintf("%s family=%d tag=%q method=%s", req.Kind,
		req.Family, req.Tag, req.Method)]++
	h.mu.Unlock()

	priv, err := h.key(&req)
	if err != nil {
		return nil, err
	}

	var resp callbacksigner.Response
	switch req.Kind {
	case callbacksigner.KindMessage:
		msg, err := hex.DecodeString(req.Message)
		if err != nil {
			return nil, err
		}
		switch {
		case req.Schnorr:
			digest := sha256.Sum256(msg)
			if req.Tag != "" {
				digest = *chainhash.TaggedHash(
					[]byte(req.Tag), msg,
				)
			}
			sig, err := schnorr.Sign(priv, digest[:])
			if err != nil {
				return nil, err
			}
			resp.Signature = hex.EncodeToString(sig.Serialize())

		case req.Compact:
			digest := chainhash.HashB(msg)
			if req.DoubleHash {
				digest = chainhash.DoubleHashB(msg)
			}
			sig := ecdsa.SignCompact(priv, digest, true)
			resp.Signature = hex.EncodeToString(sig)

		default:
			digest := chainhash.HashB(msg)
			if req.DoubleHash {
				digest = chainhash.DoubleHashB(msg)
			}
			sig := ecdsa.Sign(priv, digest)
			resp.Signature = hex.EncodeToString(sig.Serialize())
		}

	case callbacksigner.KindInput:
		digest, err := hex.DecodeString(req.Digest)
		if err != nil {
			return nil, err
		}
		if req.Method == callbacksigner.MethodBIP86 {
			priv = txscript.TweakTaprootPrivKey(*priv, nil)
		}
		sig, err := schnorr.Sign(priv, digest)
		if err != nil {
			return nil, err
		}
		resp.Signature = hex.EncodeToString(sig.Serialize())

	default:
		return nil, fmt.Errorf("census host does not answer %s",
			req.Kind)
	}

	return json.Marshal(&resp)
}

// TestHostedSignetCensus opens a throwaway hosted wallet against the public
// signet operator, leaves it idle, then asks the real swap server for an
// invoice under a vHTLC key that is not the wallet's identity. It holds no
// coins, so it cannot get further than that. It touches the network, and only
// runs when asked for.
func TestHostedSignetCensus(t *testing.T) {
	if os.Getenv("WAVELENGTH_SIGNET_PROBE") == "" {
		t.Skip("set WAVELENGTH_SIGNET_PROBE to run against signet")
	}

	params := &chaincfg.SigNetParams
	seed := make([]byte, 32)
	copy(seed, []byte(fmt.Sprintf("census %d", time.Now().UnixNano())))
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)

	keys, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	manifest, err := walletdesc.FormatManifest(keys, params)
	require.NoError(t, err)
	auth, err := walletdesc.FormatAuthKeys(keys)
	require.NoError(t, err)

	host := &censusHost{
		t: t, root: root, coin: 1, counts: make(map[string]int),
	}
	cfg := Config{
		DataDir:    t.TempDir(),
		Network:    "signet",
		DebugLevel: "warn",
		RemoteSigner: &RemoteSignerConfig{
			Host:           host,
			RequestTimeout: 30 * time.Second,
		},
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 8*time.Minute,
	)
	defer cancel()

	report := func(stage string, began time.Time) {
		host.mu.Lock()
		defer host.mu.Unlock()

		lines := make([]string, 0, len(host.counts))
		for line, count := range host.counts {
			lines = append(lines, fmt.Sprintf("%5d  %s", count, line))
		}
		sort.Strings(lines)
		t.Logf("=== %s after %s", stage, time.Since(began).Round(time.Second))
		for _, line := range lines {
			t.Log(line)
		}
	}

	began := time.Now()
	client, opened, err := StartWatchOnlyWallet(
		ctx, cfg, WatchOnlyWalletRequest{
			Manifest:       manifest,
			AuthKeys:       auth,
			WalletPassword: bytes.Repeat([]byte("p"), 12),
			RecoverState:   true,
			RecoveryWindow: 3,
		},
	)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	t.Logf("opened: imported=%v manifest=%s", opened.Imported,
		opened.ManifestHash)
	report("open with a recovery window of 3", began)

	time.Sleep(60 * time.Second)
	report("after an idle minute", began)

	result, err := client.Receive(ctx, ReceiveRequest{
		AmountSat: 1_000, Memo: "census",
	})
	if err != nil {
		t.Logf("RECEIVE REFUSED: %v", err)
	} else {
		t.Logf("RECEIVE ACCEPTED: invoice %s", result.Invoice)
	}
	report("after asking for an invoice", began)

	time.Sleep(30 * time.Second)
	report("thirty seconds later", began)
}
