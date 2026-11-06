//go:build wavewalletrpc && swapruntime

package wavewalletdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bridgeOpen is what the signer, in another process, says to open.
type bridgeOpen struct {
	SignerURL string `json:"signer_url"`
	Manifest  string `json:"manifest"`
	AuthKeys  string `json:"auth_keys"`
	Password  string `json:"password"`
	Identity  string `json:"identity"`
}

// bridgeHost hands a hosted wallet's requests to a signer in another process,
// which may be in another language and is the thing under test.
type bridgeHost struct {
	url    string
	client *http.Client
}

// Handle implements callbacksigner.Host.
func (h *bridgeHost) Handle(raw []byte) ([]byte, error) {
	resp, err := h.client.Post(
		h.url, "application/json", bytes.NewReader(raw),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer refused: %s", body)
	}

	return body, nil
}

// TestHostedBridge runs a real hosted wallet on signet for a signer in another
// process, and takes commands over HTTP until told to stop. It is a harness and
// proves nothing itself: whoever drives it reads the wallet's state, and real
// coins may be sent to the addresses it hands out.
func TestHostedBridge(t *testing.T) {
	dir := os.Getenv("WAVELENGTH_BRIDGE_DIR")
	if dir == "" {
		t.Skip("set WAVELENGTH_BRIDGE_DIR to run against signet")
	}

	var opening bridgeOpen
	deadline := time.Now().Add(20 * time.Minute)
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "open.json"))
		if err == nil {
			require.NoError(t, json.Unmarshal(raw, &opening))
			break
		}
		require.True(t, time.Now().Before(deadline), "nobody said what to open")
		time.Sleep(time.Second)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		DataDir:    filepath.Join(dir, "daemon"),
		Network:    "signet",
		DebugLevel: "info",
		RemoteSigner: &RemoteSignerConfig{
			Host: &bridgeHost{
				url:    opening.SignerURL,
				client: &http.Client{Timeout: 115 * time.Second},
			},
			RequestTimeout: 110 * time.Second,
		},
	}
	began := time.Now()
	client, opened, err := StartWatchOnlyWallet(
		ctx, cfg, WatchOnlyWalletRequest{
			Manifest:       []byte(opening.Manifest),
			AuthKeys:       []byte(opening.AuthKeys),
			WalletPassword: []byte(opening.Password),
		},
	)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	t.Logf("opened after %s: imported=%v manifest=%s",
		time.Since(began).Round(time.Second), opened.Imported,
		opened.ManifestHash)

	stop := make(chan struct{})
	mux := http.NewServeMux()
	serve := func(path string, do func(*http.Request) (any, error)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			result, err := do(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)

				return
			}
			_ = json.NewEncoder(w).Encode(result)
		})
	}
	serve("/info", func(r *http.Request) (any, error) {
		return client.GetInfo(r.Context())
	})
	serve("/balance", func(r *http.Request) (any, error) {
		return client.Balance(r.Context())
	})
	serve("/status", func(r *http.Request) (any, error) {
		return client.Status(r.Context())
	})
	serve("/deposit", func(r *http.Request) (any, error) {
		sat, err := strconv.ParseUint(r.URL.Query().Get("sat"), 10, 64)
		if err != nil {
			return nil, err
		}

		return client.Deposit(r.Context(), DepositRequest{
			AmountSatHint: sat,
		})
	})
	serve("/vtxos", func(r *http.Request) (any, error) {
		return client.List(r.Context(), ListRequest{View: ListViewVTXOs})
	})
	serve("/activity", func(r *http.Request) (any, error) {
		return client.List(r.Context(), ListRequest{})
	})
	serve("/exit", func(r *http.Request) (any, error) {
		return client.Exit(r.Context(), ExitRequest{
			Outpoint:    r.URL.Query().Get("outpoint"),
			Destination: r.URL.Query().Get("destination"),
		})
	})
	serve("/stop", func(*http.Request) (any, error) {
		close(stop)

		return "stopping", nil
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	ready, err := json.Marshal(map[string]any{
		"port":          listener.Addr().(*net.TCPAddr).Port,
		"manifest_hash": opened.ManifestHash,
		"identity":      opened.IdentityPubKey,
		"seconds":       time.Since(began).Seconds(),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "ready.json"), ready, 0o600,
	))

	select {
	case <-stop:
	case err := <-client.Wait():
		t.Fatalf("the daemon stopped: %v", err)
	}
}
