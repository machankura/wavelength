//go:build mobile && wavewalletrpc && swapruntime

package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lightninglabs/wavelength/sdk/wavewalletdk"
)

// watchOnlyWalletStartRequest is the private mobile transport envelope for
// StartWatchOnlyWallet. Config is the final daemon configuration and must
// name the remote signer. Bundle or Manifest is the signer's export as
// text; AuthKeys and a minimal Bundle hold private keys, and WalletPassword
// is standard base64.
type watchOnlyWalletStartRequest struct {
	Config json.RawMessage `json:"config"`

	Bundle           string `json:"bundle,omitempty"`
	Manifest         string `json:"manifest,omitempty"`
	AuthKeys         string `json:"auth_keys,omitempty"`
	OverrideIdentity bool   `json:"override_identity,omitempty"`

	WalletPassword   []byte `json:"wallet_password"`
	BirthdayUnix     int64  `json:"birthday_unix,omitempty"`
	ExpectedIdentity string `json:"expected_identity_pubkey,omitempty"`
	RecoverState     bool   `json:"recover_state,omitempty"`
	RecoveryWindow   uint32 `json:"recovery_window,omitempty"`
}

// StartWatchOnlyWallet is the private binding ABI for atomically booting an
// embedded daemon at a host-selected data directory and importing or
// unlocking a watch-only wallet whose fund keys live on a remote signer. It
// follows the lifecycle contract of StartDescriptorWallet: one wallet at a
// time, a successful response means wallet-dependent actors and mailbox
// ingress are online, and any failure resets the lifecycle to stopped.
func StartWatchOnlyWallet(reqJSON []byte) ([]byte, error) {
	var result *wavewalletdk.WatchOnlyWalletOpenResult
	err := startEmbedded(func(startCtx, operationCtx context.Context) (
		*wavewalletdk.Client, error) {

		cfg, req, err := parseWatchOnlyWalletStartRequest(reqJSON)
		if err != nil {
			return nil, fmt.Errorf("parse watch-only wallet "+
				"request: %w", err)
		}
		defer clear(req.WalletPassword)

		client, openResult, err :=
			wavewalletdk.StartWatchOnlyWalletWithContexts(
				startCtx, operationCtx, cfg, req,
				mobileStartOptions(cfg)...,
			)
		if err != nil {
			return nil, fmt.Errorf("start watch-only wallet: %w",
				err)
		}

		result = openResult

		return client, nil
	})
	if err != nil {
		return nil, err
	}

	return marshal(result)
}

// parseWatchOnlyWalletStartRequest separates the final startup config from
// the watch-only inputs. The SDK validates the inputs themselves.
func parseWatchOnlyWalletStartRequest(reqJSON []byte) (wavewalletdk.Config,
	wavewalletdk.WatchOnlyWalletRequest, error) {

	var envelope watchOnlyWalletStartRequest
	if err := json.Unmarshal(reqJSON, &envelope); err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			fmt.Errorf("decode request: %w", err)
	}

	nested := bytes.TrimSpace(envelope.Config)
	if len(nested) == 0 || bytes.Equal(nested, []byte("null")) {
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			errors.New("config must be a nested object")
	}

	var mobileCfg mobileConfig
	if err := json.Unmarshal(nested, &mobileCfg); err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			fmt.Errorf("decode nested config: %w", err)
	}
	switch {
	case mobileCfg.DataDir == "":
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			errors.New("config.data_dir must select the final " +
				"wallet directory")

	case mobileCfg.RemoteSignerRPCHost == "":
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			errors.New("config.remote_signer_rpc_host is " +
				"required for a watch-only wallet")

	case envelope.BirthdayUnix < 0:
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{},
			errors.New("birthday_unix must not be negative")
	}

	cfg, err := parseConfig(string(nested))
	if err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.WatchOnlyWalletRequest{}, err
	}

	req := wavewalletdk.WatchOnlyWalletRequest{
		Bundle:                 []byte(envelope.Bundle),
		Manifest:               []byte(envelope.Manifest),
		AuthKeys:               []byte(envelope.AuthKeys),
		OverrideIdentity:       envelope.OverrideIdentity,
		WalletPassword:         envelope.WalletPassword,
		ExpectedIdentityPubKey: envelope.ExpectedIdentity,
		RecoverState:           envelope.RecoverState,
		RecoveryWindow:         envelope.RecoveryWindow,
	}
	if envelope.BirthdayUnix > 0 {
		req.Birthday = time.Unix(envelope.BirthdayUnix, 0)
	}

	return cfg, req, nil
}
