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

// descriptorWalletStartRequest is the private mobile/WASM transport envelope
// for StartDescriptorWallet. Config is the final daemon configuration,
// including its already-selected data directory. Descriptors are private
// output descriptors and are as sensitive as a seed.
type descriptorWalletStartRequest struct {
	Config json.RawMessage `json:"config"`

	Descriptors      []string `json:"descriptors"`
	BirthdayUnix     int64    `json:"birthday_unix,omitempty"`
	ExpectedIdentity string   `json:"expected_identity_pubkey,omitempty"`
	RecoverState     bool     `json:"recover_state,omitempty"`
	RecoveryWindow   uint32   `json:"recovery_window,omitempty"`
}

// StartDescriptorWallet is the private binding ABI for atomically booting an
// embedded daemon at a host-selected data directory and importing or
// unlocking its wallet from private output descriptors. It follows the same
// lifecycle contract as StartExternalSeedWallet: typed host SDKs route it
// through the same lifecycle queue and runtime lock as Start and Stop, only
// one wallet may be active at a time, and a successful response means
// wallet-dependent actors and mailbox ingress are online. Any startup,
// import, unlock, recovery or identity-check failure resets the lifecycle to
// stopped.
func StartDescriptorWallet(reqJSON []byte) ([]byte, error) {
	var result *wavewalletdk.DescriptorWalletOpenResult
	err := startEmbedded(func(startCtx, operationCtx context.Context) (
		*wavewalletdk.Client, error) {

		cfg, req, err := parseDescriptorWalletStartRequest(reqJSON)
		if err != nil {
			return nil, fmt.Errorf("parse descriptor wallet "+
				"request: %w", err)
		}

		client, openResult, err :=
			wavewalletdk.StartDescriptorWalletWithContexts(
				startCtx, operationCtx, cfg, req,
				mobileStartOptions(cfg)...,
			)
		if err != nil {
			return nil, fmt.Errorf("start descriptor wallet: %w",
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

// parseDescriptorWalletStartRequest separates the final startup config from
// the descriptors. Only the nested config shape is accepted so the selected
// state directory cannot be confused with transport-level fields.
func parseDescriptorWalletStartRequest(reqJSON []byte) (wavewalletdk.Config,
	wavewalletdk.DescriptorWalletRequest, error) {

	var envelope descriptorWalletStartRequest
	if err := json.Unmarshal(reqJSON, &envelope); err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			fmt.Errorf("decode request: %w", err)
	}

	nested := bytes.TrimSpace(envelope.Config)
	if len(nested) == 0 || bytes.Equal(nested, []byte("null")) {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			errors.New("config must be a nested object")
	}

	var mobileCfg mobileConfig
	if err := json.Unmarshal(nested, &mobileCfg); err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			fmt.Errorf("decode nested config: %w", err)
	}
	if mobileCfg.DataDir == "" {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			errors.New("config.data_dir must select the final " +
				"wallet directory")
	}

	cfg, err := parseConfig(string(nested))
	if err != nil {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{}, err
	}

	if len(envelope.Descriptors) == 0 {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			errors.New("descriptors must not be empty")
	}
	if envelope.BirthdayUnix < 0 {
		return wavewalletdk.Config{},
			wavewalletdk.DescriptorWalletRequest{},
			errors.New("birthday_unix must not be negative")
	}

	req := wavewalletdk.DescriptorWalletRequest{
		Descriptors:            envelope.Descriptors,
		ExpectedIdentityPubKey: envelope.ExpectedIdentity,
		RecoverState:           envelope.RecoverState,
		RecoveryWindow:         envelope.RecoveryWindow,
	}
	if envelope.BirthdayUnix > 0 {
		req.Birthday = time.Unix(envelope.BirthdayUnix, 0)
	}

	return cfg, req, nil
}

// ListWalletDescriptors returns the active wallet's descriptors. The request
// JSON mirrors wavewalletdk.ListWalletDescriptorsRequest.
func ListWalletDescriptors(reqJSON []byte) ([]byte, error) {
	client, parentCtx, err := activeClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := readContext(parentCtx)
	defer cancel()

	var req wavewalletdk.ListWalletDescriptorsRequest
	if err := decode(reqJSON, &req); err != nil {
		return nil, err
	}

	res, err := client.ListWalletDescriptors(ctx, req)
	if err != nil {
		return nil, err
	}

	return marshal(res)
}
