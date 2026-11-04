package wavewalletdk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/lightninglabs/wavelength/lib/keyfamily"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
)

// WatchOnlyWalletRequest opens a watch-only wallet at an explicit daemon
// data directory: one created from a remote signer's bundle (Bundle, full
// or minimal) or from a manifest with its authentication keys (Manifest
// and AuthKeys). Every fund signature comes from Config.RemoteSigner.
//
// WalletPassword protects the wallet database and, for a minimal bundle or
// a manifest, the authentication keys the daemon keeps; a watch-only
// wallet has no other secret to derive it from, so the host supplies it.
// The other fields behave as in DescriptorWalletRequest.
type WatchOnlyWalletRequest struct {
	Bundle           []byte
	Manifest         []byte
	AuthKeys         []byte
	OverrideIdentity bool

	WalletPassword         []byte
	Birthday               time.Time
	ExpectedIdentityPubKey string
	RecoverState           bool
	RecoveryWindow         uint32
}

// StartWatchOnlyWallet starts an embedded daemon at the explicit
// Config.DataDir with Config.RemoteSigner, then imports a fresh watch-only
// wallet from the request or unlocks the one already there. If opening
// fails, the newly started daemon is stopped before the error returns.
func StartWatchOnlyWallet(ctx context.Context, cfg Config,
	req WatchOnlyWalletRequest, opts ...Option) (*Client,
	*WatchOnlyWalletOpenResult, error) {

	return StartWatchOnlyWalletWithContexts(ctx, ctx, cfg, req, opts...)
}

// StartWatchOnlyWalletWithContexts starts an embedded daemon with startCtx
// and opens its watch-only wallet with openCtx, with the same readiness and
// rollback guarantees as StartDescriptorWalletWithContexts.
func StartWatchOnlyWalletWithContexts(startCtx, openCtx context.Context,
	cfg Config, req WatchOnlyWalletRequest, opts ...Option) (*Client,
	*WatchOnlyWalletOpenResult, error) {

	if err := validateHostOwnedWalletConfig(cfg, "watch-only"); err != nil {
		return nil, nil, err
	}

	daemonCfg, err := daemonConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve watch-only wallet "+
			"network: %w", err)
	}
	if daemonCfg.Wallet == nil || !daemonCfg.Wallet.RemoteSigner.Enable {
		return nil, nil, errors.New("a watch-only wallet needs " +
			"Config.RemoteSigner")
	}

	// Validate the request and pin the identity before Start can create
	// a directory or a database.
	identity, err := watchOnlyIdentity(req, daemonCfg.Network)
	if err != nil {
		return nil, nil, err
	}
	err = verifyDescriptorWalletIdentity(
		req.ExpectedIdentityPubKey, identity,
	)
	if err != nil {
		return nil, nil, err
	}

	// A seed in the environment is ignored in remote signer mode, but a
	// password there would replace the host's; refuse both, as for the
	// other host-owned wallets.
	for _, envVar := range []string{wavedSeedEnvVar, wavedPasswordEnvVar} {
		if value, ok := os.LookupEnv(envVar); ok && value != "" {
			return nil, nil, fmt.Errorf("%s must be unset when "+
				"starting a watch-only wallet", envVar)
		}
	}

	client, err := Start(startCtx, cfg, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("start watch-only wallet: %w", err)
	}

	result, err := client.openWatchOnlyWallet(openCtx, req, identity)
	if err == nil {
		err = waitForExternalSeedWalletReady(openCtx, client)
	}
	if err != nil {
		// Stop owns its own bounded daemon-shutdown context.
		//nolint:contextcheck
		stopErr := client.Stop()

		return nil, nil, fmt.Errorf("open watch-only wallet: %w",
			errors.Join(err, stopErr))
	}

	return client, result, nil
}

// watchOnlyIdentity validates a watch-only request for network and returns
// the identity public key it implies, hex encoded.
func watchOnlyIdentity(req WatchOnlyWalletRequest,
	network string) (string, error) {

	hasBundle := len(req.Bundle) > 0
	hasManifest := len(req.Manifest) > 0
	switch {
	case len(req.WalletPassword) == 0:
		return "", errors.New("watch-only wallet requires a wallet " +
			"password")

	case hasBundle == hasManifest:
		return "", errors.New("watch-only wallet requires exactly " +
			"one of a bundle and a manifest")

	case hasManifest && len(req.AuthKeys) == 0:
		return "", errors.New("a manifest requires its " +
			"authentication keys")

	case hasBundle && (len(req.AuthKeys) > 0 || req.OverrideIdentity):
		return "", errors.New("authentication keys and " +
			"OverrideIdentity are only used with a manifest")
	}

	params, err := waved.NetworkChainParams(network)
	if err != nil {
		return "", err
	}

	var identityKey *hdkeychain.ExtendedKey
	if hasBundle {
		full, minimal, err := walletdesc.ParseBundle(req.Bundle, params)
		if err != nil {
			return "", fmt.Errorf("invalid watch-only bundle: %w",
				err)
		}
		if minimal != nil {
			defer minimal.Zero()
			full = minimal.Public
		}
		identityKey, err = full.IdentityKey()
		if err != nil {
			return "", err
		}
	} else {
		manifest, err := walletdesc.ParseManifest(req.Manifest, params)
		if err != nil {
			return "", fmt.Errorf("invalid manifest: %w", err)
		}
		err = manifest.CheckIdentity(req.OverrideIdentity, params)
		if err != nil {
			return "", err
		}
		auth, err := walletdesc.ParseAuthKeys(req.AuthKeys, params)
		if err != nil {
			return "", fmt.Errorf("invalid authentication keys: %w",
				err)
		}
		auth.Zero()

		slot := manifest.Families[keyfamily.Identity]
		identityKey, err = slot.Key.Derive(0)
		if err == nil {
			identityKey, err = identityKey.Derive(0)
		}
		if err != nil {
			return "", err
		}
	}

	pub, err := identityKey.ECPubKey()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(pub.SerializeCompressed()), nil
}

// openWatchOnlyWallet imports the bundle or manifest into an empty daemon
// or unlocks the existing wallet, then checks the opened wallet's identity
// matches the request.
func (c *Client) openWatchOnlyWallet(ctx context.Context,
	req WatchOnlyWalletRequest, identity string) (
	*WatchOnlyWalletOpenResult, error) {

	if req.RecoverState && c.recoverWalletState == nil {
		return nil, errors.New("wallet state recovery requires an " +
			"embedded client")
	}

	info, err := c.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("read wallet state: %w", err)
	}

	result := &WatchOnlyWalletOpenResult{}
	switch info.WalletState {
	case WalletStateNone:
		created, err := c.CreateWallet(ctx, CreateWalletRequest{
			WalletPassword:    req.WalletPassword,
			Birthday:          req.Birthday,
			WatchOnlyBundle:   req.Bundle,
			WatchOnlyManifest: req.Manifest,
			AuthKeys:          req.AuthKeys,
			OverrideIdentity:  req.OverrideIdentity,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize watch-only "+
				"wallet: %w", err)
		}

		result.Imported = true
		result.IdentityPubKey = created.IdentityPubKey
		result.RootFingerprint = created.RootFingerprint
		result.ManifestHash = created.ManifestHash
		result.Descriptors = created.Descriptors

	case WalletStateLocked:
		unlock, err := c.UnlockWallet(ctx, UnlockWalletRequest{
			WalletPassword: req.WalletPassword,
		})
		if err != nil {
			return nil, err
		}
		result.IdentityPubKey = unlock.IdentityPubKey

		info, err := c.GetInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("read wallet info: %w", err)
		}
		result.ManifestHash = info.ManifestHash

		listed, err := c.ListWalletDescriptors(
			ctx, ListWalletDescriptorsRequest{},
		)
		if err != nil {
			return nil, err
		}
		result.RootFingerprint = listed.RootFingerprint
		result.Descriptors = listed.Descriptors

	case WalletStateReady, WalletStateSyncing:
		return nil, errors.New("wallet is already unlocked")

	default:
		return nil, fmt.Errorf("unexpected wallet state %v: cannot "+
			"open wallet", info.WalletState)
	}

	if result.IdentityPubKey != identity {
		return nil, fmt.Errorf("watch-only wallet identity mismatch: "+
			"request gives %s, wallet has %s", identity,
			result.IdentityPubKey)
	}

	if !req.RecoverState {
		return result, nil
	}

	recovery, err := c.recoverWalletState(ctx, req.RecoveryWindow)
	if err != nil {
		return nil, fmt.Errorf("recover wallet state: %w", err)
	}
	if recovery == nil {
		return nil, errors.New("recover wallet state: empty result")
	}

	result.RecoveryRan = true
	result.RecoveredBoardingAddresses = recovery.BoardingAddresses
	result.RecoveredBoardingUTXOs = recovery.BoardingUTXOs
	result.RecoveredVTXOs = recovery.VTXOs
	result.RecoveredOORReceiveScripts = recovery.OORReceiveScripts
	result.RecoveredOORRecipientEvents = recovery.OOREvents

	return result, nil
}
