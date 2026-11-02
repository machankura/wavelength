package wavewalletdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waved"
	"golang.org/x/crypto/hkdf"
)

// descriptorDBKeyInfo domain-separates the database password derived from a
// descriptor wallet's master key from every other use of that key, and from
// the external-seed scheme's info string, so the two can never collide.
const descriptorDBKeyInfo = "wavewalletdk:descriptor:dbpw:v1"

// DescriptorWalletRequest opens the wallet at an explicit daemon data
// directory from private output descriptors that share one BIP32 master key.
// The accepted forms are those of walletdesc.Parse: tr() under 86h/0h/0h and
// wpkh() under 84h/0h/0h, with branch 0, 1 or <0;1>.
//
// Birthday bounds the first rescan of a new import; zero scans from genesis.
// ExpectedIdentityPubKey optionally binds the directory to a previously
// persisted identity. The identity derived from the descriptors is always
// checked against the opened wallet, pinned or not. RecoverState reruns the
// idempotent recovery scan on this open, as for external-seed wallets.
type DescriptorWalletRequest struct {
	Descriptors            []string
	Birthday               time.Time
	ExpectedIdentityPubKey string
	RecoverState           bool
	RecoveryWindow         uint32
}

// DescriptorWalletOpenResult reports a descriptor wallet import or unlock,
// the public descriptors it watches, and the optional state-recovery scan.
type DescriptorWalletOpenResult struct {
	Imported                    bool
	IdentityPubKey              string
	RootFingerprint             string
	Descriptors                 []string
	RecoveryRan                 bool
	RecoveredBoardingAddresses  uint32
	RecoveredBoardingUTXOs      uint32
	RecoveredVTXOs              uint32
	RecoveredOORReceiveScripts  uint32
	RecoveredOORRecipientEvents uint32
}

// StartDescriptorWallet starts an embedded daemon at the explicit
// Config.DataDir, then imports a fresh wallet from the descriptors or unlocks
// the wallet already there. If opening fails, the newly started daemon is
// stopped before the error returns.
func StartDescriptorWallet(ctx context.Context, cfg Config,
	req DescriptorWalletRequest, opts ...Option) (*Client,
	*DescriptorWalletOpenResult, error) {

	return StartDescriptorWalletWithContexts(ctx, ctx, cfg, req, opts...)
}

// StartDescriptorWalletWithContexts starts an embedded daemon with startCtx
// and opens its wallet with openCtx, with the same readiness and rollback
// guarantees as StartExternalSeedWalletWithContexts.
func StartDescriptorWalletWithContexts(startCtx, openCtx context.Context,
	cfg Config, req DescriptorWalletRequest, opts ...Option) (*Client,
	*DescriptorWalletOpenResult, error) {

	if err := validateHostOwnedWalletConfig(cfg, "descriptor"); err != nil {
		return nil, nil, err
	}

	daemonCfg, err := daemonConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve descriptor wallet "+
			"network: %w", err)
	}

	// Validate the descriptors and pin the identity before Start can
	// create a directory or a database.
	wd, err := parseDescriptorWalletRequest(req, daemonCfg.Network)
	if err != nil {
		return nil, nil, err
	}
	defer wd.Zero()

	identity, err := waved.WalletIdentityPubKeyFromRootKey(
		wd.Root, daemonCfg.Network,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("derive descriptor wallet "+
			"identity: %w", err)
	}
	if err := verifyDescriptorWalletIdentity(
		req.ExpectedIdentityPubKey, identity,
	); err != nil {
		return nil, nil, err
	}

	// The seed and password environment hooks are process-global and
	// take precedence during daemon startup, exactly as for external
	// seeds, so refuse them before Start.
	for _, envVar := range []string{wavedSeedEnvVar, wavedPasswordEnvVar} {
		if value, ok := os.LookupEnv(envVar); ok && value != "" {
			return nil, nil, fmt.Errorf("%s must be unset when "+
				"starting a descriptor wallet", envVar)
		}
	}

	client, err := Start(startCtx, cfg, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("start descriptor wallet: %w", err)
	}

	result, err := client.openWalletFromDescriptors(
		openCtx, req, wd.Root, identity,
	)
	if err == nil {
		err = waitForExternalSeedWalletReady(openCtx, client)
	}
	if err != nil {
		// Stop owns its own bounded daemon-shutdown context.
		//nolint:contextcheck
		stopErr := client.Stop()

		return nil, nil, fmt.Errorf("open descriptor wallet: %w",
			errors.Join(err, stopErr))
	}

	return client, result, nil
}

// parseDescriptorWalletRequest validates a request's descriptors for the
// daemon network. The caller must zero the result.
func parseDescriptorWalletRequest(req DescriptorWalletRequest,
	network string) (*walletdesc.WalletDescriptors, error) {

	if len(req.Descriptors) == 0 {
		return nil, errors.New("descriptor wallet requires at least " +
			"one descriptor")
	}

	wd, err := waved.WalletRootFromDescriptors(
		req.Descriptors, network,
		// The database password is derived, not user chosen, so
		// only the descriptors are validated here.
		make([]byte, 64),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid descriptors: %w", err)
	}

	return wd, nil
}

// openWalletFromDescriptors imports the descriptors into an empty daemon or
// unlocks the existing wallet with the password derived from their master
// key, then checks the opened wallet's identity matches the descriptors.
func (c *Client) openWalletFromDescriptors(ctx context.Context,
	req DescriptorWalletRequest, root *hdkeychain.ExtendedKey,
	identity string) (*DescriptorWalletOpenResult, error) {

	if req.RecoverState && c.recoverWalletState == nil {
		return nil, errors.New("wallet state recovery requires an " +
			"embedded client")
	}

	dbPassword := deriveDescriptorDBPassword(root)
	defer clear(dbPassword)

	info, err := c.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("read wallet state: %w", err)
	}

	result := &DescriptorWalletOpenResult{}
	switch info.WalletState {
	case WalletStateNone:
		created, err := c.CreateWallet(ctx, CreateWalletRequest{
			Descriptors:    req.Descriptors,
			Birthday:       req.Birthday,
			WalletPassword: dbPassword,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize wallet from "+
				"descriptors: %w", err)
		}

		result.Imported = true
		result.IdentityPubKey = created.IdentityPubKey
		result.RootFingerprint = created.RootFingerprint
		result.Descriptors = created.Descriptors

	case WalletStateLocked:
		unlock, err := c.UnlockWallet(ctx, UnlockWalletRequest{
			WalletPassword: dbPassword,
		})
		if err != nil {
			return nil, err
		}
		result.IdentityPubKey = unlock.IdentityPubKey

		listed, err := c.ListWalletDescriptors(
			ctx, ListWalletDescriptorsRequest{},
		)
		if err != nil {
			return nil, err
		}
		result.RootFingerprint = listed.RootFingerprint
		result.Descriptors = listed.Descriptors

	case WalletStateReady, WalletStateSyncing:
		// Without an unlock, the daemon cannot prove its open wallet
		// came from these descriptors.
		return nil, errors.New("wallet is already unlocked")

	default:
		return nil, fmt.Errorf("unexpected wallet state %v: cannot "+
			"open wallet", info.WalletState)
	}

	// Identity must be verified before recovery can register or persist
	// state for this profile.
	if result.IdentityPubKey != identity {
		return nil, fmt.Errorf("descriptor wallet identity mismatch: "+
			"descriptors give %s, wallet has %s", identity,
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

// deriveDescriptorDBPassword derives the local wallet database password from
// the master key's private key and chain code with HKDF-SHA256. It is not
// the key material itself, and its info string differs from the
// external-seed scheme's.
func deriveDescriptorDBPassword(root *hdkeychain.ExtendedKey) []byte {
	priv, err := root.ECPrivKey()
	if err != nil {
		// Parse already guaranteed a private master key.
		panic(
			fmt.Sprintf("descriptor root has no private key: %v",
				err),
		)
	}

	secret := append(priv.Serialize(), root.ChainCode()...)
	defer clear(secret)

	rawPassword := make([]byte, 32)
	reader := hkdf.New(
		sha256.New, secret, nil, []byte(descriptorDBKeyInfo),
	)
	_, _ = io.ReadFull(reader, rawPassword)
	defer clear(rawPassword)

	password := make([]byte, hex.EncodedLen(len(rawPassword)))
	hex.Encode(password, rawPassword)

	return password
}

// verifyDescriptorWalletIdentity checks an optional caller-persisted
// identity against the one the descriptors derive.
func verifyDescriptorWalletIdentity(expected, actual string) error {
	if expected == "" || expected == actual {
		return nil
	}

	return fmt.Errorf("descriptor wallet identity mismatch: expected "+
		"%s, got %s", expected, actual)
}
