package waved

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExportWatchOnlyBundle renders the open wallet's watch-only bundle, full or
// minimal, from resupplied seed material that matches the wallet. It is the
// daemon-side counterpart of `wavesigner export-watchonly` for a wallet
// whose keys are about to move to a remote signer.
func (r *RPCServer) ExportWatchOnlyBundle(ctx context.Context,
	req *waverpc.ExportWatchOnlyBundleRequest) (
	*waverpc.ExportWatchOnlyBundleResponse, error) {

	if !r.server.isSelfManagedWallet() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"ExportWatchOnlyBundle is only available in "+
				"lwwallet/btcwallet mode")
	}

	// A watch-only wallet's keys are on its signer, which exports the
	// bundle itself.
	if r.server.cfg.Wallet.RemoteSigner.Enable {
		return nil, status.Errorf(codes.FailedPrecondition, "this "+
			"wallet signs remotely; export its bundle from the "+
			"signer")
	}

	if err := validateExportWatchOnlyBundle(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := r.requireWalletReady(); err != nil {
		return nil, err
	}

	accounts, err := r.server.walletAccountKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read wallet "+
			"accounts: %v", err)
	}

	keys, err := r.bundleAccountKeys(ctx, req, accounts)
	if err != nil {
		return nil, err
	}
	defer keys.Zero()

	text, err := walletdesc.FormatBundle(keys, req.GetMinimal())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "render bundle: %v",
			err)
	}

	return &waverpc.ExportWatchOnlyBundleResponse{
		Bundle:          string(text),
		Minimal:         req.GetMinimal(),
		RootFingerprint: FormatFingerprint(keys.MasterFingerprint),
	}, nil
}

// validateExportWatchOnlyBundle checks that exactly one source of seed
// material is supplied.
func validateExportWatchOnlyBundle(
	req *waverpc.ExportWatchOnlyBundleRequest) error {

	hasMnemonic := len(req.GetMnemonic()) > 0
	hasDescriptors := len(req.GetDescriptors()) > 0

	switch {
	case hasMnemonic && hasDescriptors:
		return errors.New("mnemonic and descriptors are mutually " +
			"exclusive")

	case !hasMnemonic && !hasDescriptors:
		return errors.New("the wallet's mnemonic, root descriptors " +
			"or account keys are required")

	case len(req.GetSeedPassphrase()) > 0 && !hasMnemonic:
		return errors.New("seed_passphrase requires mnemonic")
	}

	return nil
}

// bundleAccountKeys turns the request's seed material into the account
// keys the open wallet holds, refusing material that does not reproduce
// the wallet's BIP86 account and identity key. The caller must zero the
// result.
func (r *RPCServer) bundleAccountKeys(ctx context.Context,
	req *waverpc.ExportWatchOnlyBundleRequest,
	accounts map[walletdesc.ScriptType]*hdkeychain.ExtendedKey) (
	*walletdesc.AccountKeys, error) {

	network := r.server.cfg.Network
	if walletdesc.HasAccountKeys(req.GetDescriptors()) {
		keys, err := WalletAccountKeysFromDescriptors(
			req.GetDescriptors(), network,
		)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v",
				err)
		}
		if err := r.verifyWalletAccountKeys(
			ctx, keys, accounts,
		); err != nil {

			keys.Zero()

			return nil, err
		}

		return keys, nil
	}

	root, _, err := rootFromExportRequest(
		req.GetMnemonic(), req.GetSeedPassphrase(),
		req.GetDescriptors(), network,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	defer root.Zero()

	if err := r.verifyWalletRoot(ctx, root, accounts); err != nil {
		return nil, err
	}

	keys, err := walletdesc.BtcwalletAccountKeys(root, r.server.chainParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	return keys, nil
}

// verifyWalletAccountKeys checks account keys reproduce the open wallet's
// BIP86 account key and identity key.
func (r *RPCServer) verifyWalletAccountKeys(ctx context.Context,
	keys *walletdesc.AccountKeys,
	accounts map[walletdesc.ScriptType]*hdkeychain.ExtendedKey) error {

	bundle, err := keys.Bundle()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	wrong := status.Error(
		codes.InvalidArgument, errWrongWalletSecret.Error(),
	)

	var taproot *hdkeychain.ExtendedKey
	for _, acct := range bundle.Accounts {
		if acct.Purpose == walletdesc.ScriptTaproot.Purpose() {
			taproot = acct.Key
		}
	}
	want := accounts[walletdesc.ScriptTaproot]
	if taproot == nil || want == nil || taproot.String() != want.String() {
		return wrong
	}

	identityKey, err := bundle.IdentityKey()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	identityPub, err := identityKey.ECPubKey()
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	wantIdentity, err := r.deriveIdentityPubkey(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	gotIdentity := hex.EncodeToString(identityPub.SerializeCompressed())
	if wantIdentity != gotIdentity {
		return wrong
	}

	return nil
}
