package waved

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/wavelength/db"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errWrongWalletSecret is returned when resupplied seed material does not
// belong to the open wallet. It deliberately says nothing about which check
// failed.
var errWrongWalletSecret = errors.New("the supplied seed material does not " +
	"belong to this wallet")

// exportScopes pairs each exported descriptor script type with the
// btcwallet key scope that holds its account.
var exportScopes = []struct {
	scriptType walletdesc.ScriptType
	scope      waddrmgr.KeyScope
}{
	{walletdesc.ScriptTaproot, waddrmgr.KeyScopeBIP0086},
	{walletdesc.ScriptWitnessPubKeyHash, waddrmgr.KeyScopeBIP0084},
}

// ListWalletDescriptors returns the self-managed wallet's output
// descriptors. Public descriptors come from btcwallet's account keys and the
// recorded fingerprint. Private descriptors are only rendered from
// resupplied seed material that matches the open wallet, so an unlocked
// daemon never reveals key material on its own.
func (r *RPCServer) ListWalletDescriptors(ctx context.Context,
	req *waverpc.ListWalletDescriptorsRequest) (
	*waverpc.ListWalletDescriptorsResponse, error) {

	if !r.server.isSelfManagedWallet() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"ListWalletDescriptors is only available in "+
				"lwwallet/btcwallet mode")
	}

	if err := validateListWalletDescriptors(req); err != nil {
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

	originStore, err := r.walletKeyOriginStore()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	origin, err := originStore.Get(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	if !req.GetIncludePrivate() {
		return publicWalletDescriptors(
			accounts, origin, r.server.chainParams,
		)
	}

	return r.privateWalletDescriptors(ctx, req, accounts, origin)
}

// validateListWalletDescriptors checks that seed material is supplied
// exactly when private descriptors are requested.
func validateListWalletDescriptors(
	req *waverpc.ListWalletDescriptorsRequest) error {

	hasMnemonic := len(req.GetMnemonic()) > 0
	hasDescriptors := len(req.GetDescriptors()) > 0

	switch {
	case hasMnemonic && hasDescriptors:
		return errors.New("mnemonic and descriptors are mutually " +
			"exclusive")

	case len(req.GetSeedPassphrase()) > 0 && !hasMnemonic:
		return errors.New("seed_passphrase requires mnemonic")

	case req.GetIncludePrivate() && !hasMnemonic && !hasDescriptors:
		return errors.New("include_private requires the wallet's " +
			"mnemonic or root descriptors")

	case !req.GetIncludePrivate() && (hasMnemonic || hasDescriptors):
		return errors.New("mnemonic and descriptors are only used " +
			"with include_private")
	}

	return nil
}

// publicWalletDescriptors renders the account-level public descriptors.
// Without a recorded fingerprint they carry no key origin.
func publicWalletDescriptors(
	accounts map[walletdesc.ScriptType]*hdkeychain.ExtendedKey,
	origin fn.Option[db.WalletKeyOrigin],
	params *chaincfg.Params) (*waverpc.ListWalletDescriptorsResponse,
	error) {

	resp := &waverpc.ListWalletDescriptorsResponse{}

	var (
		fp    uint32
		hasFP bool
	)
	origin.WhenSome(func(o db.WalletKeyOrigin) {
		fp, hasFP = o.RootFingerprint, true
		resp.RootFingerprint = FormatFingerprint(fp)
	})

	for _, entry := range exportScopes {
		account, ok := accounts[entry.scriptType]
		if !ok {
			continue
		}

		desc, err := walletdesc.NewAccountDescriptor(
			entry.scriptType, account, fp, hasFP, params,
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "build %s "+
				"descriptor: %v", entry.scriptType, err)
		}

		text, err := desc.Render(false)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "render %s "+
				"descriptor: %v", entry.scriptType, err)
		}
		resp.Descriptors = append(resp.Descriptors, text)
	}

	return resp, nil
}

// privateWalletDescriptors derives the master key from the resupplied seed
// material, refuses it unless it reproduces the open wallet's account keys
// and identity, backfills a missing fingerprint, and renders the private
// descriptors.
func (r *RPCServer) privateWalletDescriptors(ctx context.Context,
	req *waverpc.ListWalletDescriptorsRequest,
	accounts map[walletdesc.ScriptType]*hdkeychain.ExtendedKey,
	origin fn.Option[db.WalletKeyOrigin]) (
	*waverpc.ListWalletDescriptorsResponse, error) {

	network := r.server.cfg.Network
	root, source, err := rootFromExportRequest(
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

	fp, err := walletdesc.Fingerprint(root)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	// A wallet created before fingerprints were recorded learns its own
	// now, so later public exports carry key origins.
	if origin.IsNone() {
		r.recordWalletKeyOrigin(ctx, db.WalletKeyOrigin{
			RootFingerprint: fp,
			Source:          source,
		})
	}

	private, err := walletdesc.CanonicalPrivate(root, r.server.chainParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	resp := &waverpc.ListWalletDescriptorsResponse{
		RootFingerprint: FormatFingerprint(fp),
		IncludesPrivate: true,
	}
	for i := range private {
		text, err := private[i].Render(true)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		resp.Descriptors = append(resp.Descriptors, text)
	}

	return resp, nil
}

// rootFromExportRequest derives the master key from an export request's
// mnemonic or root descriptors. The caller must zero the result.
func rootFromExportRequest(mnemonic []string, seedPassphrase []byte,
	descriptors []string, network string) (*hdkeychain.ExtendedKey,
	db.WalletKeySource, error) {

	chainParams, err := networkToChainParams(network)
	if err != nil {
		return nil, 0, err
	}

	if len(descriptors) > 0 {
		wd, err := walletdesc.Parse(descriptors, chainParams)
		if err != nil {
			return nil, 0, err
		}

		return wd.Root, db.WalletKeySourceDescriptors, nil
	}

	seed, _, err := MnemonicSeed(mnemonic, seedPassphrase)
	if err != nil {
		return nil, 0, err
	}
	defer zeroBytes(seed[:])

	root, err := hdkeychain.NewMaster(seed[:], chainParams)
	if err != nil {
		return nil, 0, fmt.Errorf("derive master key: %w", err)
	}

	return root, db.WalletKeySourceSeed, nil
}

// verifyWalletRoot checks root reproduces the BIP86 and BIP84 account keys the
// open wallet holds and its identity key. walletAccountKeys guarantees BIP86.
func (r *RPCServer) verifyWalletRoot(ctx context.Context,
	root *hdkeychain.ExtendedKey,
	accounts map[walletdesc.ScriptType]*hdkeychain.ExtendedKey) error {

	public, err := walletdesc.CanonicalPublic(root, r.server.chainParams)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	for i := range public {
		got, err := public[i].AccountPublicKey()
		if err != nil {
			return status.Errorf(codes.Internal, "%v", err)
		}

		want, ok := accounts[public[i].ScriptType()]
		if !ok {
			continue
		}
		if want.String() != got.String() {
			return status.Error(
				codes.InvalidArgument,
				errWrongWalletSecret.Error(),
			)
		}
	}

	wantIdentity, err := r.deriveIdentityPubkey(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	gotIdentity, err := WalletIdentityPubKeyFromRootKey(
		root, r.server.cfg.Network,
	)
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	if wantIdentity != gotIdentity {
		return status.Error(
			codes.InvalidArgument, errWrongWalletSecret.Error(),
		)
	}

	return nil
}

// walletAccountKeys reads the account-0 public keys of the scopes the
// wallet exports, from whichever self-managed backend is running. A wallet
// imported without a BIP84 account has none under that name, only a
// placeholder whose key was discarded, so the result omits that scope. Every
// wallet must hold BIP86.
func (s *Server) walletAccountKeys() (
	map[walletdesc.ScriptType]*hdkeychain.ExtendedKey, error) {

	var btcw *btcwallet.BtcWallet
	switch {
	case s.lwWallet.IsSome():
		btcw = s.lwWallet.UnsafeFromSome().BtcWallet

	case s.btcwWallet.IsSome():
		btcw = s.btcwWallet.UnsafeFromSome().BtcWallet

	default:
		return nil, errors.New("self-managed wallet not running")
	}

	keys := make(map[walletdesc.ScriptType]*hdkeychain.ExtendedKey)
	for _, entry := range exportScopes {
		scope := entry.scope
		props, err := btcw.ListAccounts(
			lnwallet.DefaultAccountName, &scope,
		)
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) &&
			scope != waddrmgr.KeyScopeBIP0086 {

			continue
		}
		if err != nil {
			return nil, fmt.Errorf("list %v accounts: %w", scope,
				err)
		}
		if len(props) != 1 || props[0].AccountPubKey == nil {
			return nil, fmt.Errorf("scope %v has no default "+
				"account key", scope)
		}

		// btcwallet stores BIP84 accounts with SLIP-132 versions;
		// normalize so keys compare and render as descriptors expect.
		key, err := walletdesc.StandardAccountPublicKey(
			props[0].AccountPubKey, s.chainParams,
		)
		if err != nil {
			return nil, fmt.Errorf("normalize %v account key: %w",
				scope, err)
		}
		keys[entry.scriptType] = key
	}

	return keys, nil
}

// walletKeyOriginStore opens the wallet key origin store on the daemon
// database.
func (r *RPCServer) walletKeyOriginStore() (*db.WalletKeyOriginStore, error) {
	if r.server.db == nil {
		return nil, errors.New("database not initialized")
	}

	dbStore := db.NewStore(
		r.server.db.DB, r.server.db.Queries, r.server.db.Backend(),
		r.server.subLogger(db.Subsystem),
	)

	return dbStore.NewWalletKeyOriginStore(), nil
}

// recordCreatedKeyOrigin records the key origin of a wallet just created.
// Descriptor export renders the origin as the fingerprint at the on-chain
// account's standard path, so a wallet whose on-chain account came from
// elsewhere records nothing and exports its keys with no origin.
func (r *RPCServer) recordCreatedKeyOrigin(ctx context.Context,
	created *preparedWalletCreate) {

	if created.originUnknown {
		return
	}

	r.recordWalletKeyOrigin(ctx, db.WalletKeyOrigin{
		RootFingerprint: created.rootFingerprint,
		Source:          created.source,
	})
}

// recordWalletKeyOrigin persists the wallet key origin. A failure is logged
// rather than returned: without the row, export only loses its key origins.
func (r *RPCServer) recordWalletKeyOrigin(ctx context.Context,
	origin db.WalletKeyOrigin) {

	store, err := r.walletKeyOriginStore()
	if err == nil {
		err = store.Put(ctx, origin, r.server.clk.Now())
	}
	if err != nil {
		r.server.log.WarnS(ctx, "Failed to record wallet key origin; "+
			"descriptor export will omit key origins", err)
	}
}
