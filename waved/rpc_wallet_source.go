package waved

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/db"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
)

// preparedWalletCreate is the creation input derived from an InitWallet
// request, plus the public descriptors and fingerprint reported back.
type preparedWalletCreate struct {
	input             walletCreateInput
	publicDescriptors []string
	rootFingerprint   uint32
	source            db.WalletKeySource

	// zero wipes the seed or master key behind input.
	zero func()
}

// validateInitWalletSource rejects requests that mix mnemonic, descriptor
// and watch-only bundle inputs, and requests whose input does not match
// whether the daemon signs remotely. It runs before any wallet state is
// claimed.
func validateInitWalletSource(req *waverpc.InitWalletRequest,
	remoteSigner bool) error {

	hasBundle := len(req.GetWatchOnlyBundle()) > 0
	switch {
	case remoteSigner && !hasBundle:
		return errors.New("wallet.remotesigner is enabled, so the " +
			"wallet must be created from a watch-only bundle: " +
			"its private keys belong on the signer")

	case !remoteSigner && hasBundle:
		return errors.New("a watch-only bundle needs " +
			"wallet.remotesigner, since this daemon would hold " +
			"no key to sign with")

	case hasBundle:
		if len(req.GetMnemonic()) > 0 ||
			len(req.GetSeedPassphrase()) > 0 ||
			len(req.GetDescriptors()) > 0 {
			return errors.New("watch_only_bundle is mutually " +
				"exclusive with mnemonic, seed_passphrase " +
				"and descriptors")
		}

		return nil
	}

	if len(req.GetDescriptors()) == 0 {
		if req.GetBirthdayUnix() != 0 {
			return errors.New("birthday_unix is only used with " +
				"descriptors or a watch-only bundle; a " +
				"mnemonic carries its own birthday")
		}

		return nil
	}

	if len(req.GetMnemonic()) > 0 {
		return errors.New("mnemonic and descriptors are mutually " +
			"exclusive")
	}

	if len(req.GetSeedPassphrase()) > 0 {
		return errors.New("seed_passphrase applies only to a " +
			"mnemonic and cannot be used with descriptors")
	}

	return nil
}

// prepareWalletCreateInput derives the wallet creation input from either
// the request's mnemonic or its descriptors, together with the public
// descriptors the new wallet will watch. The caller must call zero on the
// result.
func prepareWalletCreateInput(req *waverpc.InitWalletRequest,
	network string) (*preparedWalletCreate, error) {

	chainParams, err := networkToChainParams(network)
	if err != nil {
		return nil, err
	}

	// Watch-only path: the bundle's account public keys are the
	// creation input, and there is no key material to wipe.
	if len(req.GetWatchOnlyBundle()) > 0 {
		birthday, err := BirthdayFromUnix(req.GetBirthdayUnix())
		if err != nil {
			return nil, err
		}

		bundle, minimal, err := walletdesc.ParseBundle(
			req.GetWatchOnlyBundle(), chainParams,
		)
		if err != nil {
			return nil, err
		}

		prepared := &preparedWalletCreate{
			input: walletCreateInput{
				watchOnly:        bundle,
				watchOnlyMinimal: minimal,
				birthday:         birthday,
			},
			source: db.WalletKeySourceWatchOnly,
			zero:   func() {},
		}
		if minimal != nil {
			// A minimal bundle carries the authentication keys,
			// which the wallet stores once it is created.
			bundle = minimal.Public
			prepared.zero = minimal.Zero
		}

		public, err := watchOnlyPublicDescriptors(bundle, chainParams)
		if err != nil {
			prepared.zero()

			return nil, err
		}
		prepared.publicDescriptors = public
		prepared.rootFingerprint = bundle.MasterFingerprint

		return prepared, nil
	}

	// Account key path: account-level private keys, signed with in
	// process from the wallet's encrypted keystore.
	if walletdesc.HasAccountKeys(req.GetDescriptors()) {
		birthday, err := BirthdayFromUnix(req.GetBirthdayUnix())
		if err != nil {
			return nil, err
		}

		keys, err := walletdesc.ParseAccountKeys(
			req.GetDescriptors(), chainParams,
		)
		if err != nil {
			return nil, err
		}

		bundle, err := keys.Bundle()
		if err != nil {
			keys.Zero()

			return nil, err
		}
		public, err := watchOnlyPublicDescriptors(bundle, chainParams)
		if err != nil {
			keys.Zero()

			return nil, err
		}

		return &preparedWalletCreate{
			input: walletCreateInput{
				accountKeys: keys,
				birthday:    birthday,
			},
			publicDescriptors: public,
			rootFingerprint:   keys.MasterFingerprint,
			source:            db.WalletKeySourceAccountKeys,
			zero:              keys.Zero,
		}, nil
	}

	// Descriptor path: the descriptors' shared master key is the
	// creation input.
	if len(req.GetDescriptors()) > 0 {
		birthday, err := BirthdayFromUnix(req.GetBirthdayUnix())
		if err != nil {
			return nil, err
		}

		wd, err := WalletRootFromDescriptors(
			req.GetDescriptors(), network, req.GetWalletPassword(),
		)
		if err != nil {
			return nil, err
		}

		public, fp, err := WalletPublicDescriptors(wd.Root, network)
		if err != nil {
			wd.Zero()

			return nil, err
		}

		return &preparedWalletCreate{
			input: walletCreateInput{
				rootKey:  wd.Root,
				birthday: birthday,
			},
			publicDescriptors: public,
			rootFingerprint:   fp,
			source:            db.WalletKeySourceDescriptors,
			zero:              wd.Zero,
		}, nil
	}

	// Mnemonic path: the aezeed seed is the creation input, and its
	// master key only provides the public descriptors to report.
	seed, birthday, err := WalletSeedFromMnemonic(
		req.GetMnemonic(), req.GetSeedPassphrase(),
		req.GetWalletPassword(),
	)
	if err != nil {
		return nil, err
	}

	seedBytes := seed[:]
	zero := func() {
		zeroBytes(seedBytes)
	}

	root, err := hdkeychain.NewMaster(seedBytes, chainParams)
	if err != nil {
		zero()

		return nil, fmt.Errorf("derive master key: %w", err)
	}
	defer root.Zero()

	public, fp, err := WalletPublicDescriptors(root, network)
	if err != nil {
		zero()

		return nil, err
	}

	return &preparedWalletCreate{
		input: walletCreateInput{
			seed:     seedBytes,
			birthday: birthday,
		},
		publicDescriptors: public,
		rootFingerprint:   fp,
		source:            db.WalletKeySourceSeed,
		zero:              zero,
	}, nil
}

// watchOnlyPublicDescriptors renders the on-chain account descriptors a
// watch-only bundle describes, tr() and, when present, wpkh(), with the
// bundle's fingerprint as key origin when it names one.
func watchOnlyPublicDescriptors(bundle *walletdesc.WatchOnlyBundle,
	params *chaincfg.Params) ([]string, error) {

	var public []string
	for _, scriptType := range []walletdesc.ScriptType{
		walletdesc.ScriptTaproot, walletdesc.ScriptWitnessPubKeyHash,
	} {
		acct, ok := bundle.Account(scriptType.Purpose(), 0)
		if !ok {
			continue
		}

		desc, err := walletdesc.NewAccountDescriptor(
			scriptType, acct.Key, bundle.MasterFingerprint,
			bundle.MasterFingerprint != 0, params,
		)
		if err != nil {
			return nil, err
		}

		text, err := desc.Render(false)
		if err != nil {
			return nil, err
		}
		public = append(public, text)
	}

	return public, nil
}
