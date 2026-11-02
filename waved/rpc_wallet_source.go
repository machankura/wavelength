package waved

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/lightninglabs/wavelength/db"
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

// validateInitWalletSource rejects requests that mix mnemonic and
// descriptor seed material. It runs before any wallet state is claimed.
func validateInitWalletSource(req *waverpc.InitWalletRequest) error {
	if len(req.GetDescriptors()) == 0 {
		if req.GetBirthdayUnix() != 0 {
			return errors.New("birthday_unix is only used with " +
				"descriptors; a mnemonic carries its own " +
				"birthday")
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
