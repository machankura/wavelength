package waved

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListArkOutputDescriptors returns one rawtr() descriptor per Ark output the
// wallet knows about, read from the stored output scripts. Unlike
// ListWalletDescriptors these describe individual outputs, not ranges: the
// standard Ark exit leaf has no miniscript form, and the operator key and
// exit delay come from operator terms that change over time.
func (r *RPCServer) ListArkOutputDescriptors(ctx context.Context,
	req *waverpc.ListArkOutputDescriptorsRequest) (
	*waverpc.ListArkOutputDescriptorsResponse, error) {

	if err := r.requireWalletReady(); err != nil {
		return nil, err
	}

	want := make(map[waverpc.ArkOutputKind]bool)
	for _, kind := range req.GetKinds() {
		if kind == waverpc.ArkOutputKind_ARK_OUTPUT_KIND_UNSPECIFIED {
			return nil, status.Error(
				codes.InvalidArgument,
				"kinds must not contain UNSPECIFIED",
			)
		}
		want[kind] = true
	}
	include := func(kind waverpc.ArkOutputKind) bool {
		return len(want) == 0 || want[kind]
	}

	resp := &waverpc.ListArkOutputDescriptorsResponse{}
	add := func(entry *waverpc.ArkOutputDescriptor, err error) error {
		if err != nil {
			return status.Errorf(codes.Internal, "export Ark "+
				"output: %v", err)
		}
		resp.Descriptors = append(resp.Descriptors, entry)

		return nil
	}

	if include(waverpc.ArkOutputKind_ARK_OUTPUT_KIND_BOARDING) {
		addrs, err := r.server.newBoardingStore().
			ListAllBoardingAddresses(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list "+
				"boarding addresses: %v", err)
		}

		for _, addr := range addrs {
			pkScript, err := txscript.PayToAddrScript(addr.Address)
			if err == nil {
				err = add(
					arkOutputDescriptor(
						waverpc.ArkOutputKind_ARK_OUTPUT_KIND_BOARDING,
						pkScript,
						addr.KeyDesc.KeyLocator,
						addr.OperatorKey,
						addr.ExitDelay,
						fn.None[wire.OutPoint](),
					),
				)
			}
			if err != nil {
				return nil, err
			}
		}
	}

	if include(waverpc.ArkOutputKind_ARK_OUTPUT_KIND_VTXO) {
		if r.server.vtxoStore == nil {
			return nil, status.Error(
				codes.Unavailable, "VTXO store not initialized",
			)
		}

		vtxos, err := r.server.vtxoStore.ListLiveVTXOs(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list live "+
				"VTXOs: %v", err)
		}

		for _, v := range vtxos {
			// The exit delay lives in the VTXO's policy template,
			// which is not decoded here; zero means unknown.
			err := add(
				arkOutputDescriptor(
					waverpc.ArkOutputKind_ARK_OUTPUT_KIND_VTXO,
					v.PkScript, v.ClientKey.KeyLocator,
					v.OperatorKey, 0, fn.Some(v.Outpoint),
				),
			)
			if err != nil {
				return nil, err
			}
		}
	}

	if include(waverpc.ArkOutputKind_ARK_OUTPUT_KIND_OOR_RECEIVE) {
		store, err := r.newOORReceiveScriptStore()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}

		scripts, err := store.ListOwnedReceiveScripts(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list "+
				"receive scripts: %v", err)
		}

		for _, rec := range scripts {
			exitDelay := uint32(0)
			if rec.ExitDelay > 0 {
				exitDelay = uint32(rec.ExitDelay)
			}

			err := add(
				arkOutputDescriptor(
					waverpc.ArkOutputKind_ARK_OUTPUT_KIND_OOR_RECEIVE,
					rec.PkScript, rec.ClientKey.KeyLocator,
					rec.OperatorPubKey, exitDelay,
					fn.None[wire.OutPoint](),
				),
			)
			if err != nil {
				return nil, err
			}
		}
	}

	return resp, nil
}

// arkOutputDescriptor builds one exported entry from a stored output script
// and the policy metadata kept alongside it.
func arkOutputDescriptor(kind waverpc.ArkOutputKind, pkScript []byte,
	loc keychain.KeyLocator, operatorKey *btcec.PublicKey, exitDelay uint32,
	outpoint fn.Option[wire.OutPoint]) (*waverpc.ArkOutputDescriptor,
	error) {

	descriptor, err := walletdesc.RawTaprootDescriptor(pkScript)
	if err != nil {
		return nil, fmt.Errorf("%v output: %w", kind, err)
	}

	entry := &waverpc.ArkOutputDescriptor{
		OutputDescriptor: descriptor,
		Kind:             kind,
		KeyFamily:        uint32(loc.Family),
		KeyIndex:         loc.Index,
		ExitDelay:        exitDelay,
	}
	if operatorKey != nil {
		entry.OperatorPubkey = hex.EncodeToString(
			operatorKey.SerializeCompressed(),
		)
	}
	outpoint.WhenSome(func(op wire.OutPoint) {
		entry.Outpoint = op.String()
	})

	return entry, nil
}
