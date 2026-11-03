package signerserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lightninglabs/wavelength/rpcauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon.v2"
)

// macaroonID names the signer's macaroon. There is one macaroon and one
// permission: whoever holds it may ask for signatures.
var macaroonID = []byte("wavesigner")

// ensureMacaroon loads the root key at rootKeyPath, creating it and the
// client macaroon at macaroonPath when the root key does not exist yet.
func ensureMacaroon(rootKeyPath, macaroonPath string) ([]byte, error) {
	// The path comes from the operator's signer configuration.
	rootKey, err := os.ReadFile(rootKeyPath) //nolint:gosec // G304
	switch {
	case err == nil:
		if len(rootKey) != 32 {
			return nil, fmt.Errorf("macaroon root key %s is "+
				"malformed", rootKeyPath)
		}

		return rootKey, nil

	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}

	rootKey = make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, err
	}

	mac, err := macaroon.New(
		rootKey, macaroonID, "wavesigner", macaroon.LatestVersion,
	)
	if err != nil {
		return nil, err
	}
	macBytes, err := mac.MarshalBinary()
	if err != nil {
		return nil, err
	}

	for _, path := range []string{rootKeyPath, macaroonPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(macaroonPath, macBytes, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(rootKeyPath, rootKey, 0o600); err != nil {
		return nil, err
	}

	return rootKey, nil
}

// authenticate checks the request carries a macaroon minted from rootKey
// with no caveats.
func authenticate(ctx context.Context, rootKey []byte) error {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(rpcauth.MacaroonMetadataKey)
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "macaroon required")
	}

	raw, err := hex.DecodeString(values[0])
	if err != nil {
		return status.Error(codes.Unauthenticated, "malformed macaroon")
	}

	var mac macaroon.Macaroon
	if err := mac.UnmarshalBinary(raw); err != nil {
		return status.Error(codes.Unauthenticated, "malformed macaroon")
	}

	err = mac.Verify(rootKey, func(string) error {
		return errors.New("caveats are not supported")
	}, nil)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid macaroon")
	}

	return nil
}

// unaryAuth rejects unary requests without a valid macaroon.
func unaryAuth(rootKey []byte) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		if err := authenticate(ctx, rootKey); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// streamAuth rejects streams without a valid macaroon. The signer serves
// none, but the check keeps an unimplemented stream from answering anyone.
func streamAuth(rootKey []byte) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		if err := authenticate(stream.Context(), rootKey); err != nil {
			return err
		}

		return handler(srv, stream)
	}
}
