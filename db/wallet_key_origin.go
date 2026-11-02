package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lightninglabs/wavelength/db/sqlc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
)

// WalletKeySource records how a self-managed wallet's keys were supplied.
type WalletKeySource int32

const (
	// WalletKeySourceSeed is an aezeed mnemonic or a raw seed.
	WalletKeySourceSeed WalletKeySource = 0

	// WalletKeySourceDescriptors is a set of output descriptors.
	WalletKeySourceDescriptors WalletKeySource = 1

	// WalletKeySourceWatchOnly is a bundle of account public keys whose
	// private keys live on a remote signer.
	WalletKeySourceWatchOnly WalletKeySource = 2

	// WalletKeySourceAccountKeys is a set of account-level private keys,
	// kept in the wallet's encrypted keystore.
	WalletKeySourceAccountKeys WalletKeySource = 3
)

// WalletKeyOrigin is the public metadata about a wallet's BIP32 master key
// that btcwallet itself does not keep: its fingerprint and how the key was
// supplied. It contains no secret.
type WalletKeyOrigin struct {
	// RootFingerprint is the BIP32 fingerprint of the master key.
	RootFingerprint uint32

	// Source records how the wallet was created.
	Source WalletKeySource
}

// WalletKeyOriginQueries is the query surface the wallet key origin store
// needs.
type WalletKeyOriginQueries interface {
	// GetWalletKeyOrigin fetches the single wallet key origin row.
	GetWalletKeyOrigin(ctx context.Context) (sqlc.WalletKeyOrigin, error)

	// UpsertWalletKeyOrigin writes the single wallet key origin row.
	UpsertWalletKeyOrigin(ctx context.Context,
		arg sqlc.UpsertWalletKeyOriginParams) error
}

// BatchedWalletKeyOriginQueries runs wallet key origin queries in
// transactions.
type BatchedWalletKeyOriginQueries interface {
	WalletKeyOriginQueries
	BatchedTx[WalletKeyOriginQueries]
}

// WalletKeyOriginStore persists the wallet key origin row.
type WalletKeyOriginStore struct {
	db BatchedWalletKeyOriginQueries
}

// NewWalletKeyOriginStore creates a wallet key origin store for this Store.
func (s *Store) NewWalletKeyOriginStore() *WalletKeyOriginStore {
	originDB := NewTransactionExecutor(
		s.BaseDB(), func(tx *sql.Tx) WalletKeyOriginQueries {
			return s.queries.WithTx(tx)
		}, s.log,
	)

	return &WalletKeyOriginStore{db: originDB}
}

// Get returns the stored wallet key origin, or None for a wallet created
// before the daemon recorded one.
func (w *WalletKeyOriginStore) Get(ctx context.Context) (
	fn.Option[WalletKeyOrigin], error) {

	var row sqlc.WalletKeyOrigin
	err := w.db.ExecTx(
		ctx, ReadTxOption(), func(q WalletKeyOriginQueries) error {
			var err error
			row, err = q.GetWalletKeyOrigin(ctx)

			return err
		},
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fn.None[WalletKeyOrigin](), nil

	case err != nil:
		return fn.None[WalletKeyOrigin](), fmt.Errorf("get wallet key "+
			"origin: %w", err)
	}

	return fn.Some(WalletKeyOrigin{
		RootFingerprint: uint32(row.RootFingerprint),
		Source:          WalletKeySource(row.Source),
	}), nil
}

// Put writes the wallet key origin, replacing any earlier row. createdAt is
// only recorded the first time.
func (w *WalletKeyOriginStore) Put(ctx context.Context, origin WalletKeyOrigin,
	createdAt time.Time) error {

	err := w.db.ExecTx(
		ctx, WriteTxOption(), func(q WalletKeyOriginQueries) error {
			return q.UpsertWalletKeyOrigin(
				ctx, sqlc.UpsertWalletKeyOriginParams{
					RootFingerprint: int64(
						origin.RootFingerprint,
					),
					Source:    int32(origin.Source),
					CreatedAt: createdAt.Unix(),
				},
			)
		},
	)
	if err != nil {
		return fmt.Errorf("put wallet key origin: %w", err)
	}

	return nil
}
