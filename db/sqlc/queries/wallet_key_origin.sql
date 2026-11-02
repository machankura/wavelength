-- Wallet key origin queries.

-- name: GetWalletKeyOrigin :one
SELECT * FROM wallet_key_origin
WHERE id = 1;

-- name: UpsertWalletKeyOrigin :exec
INSERT INTO wallet_key_origin (id, root_fingerprint, source, created_at)
VALUES (1, $1, $2, $3)
ON CONFLICT (id) DO UPDATE SET
    root_fingerprint = excluded.root_fingerprint,
    source = excluded.source;
