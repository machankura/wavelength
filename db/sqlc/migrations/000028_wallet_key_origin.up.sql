-- wallet_key_origin records where the self-managed wallet's keys come from.
-- btcwallet does not store the BIP32 master key fingerprint for its default
-- accounts, so the daemon keeps it here to render descriptor key origins.
-- There is at most one wallet per daemon database, hence the single row.
CREATE TABLE IF NOT EXISTS wallet_key_origin (
    -- id pins the table to one row.
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- root_fingerprint is the BIP32 fingerprint of the wallet's master
    -- key, as an unsigned 32-bit value.
    root_fingerprint BIGINT NOT NULL CHECK (
        root_fingerprint >= 0 AND root_fingerprint <= 4294967295
    ),

    -- source records how the wallet was created:
    --   0 = aezeed mnemonic or raw seed
    --   1 = output descriptors
    source INTEGER NOT NULL CHECK (source IN (0, 1)),

    -- created_at is the unix timestamp when the row was written.
    created_at BIGINT NOT NULL
);
