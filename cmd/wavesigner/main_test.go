package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/stretchr/testify/require"
)

// runSigner executes wavesigner with args and returns its output.
func runSigner(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()

	return out.String(), err
}

// TestCreateAndExport creates a key store from master-key descriptors and
// exports both bundle forms, checking each parses as its kind and that a
// minimal bundle is written owner-only and never over a readable file.
func TestCreateAndExport(t *testing.T) {
	t.Setenv(passwordEnvVar, "wavesigner-test-pw")

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x55 + i)
	}
	params := &chaincfg.RegressionNetParams
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)

	dir := t.TempDir()
	descriptors := filepath.Join(dir, "wallet.descriptors")
	require.NoError(
		t,
		os.WriteFile(
			descriptors, []byte(
				"tr("+root.String()+"/86h/0h/0h/<0;1>/*)\n",
			),
			0o600,
		),
	)

	dataDir := filepath.Join(dir, "signer")
	common := []string{"--datadir", dataDir, "--network", "regtest"}

	out, err := runSigner(
		t, append(
			[]string{"create", "--descriptor-file", descriptors},
			common...,
		)...,
	)
	require.NoError(t, err, out)
	require.Contains(t, out, "created key store")

	_, err = runSigner(
		t, append(
			[]string{"create", "--descriptor-file", descriptors},
			common...,
		)...,
	)
	require.ErrorIs(t, err, signerserver.ErrStoreExists)

	full := filepath.Join(dir, "full.bundle")
	out, err = runSigner(
		t, append(
			[]string{"export-watchonly", "--output", full},
			common...,
		)...,
	)
	require.NoError(t, err, out)
	data, err := os.ReadFile(full)
	require.NoError(t, err)
	bundle, minimal, err := walletdesc.ParseBundle(data, params)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	require.Nil(t, minimal)

	want, err := walletdesc.BtcwalletAccountKeys(root, params)
	require.NoError(t, err)
	defer want.Zero()
	wantBundle, err := want.Bundle()
	require.NoError(t, err)
	identity, err := bundle.IdentityKey()
	require.NoError(t, err)
	wantIdentity, err := wantBundle.IdentityKey()
	require.NoError(t, err)
	require.Equal(t, wantIdentity.String(), identity.String())

	split := filepath.Join(dir, "minimal.bundle")
	out, err = runSigner(
		t, append(
			[]string{
				"export-watchonly", "--minimal", "--output",
				split,
			},
			common...,
		)...,
	)
	require.NoError(t, err, out)
	require.Contains(t, out, "contains private keys")
	info, err := os.Stat(split)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	data, err = os.ReadFile(split)
	require.NoError(t, err)
	_, minimal, err = walletdesc.ParseBundle(data, params)
	require.NoError(t, err)
	require.NotNil(t, minimal)
	minimal.Zero()

	readable := filepath.Join(dir, "readable.bundle")
	require.NoError(t, os.WriteFile(readable, nil, 0o644))
	_, err = runSigner(
		t, append(
			[]string{
				"export-watchonly", "--minimal", "--output",
				readable,
			},
			common...,
		)...,
	)
	require.ErrorContains(t, err, "readable by other users")

	// A wrong password does not open the store.
	t.Setenv(passwordEnvVar, "not-the-password")
	_, err = runSigner(
		t, append(
			[]string{"export-watchonly", "--output", full},
			common...,
		)...,
	)
	require.Error(t, err)
}

// TestKeysFromMnemonic checks a Wavelength mnemonic yields the keys of its
// zero-padded entropy, the seed a Wavelength wallet derives from.
func TestKeysFromMnemonic(t *testing.T) {
	t.Parallel()

	var entropy [aezeed.EntropySize]byte
	entropy[0] = 7
	cipherSeed, err := aezeed.New(
		aezeed.CipherSeedVersion, &entropy, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	mnemonic, err := cipherSeed.ToMnemonic(nil)
	require.NoError(t, err)

	params := &chaincfg.RegressionNetParams
	keys, err := signerserver.KeysFromMnemonic(mnemonic[:], nil, params)
	require.NoError(t, err)
	defer keys.Zero()

	seed := make([]byte, 32)
	copy(seed, entropy[:])
	root, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	fp, err := walletdesc.Fingerprint(root)
	require.NoError(t, err)
	require.Equal(t, fp, keys.MasterFingerprint)

	_, err = signerserver.KeysFromMnemonic(mnemonic[:23], nil, params)
	require.Error(t, err)
}
