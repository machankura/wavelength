package waveclicommands

import (
	"fmt"
	"os"

	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/spf13/cobra"
)

// newExportWatchOnlyCmd builds the `export-watchonly` command, which writes
// the bundle a watch-only daemon is created from when this wallet's keys
// move to a remote signer.
func newExportWatchOnlyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export-watchonly",
		Short: "Write the wallet's watch-only bundle",
		Long: "Writes the bundle that `wavecli create " +
			"--watch-only-bundle-file` reads, for moving this " +
			"wallet's keys to a remote signer: every account " +
			"public key, or with --minimal the fund slots as " +
			"public keys and the two authentication families " +
			"as private keys, for split signing.\n\n" +
			"It requires the wallet's mnemonic (--mnemonic-file, " +
			"with an optional --seed-passphrase-file or " +
			"WAVED_SEED_PASSPHRASE), its root descriptors or " +
			"its account-level keys (--descriptor-file); the " +
			"daemon checks them against the open wallet. The " +
			"output file must not exist; a minimal bundle is " +
			"written readable by its owner only.",
		Args: cobra.NoArgs,
		RunE: exportWatchOnly,
	}

	cmd.Flags().String("output", "", "bundle file to write")
	cmd.Flags().Bool("minimal", false,
		"write a minimal bundle for split signing; it holds private "+
			"keys")
	cmd.Flags().String("mnemonic-file", "",
		"path to the wallet's 24-word aezeed mnemonic")
	cmd.Flags().String("seed-passphrase-file", "",
		"path to file containing the optional aezeed passphrase")
	cmd.Flags().String("descriptor-file", "",
		"path to the wallet's private root descriptors or account "+
			"keys")

	return cmd
}

// validateExportWatchOnlyFlags checks the flag combinations
// `export-watchonly` accepts.
func validateExportWatchOnlyFlags(cmd *cobra.Command) error {
	output, _ := cmd.Flags().GetString("output")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")
	passphraseFile, _ := cmd.Flags().GetString("seed-passphrase-file")

	switch {
	case output == "":
		return fmt.Errorf("--output is required")

	case mnemonicFile != "" && descriptorFile != "":
		return fmt.Errorf("--mnemonic-file and --descriptor-file are " +
			"mutually exclusive")

	case mnemonicFile == "" && descriptorFile == "":
		return fmt.Errorf("--mnemonic-file or --descriptor-file is " +
			"required")

	case passphraseFile != "" && mnemonicFile == "":
		return fmt.Errorf("--seed-passphrase-file requires " +
			"--mnemonic-file")
	}

	return nil
}

// exportWatchOnly implements the `export-watchonly` command.
func exportWatchOnly(cmd *cobra.Command, _ []string) error {
	if err := validateExportWatchOnlyFlags(cmd); err != nil {
		return err
	}

	output, _ := cmd.Flags().GetString("output")
	minimal, _ := cmd.Flags().GetBool("minimal")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")

	req := &waverpc.ExportWatchOnlyBundleRequest{Minimal: minimal}

	var err error
	switch {
	case mnemonicFile != "":
		req.Mnemonic, err = readMnemonicFile(mnemonicFile)
		if err != nil {
			return err
		}
		defer clearStrings(req.Mnemonic)

		req.SeedPassphrase, err = readSeedPassphrase(cmd)
		if err != nil {
			return err
		}
		defer zeroBytes(req.SeedPassphrase)

	default:
		req.Descriptors, err = readDescriptorFile(descriptorFile)
		if err != nil {
			return err
		}
		defer clearStrings(req.Descriptors)
	}

	client, conn, err := getDaemonClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := rpcContext(cmd)
	defer cancel()

	resp, err := client.ExportWatchOnlyBundle(ctx, req)
	if err != nil {
		return fmt.Errorf("export watch-only bundle: %w", err)
	}

	if err := writeNewFile(
		output,
		[]byte(
			resp.GetBundle(),
		),
		resp.GetMinimal(),
	); err != nil {
		return err
	}

	if resp.GetMinimal() {
		_, _ = fmt.Fprintln(
			os.Stderr, "warning: a minimal bundle contains "+
				"private keys; keep it as private as the "+
				"daemon's wallet password",
		)
	}

	// The bundle went to the file; keep it off stdout.
	resp.Bundle = ""

	return printJSON(resp)
}

// writeNewFile writes data to a path that must not exist yet, readable by
// the owner only when private is set.
func writeNewFile(path string, data []byte, private bool) error {
	mode := os.FileMode(0o644)
	if private {
		mode = 0o600
	}

	// The path is explicitly provided by the CLI user.
	f, err := os.OpenFile( //nolint:gosec // G304
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode,
	)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()

		return fmt.Errorf("write %s: %w", path, err)
	}

	return f.Close()
}
