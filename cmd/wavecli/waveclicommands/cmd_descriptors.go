package waveclicommands

import (
	"fmt"
	"os"

	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/spf13/cobra"
)

// newDescriptorsCmd builds the `descriptors` command, which prints the
// output descriptors of a self-managed wallet.
func newDescriptorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "descriptors",
		Short: "Print the wallet's output descriptors",
		Long: "Prints the wallet's tr (BIP86) and wpkh (BIP84) " +
			"output descriptors. By default they are public " +
			"account-level descriptors, safe to import into " +
			"watch-only software.\n\n" +
			"--private prints private descriptors instead. It " +
			"requires the wallet's mnemonic (--mnemonic-file, " +
			"with an optional --seed-passphrase-file or " +
			"WAVED_SEED_PASSPHRASE) or its root descriptors " +
			"(--descriptor-file); the daemon checks them " +
			"against the open wallet and never reveals keys " +
			"on its own. Use it to move a mnemonic wallet " +
			"into descriptor-based software. Private " +
			"descriptors are as sensitive as the seed.",
		Args: cobra.NoArgs,
		RunE: walletDescriptors,
	}

	cmd.Flags().Bool("private", false,
		"print private descriptors; requires --mnemonic-file or "+
			"--descriptor-file")
	cmd.Flags().String("mnemonic-file", "",
		"path to the wallet's 24-word aezeed mnemonic")
	cmd.Flags().String("seed-passphrase-file", "",
		"path to file containing the optional aezeed passphrase")
	cmd.Flags().String("descriptor-file", "",
		"path to the wallet's private root descriptors")

	return cmd
}

// validateDescriptorsFlags checks the flag combinations `descriptors`
// accepts.
func validateDescriptorsFlags(cmd *cobra.Command) error {
	private, _ := cmd.Flags().GetBool("private")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")
	passphraseFile, _ := cmd.Flags().GetString("seed-passphrase-file")

	switch {
	case mnemonicFile != "" && descriptorFile != "":
		return fmt.Errorf("--mnemonic-file and --descriptor-file are " +
			"mutually exclusive")

	case private && mnemonicFile == "" && descriptorFile == "":
		return fmt.Errorf("--private requires --mnemonic-file or " +
			"--descriptor-file")

	case !private && (mnemonicFile != "" || descriptorFile != ""):
		return fmt.Errorf("--mnemonic-file and --descriptor-file are " +
			"only used with --private")

	case passphraseFile != "" && mnemonicFile == "":
		return fmt.Errorf("--seed-passphrase-file requires " +
			"--mnemonic-file")
	}

	return nil
}

// walletDescriptors implements the `descriptors` command.
func walletDescriptors(cmd *cobra.Command, _ []string) error {
	if err := validateDescriptorsFlags(cmd); err != nil {
		return err
	}

	private, _ := cmd.Flags().GetBool("private")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")

	req := &waverpc.ListWalletDescriptorsRequest{
		IncludePrivate: private,
	}

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

	case descriptorFile != "":
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

	resp, err := client.ListWalletDescriptors(ctx, req)
	if err != nil {
		return fmt.Errorf("list wallet descriptors: %w", err)
	}

	if resp.GetIncludesPrivate() {
		fmt.Fprintln(
			os.Stderr, "warning: the output contains private "+
				"keys; anyone who sees it can spend this "+
				"wallet's funds",
		)
	}

	return printJSON(resp)
}
