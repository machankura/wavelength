package waveclicommands

import (
	"fmt"
	"os"
	"strings"

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
			"descriptors are as sensitive as the seed.\n\n" +
			"--ark prints one rawtr() descriptor per Ark output " +
			"instead: boarding outputs, live VTXOs and " +
			"out-of-round receive scripts, optionally filtered " +
			"with --kind. External watch-only software can track " +
			"them on chain; spending them still needs Wavelength.",
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
	cmd.Flags().Bool("ark", false,
		"print rawtr() descriptors for the wallet's Ark outputs")
	cmd.Flags().StringSlice("kind", nil,
		"with --ark, only these kinds: boarding, vtxo, oor-receive")

	return cmd
}

// arkOutputKinds maps --kind values to the RPC enum.
var arkOutputKinds = map[string]waverpc.ArkOutputKind{
	"boarding":    waverpc.ArkOutputKind_ARK_OUTPUT_KIND_BOARDING,
	"vtxo":        waverpc.ArkOutputKind_ARK_OUTPUT_KIND_VTXO,
	"oor-receive": waverpc.ArkOutputKind_ARK_OUTPUT_KIND_OOR_RECEIVE,
}

// parseArkOutputKinds converts --kind values, refusing unknown ones.
func parseArkOutputKinds(values []string) ([]waverpc.ArkOutputKind, error) {
	kinds := make([]waverpc.ArkOutputKind, 0, len(values))
	for _, value := range values {
		kind, ok := arkOutputKinds[strings.ToLower(value)]
		if !ok {
			return nil, fmt.Errorf("unknown --kind %q: use "+
				"boarding, vtxo or oor-receive", value)
		}
		kinds = append(kinds, kind)
	}

	return kinds, nil
}

// validateDescriptorsFlags checks the flag combinations `descriptors`
// accepts.
func validateDescriptorsFlags(cmd *cobra.Command) error {
	private, _ := cmd.Flags().GetBool("private")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")
	passphraseFile, _ := cmd.Flags().GetString("seed-passphrase-file")

	ark, _ := cmd.Flags().GetBool("ark")
	kinds, _ := cmd.Flags().GetStringSlice("kind")

	switch {
	case ark && (private || mnemonicFile != "" || descriptorFile != "" ||
		passphraseFile != ""):
		return fmt.Errorf("--ark prints public output descriptors " +
			"and takes no --private or seed material")

	case !ark && len(kinds) > 0:
		return fmt.Errorf("--kind requires --ark")

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

	if ark, _ := cmd.Flags().GetBool("ark"); ark {
		return arkOutputDescriptors(cmd)
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

// arkOutputDescriptors implements `descriptors --ark`.
func arkOutputDescriptors(cmd *cobra.Command) error {
	values, _ := cmd.Flags().GetStringSlice("kind")
	kinds, err := parseArkOutputKinds(values)
	if err != nil {
		return err
	}

	client, conn, err := getDaemonClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := rpcContext(cmd)
	defer cancel()

	resp, err := client.ListArkOutputDescriptors(
		ctx, &waverpc.ListArkOutputDescriptorsRequest{
			Kinds: kinds,
		},
	)
	if err != nil {
		return fmt.Errorf("list Ark output descriptors: %w", err)
	}

	return printJSON(resp)
}
