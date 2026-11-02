package waveclicommands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lightninglabs/wavelength/rpc/wavewalletrpc"
	"github.com/spf13/cobra"
)

// birthdayLayouts are the accepted formats for --birthday: a full RFC3339
// timestamp, or a plain calendar date, which is the granularity a wallet
// birthday actually has.
var birthdayLayouts = []string{time.RFC3339, time.DateOnly}

// newCreateCmd builds the top-level `create` verb. It is one of the
// seven core wallet verbs (create, unlock, send, recv, activity, balance,
// exit) and dials wavewalletrpc.WalletService.Create which proxies
// waverpc.GenSeed + waverpc.InitWallet under the hood. The wallet
// password, the optional seed passphrase and any descriptors are read
// from explicit non-argv sources so secrets never enter process listings.
func newCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new wallet from a fresh seed",
		Long: "Initializes a new wallet. The daemon generates a " +
			"24-word aezeed mnemonic, prints it to stderr (so " +
			"the caller can record it offline), and creates " +
			"the wallet database encrypted under the " +
			"supplied password.\n\n" +
			"The wallet password is read from " +
			"WAVED_WALLET_PASSWORD, --wallet-password-file, " +
			"or explicit --password-stdin (never CLI args). The " +
			"interactive password prompt asks for confirmation. " +
			"The optional seed passphrase is read from " +
			"WAVED_SEED_PASSPHRASE env / " +
			"--seed-passphrase-file. The mnemonic is shown " +
			"on stderr ONCE and is NOT included in the JSON " +
			"response on stdout (the caller must capture it " +
			"from stderr or pass --print-mnemonic-json to " +
			"opt in to the machine-consumable form).\n\n" +
			"With --descriptor-file the wallet is built from " +
			"private output descriptors instead of a mnemonic: " +
			"tr() under 86h/0h/0h and wpkh() under 84h/0h/0h, " +
			"all sharing one BIP32 master key, one per line. " +
			"Blank lines and lines starting with '#' are " +
			"ignored. --birthday bounds the first rescan; " +
			"without it the wallet scans from genesis. The " +
			"response lists the public descriptors the wallet " +
			"watches.\n\n" +
			"With --watch-only-bundle-file the wallet holds " +
			"public keys only and every signature comes from " +
			"the daemon's wallet.remotesigner. The bundle is " +
			"the signer's `lncli wallet accounts list` JSON, " +
			"or one account descriptor or key family entry per " +
			"line; see docs/daemon_cli_guide.md. --birthday " +
			"applies as for descriptors.\n\n" +
			"Example:\n" +
			"  printf '%s\\n' 'hunter2hunter2' | " +
			"wavecli create --password-stdin\n" +
			"  wavecli create --descriptor-file " +
			"wallet.descriptors --birthday 2026-01-01",
		Args: cobra.NoArgs,
		RunE: walletCreate,
	}

	cmd.Flags().String("wallet-password-file", "",
		"path to file containing wallet password")
	cmd.Flags().Bool("password-stdin", false,
		"read one wallet password line from stdin")
	cmd.Flags().String("seed-passphrase-file", "",
		"path to file containing optional aezeed passphrase")
	cmd.Flags().Bool("print-mnemonic-json", false,
		"include the mnemonic in the JSON response on stdout "+
			"(default: stderr only)")
	cmd.Flags().Bool("recover", false,
		"import an existing mnemonic and recover Ark wallet state")
	cmd.Flags().String("mnemonic-file", "",
		"path to file containing an existing 24-word aezeed mnemonic")
	cmd.Flags().Uint32("recovery-window", 0,
		"number of key indexes to scan per recovery family "+
			"(default: daemon wallet.recoverywindow)")
	cmd.Flags().String("descriptor-file", "",
		"path to file containing private output descriptors, one "+
			"per line, to build the wallet from instead of a "+
			"mnemonic")
	cmd.Flags().String("watch-only-bundle-file", "",
		"path to the remote signer's account public keys, for a "+
			"wallet whose private keys stay on that signer")
	cmd.Flags().String("birthday", "",
		"earliest date the descriptor or bundle keys may have "+
			"received funds (RFC3339 or YYYY-MM-DD); requires "+
			"--descriptor-file or --watch-only-bundle-file")

	return cmd
}

// createSource is the seed material a `create` invocation imports.
type createSource struct {
	mnemonic     []string
	descriptors  []string
	bundle       []byte
	birthdayUnix int64
}

// validateCreateFlags checks the flag combinations `create` accepts, before
// any file or secret is read.
func validateCreateFlags(cmd *cobra.Command) error {
	recoverWallet, _ := cmd.Flags().GetBool("recover")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	recoveryWindow, _ := cmd.Flags().GetUint32("recovery-window")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")
	birthday, _ := cmd.Flags().GetString("birthday")
	passphraseFile, _ := cmd.Flags().GetString("seed-passphrase-file")
	printJSON, _ := cmd.Flags().GetBool("print-mnemonic-json")
	bundleFile, _ := cmd.Flags().GetString("watch-only-bundle-file")

	if bundleFile != "" {
		switch {
		case descriptorFile != "" || mnemonicFile != "":
			return fmt.Errorf("--watch-only-bundle-file excludes " +
				"--descriptor-file and --mnemonic-file: the " +
				"wallet's private keys stay on the signer")

		case passphraseFile != "":
			return fmt.Errorf("--seed-passphrase-file applies " +
				"only to a mnemonic, not to " +
				"--watch-only-bundle-file")

		case printJSON:
			return fmt.Errorf("--print-mnemonic-json has no " +
				"effect with --watch-only-bundle-file: a " +
				"watch-only wallet has no mnemonic")

		case !recoverWallet && recoveryWindow != 0:
			return fmt.Errorf("--recovery-window requires " +
				"--recover")
		}

		return nil
	}

	if descriptorFile != "" {
		switch {
		case mnemonicFile != "":
			return fmt.Errorf("--descriptor-file and " +
				"--mnemonic-file are mutually exclusive")

		case passphraseFile != "":
			return fmt.Errorf("--seed-passphrase-file applies " +
				"only to a mnemonic, not to --descriptor-file")

		case printJSON:
			return fmt.Errorf("--print-mnemonic-json has no " +
				"effect with --descriptor-file: a descriptor " +
				"wallet has no mnemonic")

		case !recoverWallet && recoveryWindow != 0:
			return fmt.Errorf("--recovery-window requires " +
				"--recover")
		}

		return nil
	}

	switch {
	case birthday != "":
		return fmt.Errorf("--birthday requires --descriptor-file or " +
			"--watch-only-bundle-file; a mnemonic carries its " +
			"own birthday")

	case recoverWallet && mnemonicFile == "":
		return fmt.Errorf("--recover requires --mnemonic-file, " +
			"--descriptor-file or --watch-only-bundle-file")

	case !recoverWallet && mnemonicFile != "":
		return fmt.Errorf("--mnemonic-file requires --recover")

	case !recoverWallet && recoveryWindow != 0:
		return fmt.Errorf("--recovery-window requires --recover")
	}

	return nil
}

// readCreateSource reads the mnemonic or descriptors named by the flags.
func readCreateSource(cmd *cobra.Command) (*createSource, error) {
	recoverWallet, _ := cmd.Flags().GetBool("recover")
	mnemonicFile, _ := cmd.Flags().GetString("mnemonic-file")
	descriptorFile, _ := cmd.Flags().GetString("descriptor-file")
	bundleFile, _ := cmd.Flags().GetString("watch-only-bundle-file")
	birthday, _ := cmd.Flags().GetString("birthday")

	var (
		source createSource
		err    error
	)

	if birthday != "" {
		when, err := parseBirthday(birthday)
		if err != nil {
			return nil, err
		}
		source.birthdayUnix = when.Unix()
	}

	switch {
	case bundleFile != "":
		source.bundle, err = readWatchOnlyBundleFile(bundleFile)
		if err != nil {
			return nil, err
		}

	case descriptorFile != "":
		source.descriptors, err = readDescriptorFile(descriptorFile)
		if err != nil {
			return nil, err
		}

	case recoverWallet:
		source.mnemonic, err = readMnemonicFile(mnemonicFile)
		if err != nil {
			return nil, err
		}
	}

	return &source, nil
}

// walletCreate implements the top-level `create` verb.
func walletCreate(cmd *cobra.Command, _ []string) error {
	if err := validateCreateFlags(cmd); err != nil {
		return err
	}

	recoverWallet, _ := cmd.Flags().GetBool("recover")
	recoveryWindow, _ := cmd.Flags().GetUint32("recovery-window")

	source, err := readCreateSource(cmd)
	if err != nil {
		return err
	}
	defer clearStrings(source.descriptors)

	seedPassphrase, err := readSeedPassphrase(cmd)
	if err != nil {
		return err
	}
	defer zeroBytes(seedPassphrase)

	// The environment can still supply a seed passphrase; refuse it for
	// descriptors rather than silently ignoring it.
	fromDescriptors := len(source.descriptors) > 0 ||
		len(source.bundle) > 0
	if fromDescriptors && len(seedPassphrase) > 0 {
		return fmt.Errorf("WAVED_SEED_PASSPHRASE applies only to a " +
			"mnemonic; unset it to create from descriptors or a " +
			"watch-only bundle")
	}

	password, err := readPasswordConfirmed(cmd)
	if err != nil {
		return err
	}
	defer zeroBytes(password)

	printJSON, _ := cmd.Flags().GetBool("print-mnemonic-json")

	return withWalletClient(
		cmd, func(c wavewalletrpc.WalletServiceClient) error {
			ctx, cancel := rpcContext(cmd)
			defer cancel()

			resp, err := c.Create(
				ctx, &wavewalletrpc.CreateRequest{
					WalletPassword:  password,
					SeedPassphrase:  seedPassphrase,
					Mnemonic:        source.mnemonic,
					RecoverState:    recoverWallet,
					RecoveryWindow:  recoveryWindow,
					Descriptors:     source.descriptors,
					BirthdayUnix:    source.birthdayUnix,
					WatchOnlyBundle: source.bundle,
				},
			)
			if err != nil {
				return fmt.Errorf("create wallet: %w", err)
			}

			// Fresh-create prints the generated mnemonic to stderr
			// so it does not mix with structured JSON output. A
			// recovery import already read its seed material from
			// disk, so do not re-print it by default.
			if !recoverWallet && !fromDescriptors {
				fmt.Fprintln(
					os.Stderr,
					"=== WRITE DOWN YOUR SEED ===",
				)
				for i, word := range resp.GetMnemonic() {
					fmt.Fprintf(
						os.Stderr, "%2d. %s\n", i+1,
						word,
					)
				}
				fmt.Fprintln(
					os.Stderr,
					"============================",
				)
				fmt.Fprintln(os.Stderr)
			}

			if !printJSON {
				resp.Mnemonic = nil
			}

			return printWalletProto(resp)
		},
	)
}

// readMnemonicFile reads mnemonic words from path. The file may contain words
// separated by any whitespace, including one word per line.
func readMnemonicFile(path string) ([]string, error) {
	// The file path is explicitly provided by the CLI user.
	data, err := os.ReadFile(path) //nolint:gosec // G304
	if err != nil {
		return nil, fmt.Errorf("unable to read mnemonic file: %w", err)
	}

	words := strings.Fields(string(data))
	if len(words) == 0 {
		return nil, fmt.Errorf("mnemonic file is empty")
	}

	return words, nil
}

// readDescriptorFile reads one descriptor per line from path, skipping
// blank lines and lines starting with '#'. Private descriptors are as
// secret as a seed, so a file other local users can read gets a warning on
// stderr.
func readDescriptorFile(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read descriptor file: %w",
			err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(
			os.Stderr, "warning: descriptor file %s is readable "+
				"by other users (mode %04o); private "+
				"descriptors are as sensitive as a seed\n",
			path, info.Mode().Perm(),
		)
	}

	// The file path is explicitly provided by the CLI user.
	data, err := os.ReadFile(path) //nolint:gosec // G304
	if err != nil {
		return nil, fmt.Errorf("unable to read descriptor file: %w",
			err)
	}
	defer zeroBytes(data)

	var descriptors []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		descriptors = append(descriptors, line)
	}

	if len(descriptors) == 0 {
		return nil, fmt.Errorf("descriptor file contains no " +
			"descriptors")
	}

	return descriptors, nil
}

// parseBirthday parses a --birthday value.
func parseBirthday(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range birthdayLayouts {
		when, err := time.Parse(layout, value)
		if err == nil {
			return when, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid --birthday %q: use RFC3339 or "+
		"YYYY-MM-DD", value)
}

// clearStrings drops references to secret strings. Go strings are
// immutable, so this cannot wipe their bytes; it only shortens how long
// the slice keeps them reachable.
func clearStrings(values []string) {
	for i := range values {
		values[i] = ""
	}
}

// maxWatchOnlyBundleBytes bounds a bundle file. lnd's JSON for a full
// account list is around 100 KiB.
const maxWatchOnlyBundleBytes = 1 << 20

// readWatchOnlyBundleFile reads a watch-only bundle. It holds public keys
// only, so unlike a descriptor file it is not treated as a secret; the
// daemon parses and validates it.
func readWatchOnlyBundleFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read watch-only bundle: %w",
			err)
	}
	if info.Size() > maxWatchOnlyBundleBytes {
		return nil, fmt.Errorf("watch-only bundle %s is %d bytes, "+
			"at most %d", path, info.Size(),
			maxWatchOnlyBundleBytes)
	}

	// The file path is explicitly provided by the CLI user.
	data, err := os.ReadFile(path) //nolint:gosec // G304
	if err != nil {
		return nil, fmt.Errorf("unable to read watch-only bundle: %w",
			err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("watch-only bundle %s is empty", path)
	}

	return data, nil
}
