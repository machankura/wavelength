// Command wavesigner holds a Wavelength wallet's private keys and signs for
// a watch-only daemon over gRPC. It runs no chain backend, no Ark actors and
// no mailbox: it only answers the requests lnd's remote signer protocol
// defines, so the watch-only daemon (wallet.remotesigner) needs no lnd.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/signerserver"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/spf13/cobra"
)

// passwordEnvVar names the environment variable that supplies the key
// store password without a file. It holds no credential itself.
const passwordEnvVar = "WAVESIGNER_PASSWORD" //nolint:gosec // G101

// minPasswordLen matches the wallet password floor of the daemon.
const minPasswordLen = 8

// options are the flags shared by every subcommand.
type options struct {
	dataDir      string
	network      string
	passwordFile string
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "wavesigner:", err)
		os.Exit(1)
	}
}

// newRootCmd builds the command tree.
func newRootCmd() *cobra.Command {
	opts := &options{}
	root := &cobra.Command{
		Use:   "wavesigner",
		Short: "Hold a Wavelength wallet's keys and sign remotely",
		Long: "wavesigner keeps a wallet's private keys and answers " +
			"the signing requests of a watch-only waved daemon " +
			"configured with wallet.remotesigner. Create the key " +
			"store once, export the watch-only bundle for the " +
			"daemon, then run the signer where only that daemon " +
			"can reach it.\n\nThe key store password is read " +
			"from " + passwordEnvVar + " or --password-file.",
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVar(&opts.dataDir, "datadir",
		defaultDataDir(), "signer data directory")
	root.PersistentFlags().StringVar(&opts.network, "network",
		"mainnet", "network: mainnet, testnet, testnet4, signet, "+
			"regtest or simnet")
	root.PersistentFlags().StringVar(&opts.passwordFile, "password-file",
		"", "file holding the key store password")

	root.AddCommand(
		newCreateCmd(opts), newRunCmd(opts), newExportCmd(opts),
	)

	return root
}

// defaultDataDir is ~/.wavesigner.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".wavesigner"
	}

	return filepath.Join(home, ".wavesigner")
}

// networkDir is the per-network directory holding the store, TLS pair and
// macaroon.
func (o *options) networkDir() string {
	return filepath.Join(o.dataDir, o.network)
}

// params resolves the network.
func (o *options) params() (*chaincfg.Params, error) {
	switch o.network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil

	case "testnet":
		return &chaincfg.TestNet3Params, nil

	case "testnet4":
		return &chaincfg.TestNet4Params, nil

	case "signet":
		return &chaincfg.SigNetParams, nil

	case "regtest":
		return &chaincfg.RegressionNetParams, nil

	case "simnet":
		return &chaincfg.SimNetParams, nil

	default:
		return nil, fmt.Errorf("unknown network %q", o.network)
	}
}

// password reads the key store password from the environment or the
// password file, never from arguments.
func (o *options) password() ([]byte, error) {
	var password []byte
	switch {
	case os.Getenv(passwordEnvVar) != "":
		password = []byte(os.Getenv(passwordEnvVar))

	case o.passwordFile != "":
		raw, err := os.ReadFile(o.passwordFile)
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		password = bytes.TrimRight(raw, "\r\n")

	default:
		return nil, fmt.Errorf("set %s or --password-file",
			passwordEnvVar)
	}

	if len(password) < minPasswordLen {
		return nil, fmt.Errorf("password must be at least %d bytes",
			minPasswordLen)
	}

	return password, nil
}

// newCreateCmd builds `wavesigner create`.
func newCreateCmd(opts *options) *cobra.Command {
	var (
		descriptorFile   string
		mnemonicFile     string
		passphraseFile   string
		overrides        []string
		overrideIdentity bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create the encrypted key store",
		Long: "Creates the key store from either a descriptor file " +
			"(master-key descriptors or account-level private " +
			"keys, as `wavecli create --descriptor-file` " +
			"accepts) or a Wavelength aezeed mnemonic file. The " +
			"keys are encrypted under the password.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (descriptorFile == "") == (mnemonicFile == "") {
				return errors.New("give exactly one of " +
					"--descriptor-file and --mnemonic-file")
			}

			params, err := opts.params()
			if err != nil {
				return err
			}
			password, err := opts.password()
			if err != nil {
				return err
			}
			defer clear(password)

			keys, err := readKeys(
				descriptorFile, mnemonicFile, passphraseFile,
				params,
			)
			if err != nil {
				return err
			}
			defer keys.Zero()

			err = applyOverrides(
				keys, overrides, overrideIdentity, params,
			)
			if err != nil {
				return err
			}

			err = signerserver.CreateStore(
				opts.networkDir(), password, keys,
			)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(
				cmd.OutOrStdout(),
				"created key store %s (master fingerprint "+
					"%s)\n",
				signerserver.StorePath(
					opts.networkDir(),
				),
				walletdesc.FormatFingerprint(
					keys.MasterFingerprint,
				),
			)

			return nil
		},
	}
	cmd.Flags().StringVar(&descriptorFile, "descriptor-file", "",
		"file of master-key descriptors or account-level keys")
	cmd.Flags().StringVar(&mnemonicFile, "mnemonic-file", "",
		"file holding a Wavelength 24-word aezeed mnemonic")
	cmd.Flags().StringVar(&passphraseFile, "seed-passphrase-file", "",
		"file holding the mnemonic's optional aezeed passphrase")
	cmd.Flags().StringArrayVar(&overrides, "override", nil,
		"SLOT=FILE: fill a fund slot (onchain, 6, 42, 44, 45 or "+
			"202) with the key in FILE, either "+
			"[fingerprint/path]XPRV or a master XPRV/path; "+
			"repeatable")
	cmd.Flags().BoolVar(&overrideIdentity, "override-identity", false,
		"allow --override 6, which gives the wallet a different "+
			"identity, mailbox and swap key")

	return cmd
}

// applyOverrides fills the slots named by --override flags and checks the
// result still forms a valid manifest.
func applyOverrides(keys *walletdesc.AccountKeys, overrides []string,
	overrideIdentity bool, params *chaincfg.Params) error {

	for _, override := range overrides {
		slot, file, ok := strings.Cut(override, "=")
		if !ok {
			return fmt.Errorf("--override %q is not SLOT=FILE",
				override)
		}

		// The path is explicitly provided by the operator.
		data, err := os.ReadFile(file) //nolint:gosec // G304
		if err != nil {
			return err
		}
		key, origin, err := walletdesc.ParseKeySource(
			string(data), params,
		)
		clear(data)
		if err != nil {
			return fmt.Errorf("--override %s: %w", slot, err)
		}

		err = walletdesc.ApplyOverride(keys, slot, key, origin)
		if err != nil {
			key.Zero()

			return err
		}
	}

	if len(overrides) == 0 {
		return nil
	}

	text, err := walletdesc.FormatManifest(keys, params)
	if err != nil {
		return err
	}
	manifest, err := walletdesc.ParseManifest(text, params)
	if err != nil {
		return err
	}

	return manifest.CheckIdentity(overrideIdentity, params)
}

// readKeys reads the key material named by create's flags.
func readKeys(descriptorFile, mnemonicFile, passphraseFile string,
	params *chaincfg.Params) (*walletdesc.AccountKeys, error) {

	if descriptorFile != "" {
		// The path is explicitly provided by the operator.
		data, err := os.ReadFile(descriptorFile) //nolint:gosec // G304
		if err != nil {
			return nil, err
		}
		defer clear(data)

		var texts []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			texts = append(texts, line)
		}

		return signerserver.KeysFromDescriptors(texts, params)
	}

	// The path is explicitly provided by the operator.
	data, err := os.ReadFile(mnemonicFile) //nolint:gosec // G304
	if err != nil {
		return nil, err
	}
	defer clear(data)

	var passphrase []byte
	if passphraseFile != "" {
		// The path is explicitly provided by the operator.
		raw, err := os.ReadFile(passphraseFile) //nolint:gosec // G304
		if err != nil {
			return nil, err
		}
		passphrase = bytes.TrimRight(raw, "\r\n")
		defer clear(passphrase)
	}

	return signerserver.KeysFromMnemonic(
		strings.Fields(
			string(data),
		),
		passphrase,
		params,
	)
}

// newRunCmd builds `wavesigner run`.
func newRunCmd(opts *options) *cobra.Command {
	var (
		listen       string
		extraIPs     []string
		extraDomains []string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Serve signing requests",
		Long: "Decrypts the key store and serves the remote signer " +
			"protocol on --listen. The watch-only daemon needs " +
			"tls.cert and signer.macaroon from the network " +
			"directory, written on first start; the macaroon " +
			"grants signing, so give it to that daemon only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			params, err := opts.params()
			if err != nil {
				return err
			}
			password, err := opts.password()
			if err != nil {
				return err
			}
			keys, err := signerserver.OpenStore(
				opts.networkDir(), password, params,
			)
			clear(password)
			if err != nil {
				return err
			}

			dir := opts.networkDir()
			server, err := signerserver.New(signerserver.Config{
				ListenAddr:      listen,
				TLSCertPath:     filepath.Join(dir, "tls.cert"),
				TLSKeyPath:      filepath.Join(dir, "tls.key"),
				TLSExtraIPs:     extraIPs,
				TLSExtraDomains: extraDomains,
				MacaroonPath: filepath.Join(
					dir, "signer.macaroon",
				),
				RootKeyPath: filepath.Join(dir, "macaroon.key"),
				Keys:        keys,
				Params:      params,
			})
			if err != nil {
				keys.Zero()

				return err
			}

			ctx, stop := signal.NotifyContext(
				context.Background(), os.Interrupt,
				syscall.SIGTERM,
			)
			defer stop()
			go func() {
				<-ctx.Done()
				server.Stop()
			}()

			_, _ = fmt.Fprintf(
				cmd.OutOrStdout(),
				"wavesigner serving on %s\n", server.Addr(),
			)

			return server.Serve()
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "localhost:10019",
		"host:port to serve the remote signer protocol on")
	cmd.Flags().StringSliceVar(&extraIPs, "tlsextraip", nil,
		"extra IP address for a newly generated TLS certificate")
	cmd.Flags().StringSliceVar(&extraDomains, "tlsextradomain", nil,
		"extra domain for a newly generated TLS certificate")

	return cmd
}

// newExportCmd builds `wavesigner export-watchonly`.
func newExportCmd(opts *options) *cobra.Command {
	var (
		output      string
		minimal     bool
		manifestOut string
		authKeysOut string
	)
	cmd := &cobra.Command{
		Use:   "export-watchonly",
		Short: "Write the watch-only bundle for the daemon",
		Long: "Writes the bundle `wavecli create " +
			"--watch-only-bundle-file` takes. By default it is " +
			"a full bundle of public keys, and every signature " +
			"then comes from this signer. With --minimal it also " +
			"holds the two authentication keys as private keys, " +
			"so the daemon signs round joins and payment " +
			"receipts itself while every key that can move " +
			"funds stays here; the file is then written " +
			"owner-only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			manifestMode := manifestOut != "" || authKeysOut != ""
			switch {
			case manifestMode && (manifestOut == "" ||
				authKeysOut == ""):
				return errors.New("--manifest-out and " +
					"--auth-keys-out go together")

			case manifestMode && (output != "" || minimal):
				return errors.New("a manifest export takes " +
					"no --output or --minimal")

			case !manifestMode && output == "":
				return errors.New("--output or " +
					"--manifest-out is required")
			}

			params, err := opts.params()
			if err != nil {
				return err
			}
			password, err := opts.password()
			if err != nil {
				return err
			}
			keys, err := signerserver.OpenStore(
				opts.networkDir(), password, params,
			)
			clear(password)
			if err != nil {
				return err
			}
			defer keys.Zero()

			if manifestMode {
				err := signerserver.WriteManifest(
					manifestOut, authKeysOut, keys, params,
				)
				if err != nil {
					return err
				}

				_, _ = fmt.Fprintf(
					cmd.OutOrStdout(),
					"wrote %s and %s\n", manifestOut,
					authKeysOut,
				)

				return nil
			}

			if minimal {
				_, _ = fmt.Fprintln(
					cmd.ErrOrStderr(),
					"warning: a minimal bundle "+
						"contains private keys; "+
						"keep it as private as the "+
						"daemon's wallet password",
				)
			}

			err = signerserver.WriteBundle(output, keys, minimal)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(
				cmd.OutOrStdout(),
				"wrote %s\n", output,
			)

			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "bundle file to write")
	cmd.Flags().BoolVar(&minimal, "minimal", false,
		"write a minimal bundle for split signing")
	cmd.Flags().StringVar(&manifestOut, "manifest-out", "",
		"write the wallet manifest here (needed when slots are "+
			"overridden; public)")
	cmd.Flags().StringVar(&authKeysOut, "auth-keys-out", "",
		"write the authentication keys here, with --manifest-out "+
			"(private, written owner-only)")

	return cmd
}
