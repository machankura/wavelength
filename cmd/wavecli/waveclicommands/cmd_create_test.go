package waveclicommands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestValidateCreateFlags covers the flag combinations `create` accepts and
// refuses, for both mnemonic and descriptor imports.
func TestValidateCreateFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		flags   map[string]string
		wantErr string
	}{
		{
			"fresh wallet",
			nil,
			"",
		},
		{"mnemonic recovery", map[string]string{
			"recover": "true", "mnemonic-file": "m.txt",
		}, ""},
		{"descriptors", map[string]string{
			"descriptor-file": "d.txt",
		}, ""},
		{"descriptors with recovery and birthday", map[string]string{
			"descriptor-file": "d.txt", "recover": "true",
			"recovery-window": "50", "birthday": "2026-01-01",
		}, ""},
		{"descriptors and mnemonic", map[string]string{
			"descriptor-file": "d.txt", "mnemonic-file": "m.txt",
			"recover": "true",
		}, "mutually exclusive"},
		{"descriptors and passphrase", map[string]string{
			"descriptor-file":      "d.txt",
			"seed-passphrase-file": "p.txt",
		}, "applies only to a mnemonic"},
		{"descriptors and mnemonic json", map[string]string{
			"descriptor-file":     "d.txt",
			"print-mnemonic-json": "true",
		}, "no mnemonic"},
		{"descriptors window without recover", map[string]string{
			"descriptor-file": "d.txt", "recovery-window": "5",
		}, "--recovery-window requires --recover"},
		{"birthday without descriptors", map[string]string{
			"birthday": "2026-01-01",
		}, "--birthday requires --descriptor-file"},
		{"recover without source", map[string]string{
			"recover": "true",
		}, "--recover requires"},
		{"mnemonic without recover", map[string]string{
			"mnemonic-file": "m.txt",
		}, "--mnemonic-file requires --recover"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cmd := newCreateCmd()
			for name, value := range tc.flags {
				require.NoError(t, cmd.Flags().Set(name, value))
			}

			err := validateCreateFlags(cmd)
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestReadDescriptorFile checks comment and blank-line handling and the
// empty-file refusal.
func TestReadDescriptorFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.descriptors")
	content := "# exported from another wallet\n\n" +
		"  tr(tprvA/86h/0h/0h/0/*)#aaaaaaaa  \n" +
		"tr(tprvA/86h/0h/0h/1/*)\n\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	got, err := readDescriptorFile(path)
	require.NoError(t, err)
	require.Equal(t, []string{
		"tr(tprvA/86h/0h/0h/0/*)#aaaaaaaa",
		"tr(tprvA/86h/0h/0h/1/*)",
	}, got)

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte("# none\n"), 0o600))
	_, err = readDescriptorFile(empty)
	require.ErrorContains(t, err, "no descriptors")

	_, err = readDescriptorFile(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

// TestParseBirthday checks both accepted layouts and a refusal.
func TestParseBirthday(t *testing.T) {
	t.Parallel()

	got, err := parseBirthday("2026-01-02")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), got)

	got, err = parseBirthday("2026-01-02T03:04:05Z")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), got)

	_, err = parseBirthday("yesterday")
	require.ErrorContains(t, err, "invalid --birthday")
}
