package waved

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightninglabs/wavelength/waverpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// testArkKeys returns a fixed owner and operator key pair.
func testArkKeys(t *testing.T) (*btcec.PublicKey, *btcec.PublicKey) {
	t.Helper()

	owner, _ := btcec.PrivKeyFromBytes(
		chainhash.HashB(
			[]byte("ark descriptor owner"),
		),
	)
	operator, _ := btcec.PrivKeyFromBytes(
		chainhash.HashB(
			[]byte("ark descriptor operator"),
		),
	)

	return owner.PubKey(), operator.PubKey()
}

// TestArkOutputDescriptorFromStandardPolicy checks an exported entry for a
// standard Ark policy: the rawtr() key is the output key of the compiled
// policy, and the metadata is carried through.
func TestArkOutputDescriptorFromStandardPolicy(t *testing.T) {
	t.Parallel()

	owner, operator := testArkKeys(t)
	template, err := arkscript.StandardVTXOTemplate(owner, operator, 144)
	require.NoError(t, err)
	pkScript, err := template.PkScript()
	require.NoError(t, err)

	outpoint := wire.OutPoint{
		Hash:  chainhash.HashH([]byte("vtxo")),
		Index: 1,
	}
	entry, err := arkOutputDescriptor(
		waverpc.ArkOutputKind_ARK_OUTPUT_KIND_VTXO, pkScript,
		keychain.KeyLocator{
			Family: 44,
			Index:  7,
		},
		operator,
		144,
		fn.Some(outpoint),
	)
	require.NoError(t, err)

	want, err := walletdesc.AddChecksum(
		"rawtr(" + hex.EncodeToString(pkScript[2:]) + ")",
	)
	require.NoError(t, err)
	require.Equal(t, want, entry.GetOutputDescriptor())
	require.Equal(t, uint32(44), entry.GetKeyFamily())
	require.Equal(t, uint32(7), entry.GetKeyIndex())
	require.Equal(t, uint32(144), entry.GetExitDelay())
	require.Equal(t, outpoint.String(), entry.GetOutpoint())
	require.Equal(
		t,
		hex.EncodeToString(
			operator.SerializeCompressed(),
		),
		entry.GetOperatorPubkey(),
	)

	// The output key in the descriptor is the tweaked key the script
	// pays to, never the owner key itself.
	require.False(
		t,
		strings.Contains(
			entry.GetOutputDescriptor(),
			hex.EncodeToString(
				schnorr.SerializePubKey(owner),
			),
		),
	)

	_, err = arkOutputDescriptor(
		waverpc.ArkOutputKind_ARK_OUTPUT_KIND_BOARDING,
		[]byte{0x00, 0x14}, keychain.KeyLocator{}, nil, 0,
		fn.None[wire.OutPoint](),
	)
	require.Error(t, err)
}

// TestArkExitLeafIsNotMiniscript pins why Ark outputs are exported as rawtr()
// rather than as ranged tr() descriptors: the standard exit leaf ends in
// OP_DROP, and the nearest miniscript, and_v(v:pk(K),older(N)), compiles to a
// different leaf. If miniscript or descriptors ever gain a matching form,
// this is the test to revisit.
func TestArkExitLeafIsNotMiniscript(t *testing.T) {
	t.Parallel()

	owner, operator := testArkKeys(t)
	const delay = 144

	template, err := arkscript.StandardVTXOTemplate(owner, operator, delay)
	require.NoError(t, err)
	require.Len(t, template.Leaves, 2)

	exitLeaf, err := template.Leaves[1].Script()
	require.NoError(t, err)

	seq := blockchain.LockTimeToSequence(false, delay)
	miniscript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(owner)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(int64(seq)).
		AddOp(txscript.OP_CHECKSEQUENCEVERIFY).
		Script()
	require.NoError(t, err)

	require.NotEqual(t, miniscript, exitLeaf)
	require.Equal(t, byte(txscript.OP_DROP), exitLeaf[len(exitLeaf)-1])
}
