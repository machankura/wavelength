package walletdesc

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/txscript/v2"
)

// RawTaprootDescriptor returns the checksummed rawtr(OUTPUT_KEY) descriptor
// for a pay-to-taproot output script, where OUTPUT_KEY is the hex x-only
// output key taken verbatim from the script. It describes exactly that one
// output, whatever its script tree, which is why Ark outputs are exported
// this way: the standard Ark exit leaf has no miniscript form, so no ranged
// tr() descriptor can describe it.
func RawTaprootDescriptor(pkScript []byte) (string, error) {
	if !txscript.IsPayToTaproot(pkScript) {
		return "", fmt.Errorf("%w: not a pay-to-taproot script",
			ErrUnsupportedDescriptor)
	}

	// A P2TR script is OP_1 followed by a 32-byte push of the output key.
	return AddChecksum("rawtr(" + hex.EncodeToString(pkScript[2:]) + ")")
}
