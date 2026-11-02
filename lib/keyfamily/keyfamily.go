// Package keyfamily is the single registry of the lnd-style key families
// (m/1017'/coin'/family') that Wavelength derives keys from. Every family is
// classified by what its keys can do, so code that splits signing between a
// remote signer and the daemon can route on the class instead of on a list
// duplicated at each call site.
package keyfamily

import (
	"fmt"

	"github.com/lightningnetwork/lnd/keychain"
)

// Class says what a key family's keys can do.
type Class uint8

const (
	// Funds keys appear in output scripts or sign spends, so their
	// theft can move money.
	Funds Class = iota + 1

	// Auth keys authenticate the wallet to the operator or to payers.
	// They appear in no output script and sign no spend, so their theft
	// allows impersonation but not theft of funds.
	Auth
)

// String returns the class name.
func (c Class) String() string {
	switch c {
	case Funds:
		return "funds"

	case Auth:
		return "auth"

	default:
		return fmt.Sprintf("Class(%d)", uint8(c))
	}
}

// The key families Wavelength derives from. Any new family must be added
// here, and to Registry, with its class; registry_test.go fails the build
// for a family declared anywhere else.
const (
	// Identity is the daemon identity key (index 0). It signs Ark round
	// participation and OOR authorization, and is also the swap vHTLC
	// key. It matches lnd's KeyFamilyNodeKey so an lnd-backed daemon
	// and the lnd node share one identity.
	Identity = keychain.KeyFamilyNodeKey

	// ReceiveAuth is the base for per-payment receive authentication
	// keys. It matches lndclient.SharedKeyLocator's family.
	ReceiveAuth keychain.KeyFamily = 21

	// Boarding keys own boarding outputs together with the operator.
	Boarding keychain.KeyFamily = 42

	// RoundJoinAuth keys authenticate round join requests.
	RoundJoinAuth keychain.KeyFamily = 43

	// VTXOOwner keys are committed into VTXO policies and stay stable
	// across refreshes. They also sign forfeits and exit sweeps.
	VTXOOwner keychain.KeyFamily = 44

	// VTXOSigning keys are per-round MuSig2 keys for the VTXO tree. They
	// are distinct from lnd's multisig family and from the operator's
	// families, so a client sharing an lnd signer with the operator
	// cannot derive the operator key as its first VTXO signing key.
	VTXOSigning keychain.KeyFamily = 45

	// OORReceive keys own out-of-round receive scripts. The value stays
	// inside lnd's pre-provisioned 0..255 account range so a watch-only
	// wallet can derive it, and continues the operator block (sweep 200,
	// operator 201).
	OORReceive keychain.KeyFamily = 202
)

// MaxFamily is the highest family a wallet pre-provisions an account for.
// lnd's btcwallet creates accounts 1 to MaxFamily on start, and a
// watch-only wallet cannot create one later, so every registry family must
// stay at or below it.
const MaxFamily keychain.KeyFamily = 255

// Entry describes one registered family.
type Entry struct {
	// Family is the key family number.
	Family keychain.KeyFamily

	// Name is a short human-readable name.
	Name string

	// Class says what the family's keys can do.
	Class Class
}

// Registry lists every family Wavelength derives from, in ascending order.
var Registry = []Entry{
	{Family: Identity, Name: "identity", Class: Funds},
	{Family: ReceiveAuth, Name: "receive-auth", Class: Auth},
	{Family: Boarding, Name: "boarding", Class: Funds},
	{Family: RoundJoinAuth, Name: "round-join-auth", Class: Auth},
	{Family: VTXOOwner, Name: "vtxo-owner", Class: Funds},
	{Family: VTXOSigning, Name: "vtxo-signing", Class: Funds},
	{Family: OORReceive, Name: "oor-receive", Class: Funds},
}

// Lookup returns the registry entry for family.
func Lookup(family keychain.KeyFamily) (Entry, bool) {
	for _, entry := range Registry {
		if entry.Family == family {
			return entry, true
		}
	}

	return Entry{}, false
}

// Families returns the registered families of class, in ascending order.
func Families(class Class) []keychain.KeyFamily {
	var families []keychain.KeyFamily
	for _, entry := range Registry {
		if entry.Class == class {
			families = append(families, entry.Family)
		}
	}

	return families
}
