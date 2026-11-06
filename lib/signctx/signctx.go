// Package signctx lets the code about to ask for a signature say what it is
// signing, for a signer that judges requests instead of answering them.
//
// A remote signer sees a transaction or a bare digest. A signer that checks a
// request against the rest of a round has to be told about the round, and the
// signing interfaces have no place to say it: input.Signer takes no context,
// and a MuSig2 signature request carries 32 bytes. So a call site notes what it
// knows here, keyed by the transaction ids and digests it will ask about, and
// the signer looks up the note when the request arrives.
//
// A note is a hint from an untrusted device. A signer must rebuild what it
// signs from the note's material and never believe it. Nothing is recorded
// unless a signer that reads notes has enabled the package, so an ordinary
// wallet does none of this work.
package signctx

import (
	"encoding/json"
	"sync"
	"sync/atomic"
)

// maxNotes bounds what is retained. A daemon has few rounds and transfers in
// flight, and a request whose note was dropped is refused, not signed blind.
const maxNotes = 4096

// Kind says what a note describes.
type Kind string

const (
	// KindRound describes a validated round: its commitment transaction,
	// its trees and what this wallet asked of it.
	KindRound Kind = "round"

	// KindOOR describes an out-of-round transfer: its Ark transaction and
	// the checkpoints that fund it.
	KindOOR Kind = "oor"

	// KindJoin describes a round join's proof of funds: the challenge
	// transaction that makes the proof unspendable.
	KindJoin Kind = "join"
)

// Note is what a call site said about a signature it is about to ask for.
type Note struct {
	// Kind says how to read Material.
	Kind Kind `json:"kind"`

	// ID names the round or transfer.
	ID string `json:"id"`

	// Material is the note's JSON body.
	Material json.RawMessage `json:"material"`
}

var (
	enabled atomic.Bool

	mu     sync.Mutex
	notes  = make(map[[32]byte]*Note)
	oldest [][32]byte
)

// Enable starts recording notes.
func Enable() {
	enabled.Store(true)
}

// Disable stops recording and forgets every note.
func Disable() {
	enabled.Store(false)

	mu.Lock()
	defer mu.Unlock()

	notes = make(map[[32]byte]*Note)
	oldest = nil
}

// Enabled reports whether a signer is reading notes, so a call site can skip
// building material nobody will read.
func Enabled() bool {
	return enabled.Load()
}

// Record stores a note under every key it answers for: the ids of the
// transactions and the digests it describes. A material that cannot be encoded
// is dropped, which leaves the eventual request refused.
func Record(kind Kind, id string, keys [][32]byte, material any) {
	if !Enabled() {
		return
	}

	raw, err := json.Marshal(material)
	if err != nil {
		return
	}

	note := &Note{Kind: kind, ID: id, Material: raw}

	mu.Lock()
	defer mu.Unlock()

	for _, key := range keys {
		if _, known := notes[key]; !known {
			oldest = append(oldest, key)
		}
		notes[key] = note
	}

	for len(oldest) > maxNotes {
		delete(notes, oldest[0])
		oldest = oldest[1:]
	}
}

// Amend replaces the material of the note recorded under key, under every key
// that note answers for. It reports whether there was such a note. A material
// that cannot be encoded leaves the note as it was.
func Amend(key [32]byte, material any) bool {
	if !Enabled() {
		return false
	}

	raw, err := json.Marshal(material)
	if err != nil {
		return false
	}

	mu.Lock()
	defer mu.Unlock()

	old, ok := notes[key]
	if !ok {
		return false
	}

	amended := &Note{Kind: old.Kind, ID: old.ID, Material: raw}
	for k, note := range notes {
		if note == old {
			notes[k] = amended
		}
	}

	return true
}

// Lookup returns the note recorded under key.
func Lookup(key [32]byte) (*Note, bool) {
	mu.Lock()
	defer mu.Unlock()

	note, ok := notes[key]

	return note, ok
}
