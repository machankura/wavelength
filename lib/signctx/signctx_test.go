package signctx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRecordOnlyWhenEnabled proves an ordinary wallet records nothing.
func TestRecordOnlyWhenEnabled(t *testing.T) {
	t.Cleanup(Disable)

	key := [32]byte{1}
	Record(KindRound, "r", [][32]byte{key}, "material")
	_, ok := Lookup(key)
	require.False(t, ok)

	Enable()
	Record(KindRound, "r", [][32]byte{key}, "material")
	note, ok := Lookup(key)
	require.True(t, ok)
	require.Equal(t, "r", note.ID)
	require.JSONEq(t, `"material"`, string(note.Material))

	Disable()
	_, ok = Lookup(key)
	require.False(t, ok)
}

// TestRecordIsBounded proves old notes go, rather than memory growing.
func TestRecordIsBounded(t *testing.T) {
	t.Cleanup(Disable)
	Enable()

	first := [32]byte{0xff, 0xff, 0xff}
	Record(KindOOR, "first", [][32]byte{first}, 1)
	for i := 0; i < maxNotes; i++ {
		key := [32]byte{byte(i), byte(i >> 8)}
		Record(KindOOR, "later", [][32]byte{key}, 1)
	}

	_, ok := Lookup(first)
	require.False(t, ok)
	require.LessOrEqual(t, len(notes), maxNotes)
}

// TestRecordDropsUnencodable proves a bad material leaves no note at all.
func TestRecordDropsUnencodable(t *testing.T) {
	t.Cleanup(Disable)
	Enable()

	key := [32]byte{2}
	Record(KindOOR, "bad", [][32]byte{key}, make(chan int))
	_, ok := Lookup(key)
	require.False(t, ok)
}

// TestAmendReplacesEveryKey proves a note amended under one of its keys reads
// the same under all of them, and that one nobody recorded stays absent.
func TestAmendReplacesEveryKey(t *testing.T) {
	t.Cleanup(Disable)
	Enable()

	first, second := [32]byte{1}, [32]byte{2}
	Record(KindRound, "r", [][32]byte{first, second}, "before")
	require.True(t, Amend(first, "after"))

	for _, key := range [][32]byte{first, second} {
		note, ok := Lookup(key)
		require.True(t, ok)
		require.Equal(t, KindRound, note.Kind)
		require.Equal(t, "r", note.ID)
		require.JSONEq(t, `"after"`, string(note.Material))
	}

	require.False(t, Amend([32]byte{3}, "nothing"))
	_, ok := Lookup([32]byte{3})
	require.False(t, ok)
}
