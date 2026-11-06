package waved

import (
	"testing"

	"github.com/lightninglabs/wavelength/oor"
	"github.com/stretchr/testify/require"
)

// TestRecipientsOfEvent proves that replaying an event for one output of a
// package that pays this wallet twice leaves the other output to its own event,
// even where the two pay one script.
func TestRecipientsOfEvent(t *testing.T) {
	first := oor.ArkRecipientOutput{OutputIndex: 0, PkScript: []byte{1}}
	second := oor.ArkRecipientOutput{OutputIndex: 1, PkScript: []byte{2}}
	sameScript := oor.ArkRecipientOutput{OutputIndex: 2, PkScript: []byte{1}}
	all := []oor.ArkRecipientOutput{first, second, sameScript}

	require.Equal(
		t, []oor.ArkRecipientOutput{first},
		recipientsOfEvent(all, []byte{1}, 0),
	)
	require.Equal(
		t, []oor.ArkRecipientOutput{second},
		recipientsOfEvent(all, []byte{2}, 1),
	)
	require.Equal(
		t, []oor.ArkRecipientOutput{sameScript},
		recipientsOfEvent(all, []byte{1}, 2),
	)
	require.Empty(t, recipientsOfEvent(all, []byte{2}, 0))
}
