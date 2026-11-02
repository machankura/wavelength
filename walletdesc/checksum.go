package walletdesc

import (
	"fmt"
	"strings"
)

const (
	// checksumLen is the number of characters in a descriptor checksum.
	checksumLen = 8

	// inputCharset is the BIP380 character set a descriptor may use. The
	// position of a character encodes it as a 5-bit symbol plus a group
	// number, which is what lets the checksum detect common typos.
	inputCharset = "0123456789()[],'/*abcdefgh@:$%{}" +
		"IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
		"ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

	// checksumCharset is the BIP380 character set of the checksum itself.
	checksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

// checksumGenerator holds the BCH generator constants from BIP380.
var checksumGenerator = [5]uint64{
	0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd,
}

// polymod runs the BIP380 BCH code over a symbol stream.
func polymod(symbols []uint64) uint64 {
	chk := uint64(1)
	for _, value := range symbols {
		top := chk >> 35
		chk = (chk&0x7ffffffff)<<5 ^ value
		for i, gen := range checksumGenerator {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen
			}
		}
	}

	return chk
}

// expand converts descriptor text into BIP380 checksum symbols. It fails on
// any character outside inputCharset.
func expand(text string) ([]uint64, error) {
	symbols := make([]uint64, 0, len(text)+len(text)/3+checksumLen)
	groups := make([]uint64, 0, 3)
	for i, c := range text {
		pos := strings.IndexRune(inputCharset, c)
		if pos < 0 {
			return nil, fmt.Errorf("%w: invalid character %q at "+
				"offset %d", ErrMalformedDescriptor, c, i)
		}

		symbols = append(symbols, uint64(pos&31))
		groups = append(groups, uint64(pos>>5))
		if len(groups) == 3 {
			symbols = append(
				symbols, groups[0]*9+groups[1]*3+groups[2],
			)
			groups = groups[:0]
		}
	}

	switch len(groups) {
	case 1:
		symbols = append(symbols, groups[0])

	case 2:
		symbols = append(symbols, groups[0]*3+groups[1])
	}

	return symbols, nil
}

// Checksum returns the eight-character BIP380 checksum of descriptor text.
// The text must not already carry a checksum.
func Checksum(text string) (string, error) {
	symbols, err := expand(text)
	if err != nil {
		return "", err
	}

	symbols = append(symbols, make([]uint64, checksumLen)...)
	value := polymod(symbols) ^ 1

	out := make([]byte, checksumLen)
	for i := range out {
		shift := uint(5 * (checksumLen - 1 - i))
		out[i] = checksumCharset[(value>>shift)&31]
	}

	return string(out), nil
}

// AddChecksum returns text with its BIP380 checksum appended after '#'.
func AddChecksum(text string) (string, error) {
	sum, err := Checksum(text)
	if err != nil {
		return "", err
	}

	return text + "#" + sum, nil
}

// splitChecksum separates descriptor text from an optional trailing
// checksum, verifying the checksum when one is present.
func splitChecksum(text string) (string, error) {
	body, sum, found := strings.Cut(text, "#")
	if !found {
		return text, nil
	}

	if len(sum) != checksumLen {
		return "", fmt.Errorf("%w: checksum must be %d "+
			"characters, got %d", ErrBadChecksum, checksumLen,
			len(sum))
	}

	want, err := Checksum(body)
	if err != nil {
		return "", err
	}

	if sum != want {
		return "", fmt.Errorf("%w: got %s", ErrBadChecksum, sum)
	}

	return body, nil
}
