package domain

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Distinct ID types so an item ID can't be passed where a client ID belongs.
type (
	ItemID   string
	ClientID string
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID: 48 bits of Unix milliseconds followed by 80 random
// bits, written in Crockford base32. IDs sort by creation time and need no
// coordination.
func NewID() string { return newIDAt(time.Now()) }

func newIDAt(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	rand.Read(b[6:])
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}
