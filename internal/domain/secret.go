package domain

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Secret holds a secret value. Printing, logging or JSON-encoding it gives
// "[redacted]"; only Reveal returns the bytes. Call Zero when done.
type Secret struct{ b []byte }

// NewSecret takes ownership of b.
func NewSecret(b []byte) Secret { return Secret{b: b} }

func (s Secret) Reveal() []byte { return s.b }
func (s Secret) Len() int       { return len(s.b) }

// Zero overwrites the bytes. Best effort: Go may have copied them before.
func (s Secret) Zero() { clear(s.b) }

func (Secret) String() string                { return redacted }
func (Secret) GoString() string              { return redacted }
func (Secret) LogValue() slog.Value          { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error)  { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error)  { return []byte(redacted), nil }
func (Secret) Format(f fmt.State, verb rune) { io.WriteString(f, redacted) }
