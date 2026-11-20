package domain

import (
	"regexp"
	"strings"
)

// RefScheme prefixes every secret reference.
const RefScheme = "asiri://"

// DefaultField is used when a reference names no field.
const DefaultField = "value"

// Ref names a secret without containing it: asiri://<vault>/<name>[/<field>].
// Refs are safe to put in chat, configs and commits.
type Ref struct {
	Vault string
	Name  string
	Field string
}

var segment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ParseRef accepts "asiri://vault/name[/field]" or the short "vault/name[/field]".
func ParseRef(s string) (Ref, error) {
	body := strings.TrimPrefix(s, RefScheme)
	parts := strings.Split(body, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return Ref{}, Errorf(CodeInvalid, "reference %q: want asiri://vault/name[/field]", s)
	}
	if len(parts) == 2 {
		parts = append(parts, DefaultField)
	}
	for _, p := range parts {
		if !segment.MatchString(p) {
			return Ref{}, Errorf(CodeInvalid, "reference %q: %q must be 1-64 letters, digits, '.', '_' or '-'", s, p)
		}
	}
	return Ref{Vault: parts[0], Name: parts[1], Field: parts[2]}, nil
}

// String prints the canonical form, leaving out the default field.
func (r Ref) String() string {
	s := RefScheme + r.Vault + "/" + r.Name
	if r.Field != DefaultField {
		s += "/" + r.Field
	}
	return s
}

func (r Ref) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Ref) UnmarshalText(b []byte) error {
	p, err := ParseRef(string(b))
	if err != nil {
		return err
	}
	*r = p
	return nil
}
