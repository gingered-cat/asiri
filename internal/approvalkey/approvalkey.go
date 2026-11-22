// Package approvalkey builds and checks signed approvals.
//
// An approval key is a P-256 key held by the Secure Enclave of the person's
// Mac; using it takes Touch ID or the Mac's password. Once a server has an
// approval key enrolled, it only accepts an "allow" decision that carries a
// signature by that key over the request's approval statement. Holding the
// owner profile's certificate is no longer enough to approve.
//
// The statement is built by the server, never by the client, and the helper
// that signs it shows the person a sentence derived from the statement
// itself, so what is shown is what is signed.
package approvalkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	approvalHeader = "asiri approval v1"
	enrollHeader   = "asiri approval key v1"
)

// Actions an approval statement can allow. A statement names its action so
// later kinds (paying, leasing) can be added without a new format; a helper
// that doesn't know an action refuses to sign it.
const (
	ActionUse = "use" // a program receives the secret (asiri run, MCP)
	ActionSSH = "ssh" // an SSH key signs a login to one host
)

// Request is what an approval statement binds.
type Request struct {
	Action    string // ActionUse or ActionSSH
	Server    string // server CA fingerprint
	ID        string
	Client    string // client name, e.g. claude
	ClientID  string // stable client ID; a re-paired name gets a new one
	Ref       string // asiri://vault/name[/field]
	Program   string // absolute path of the program that gets the secret
	SHA256    string // hex SHA-256 of that program
	HostFP    string // SSH requests: destination host key; else ""
	Decision  string // once, 15m or 1h
	ExpiresAt time.Time
}

// Statement is the exact text an approval key signs to allow r.
func Statement(r Request) []byte {
	return lines(approvalHeader,
		"action", r.Action,
		"server", r.Server,
		"request", r.ID,
		"client", r.Client,
		"client_id", r.ClientID,
		"secret", r.Ref,
		"program", r.Program,
		"program_sha256", r.SHA256,
		"host", r.HostFP,
		"decision", r.Decision,
		"expires", r.ExpiresAt.UTC().Format(time.RFC3339),
	)
}

// EnrollStatement is the text a new key signs to prove it is the key being
// enrolled, and an existing key signs to endorse it.
func EnrollStatement(server string, publicKey []byte) []byte {
	return lines(enrollHeader, "server", server, "key", ID(publicKey))
}

// lines writes "header\nkey: value\n…". Values that contain control
// characters are quoted, so a value can never start a new line and pose as
// another field.
func lines(header string, kv ...string) []byte {
	var b strings.Builder
	b.WriteString(header)
	b.WriteByte('\n')
	for i := 0; i < len(kv); i += 2 {
		b.WriteString(kv[i])
		b.WriteString(": ")
		b.WriteString(clean(kv[i+1]))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func clean(v string) string {
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == ' ' || r == ' ' {
			return strconv.QuoteToASCII(v)
		}
	}
	return v
}

// ID names a public key: the first 16 hex digits of the SHA-256 of its DER.
func ID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKey accepts a P-256 public key in PKIX (SubjectPublicKeyInfo)
// DER form, which is what the Secure Enclave helper prints.
func ParsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("approval key: %w", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("approval key: want an ECDSA P-256 key")
	}
	return ek, nil
}

// Verify checks an ASN.1 (DER) ECDSA signature over SHA-256(msg).
func Verify(publicKey, msg, sig []byte) error {
	k, err := ParsePublicKey(publicKey)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(k, sum[:], sig) {
		return errors.New("signature doesn't match")
	}
	return nil
}

// Describe is the sentence a person sees before signing msg, as in
// "allow claude to use asiri://dev/github with /usr/bin/gh once". The Swift
// helper implements the same rules; tests keep the two in step.
func Describe(msg []byte) (string, error) {
	text := string(msg)
	header, body, _ := strings.Cut(text, "\n")
	f := map[string]string{}
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			return "", errors.New("malformed statement")
		}
		if _, dup := f[k]; dup {
			return "", errors.New("malformed statement")
		}
		f[k] = v
	}
	switch header {
	case approvalHeader:
		when := map[string]string{"once": "once", "15m": "for 15 minutes", "1h": "for 1 hour"}[f["decision"]]
		if when == "" || f["client"] == "" || f["secret"] == "" || f["program"] == "" {
			return "", errors.New("malformed statement")
		}
		switch f["action"] {
		case ActionUse:
			return "allow " + f["client"] + " to use " + f["secret"] + " with " + f["program"] + " " + when, nil
		case ActionSSH:
			if f["host"] == "" {
				return "", errors.New("malformed statement")
			}
			return "allow " + f["client"] + " to sign in to host " + f["host"] + " with " + f["secret"] +
				" using " + f["program"] + " " + when, nil
		}
		return "", errors.New("unknown action")
	case enrollHeader:
		if f["key"] == "" {
			return "", errors.New("malformed statement")
		}
		return "use this Mac to approve asiri requests (key " + f["key"] + ")", nil
	}
	return "", errors.New("not an asiri statement")
}
