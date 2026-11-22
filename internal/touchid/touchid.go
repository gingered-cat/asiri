// Package touchid runs asiri-touchid, the small Swift helper that keeps an
// approval key in the Mac's Secure Enclave (macos/touchid/main.swift). The
// asiri binary itself is pure Go; everything that needs Apple's frameworks
// lives in the helper.
package touchid

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/gingered-cat/asiri/internal/approvalkey"
	"github.com/gingered-cat/asiri/internal/client"
)

// HelperName is the helper's file name, installed next to asiri.
const HelperName = "asiri-touchid"

// KeyFileName is the approval key handle in a profile's directory.
const KeyFileName = "approval.key"

var (
	// ErrNotApproved means the person cancelled, or authentication failed.
	ErrNotApproved = errors.New("not approved: Touch ID was cancelled or failed")
	// ErrUnavailable means this Mac can't hold or use an approval key now.
	ErrUnavailable = errors.New("this Mac can't use Touch ID or its password for asiri right now")
	// ErrNoHelper means asiri-touchid isn't installed.
	ErrNoHelper = errors.New("asiri-touchid isn't installed next to asiri; run `asiri update` (or the install script), or `go run ./dev bin` from a clone")
)

// FindHelper looks for asiri-touchid: $ASIRI_TOUCHID, next to the running
// asiri, then on PATH. A substitute helper can't forge an approval: the
// server checks every signature against the enrolled public key.
func FindHelper() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("Touch ID approvals need macOS")
	}
	if p := os.Getenv("ASIRI_TOUCHID"); p != "" {
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			p := filepath.Join(filepath.Dir(exe), HelperName)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, nil
			}
		}
	}
	if p, err := exec.LookPath(HelperName); err == nil {
		return p, nil
	}
	return "", ErrNoHelper
}

// Key is one approval key: the helper and the key handle file.
type Key struct {
	Helper string
	File   string

	once sync.Once
	pub  []byte
	err  error
}

// ForProfile returns the profile's key, or nil if this machine can't sign
// (not macOS, no helper, or no key created yet).
func ForProfile(p *client.Profile) *Key {
	helper, err := FindHelper()
	if err != nil {
		return nil
	}
	file := filepath.Join(p.Dir, KeyFileName)
	if _, err := os.Stat(file); err != nil {
		return nil
	}
	return &Key{Helper: helper, File: file}
}

func (k *Key) run(ctx context.Context, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, k.Helper, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(stderr.String()), "asiri-touchid: "))
		if errors.As(err, &ee) {
			switch ee.ExitCode() {
			case 3:
				return "", ErrNotApproved
			case 4:
				return "", fmt.Errorf("%w: %s", ErrUnavailable, msg)
			}
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("asiri-touchid %s: %s", args[0], msg)
	}
	return strings.TrimSpace(string(out)), nil
}

// Available reports whether this Mac can hold and use an approval key.
func Available(ctx context.Context, helper string) error {
	_, err := (&Key{Helper: helper}).run(ctx, nil, "available")
	return err
}

// Create makes a new Secure Enclave key in file and returns its public key.
// It does not prompt; using the key does.
func Create(ctx context.Context, helper, file string) (*Key, error) {
	k := &Key{Helper: helper, File: file}
	out, err := k.run(ctx, nil, "create", file)
	if err != nil {
		return nil, err
	}
	pub, err := decodePublicKey(out)
	if err != nil {
		return nil, err
	}
	k.once.Do(func() { k.pub = pub })
	return k, nil
}

func decodePublicKey(s string) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("asiri-touchid printed a bad public key: %w", err)
	}
	if _, err := approvalkey.ParsePublicKey(der); err != nil {
		return nil, err
	}
	return der, nil
}

// PublicKey is the key's public half (PKIX DER). It needs no prompt.
func (k *Key) PublicKey(ctx context.Context) ([]byte, error) {
	k.once.Do(func() {
		var out string
		if out, k.err = k.run(ctx, nil, "pubkey", k.File); k.err == nil {
			k.pub, k.err = decodePublicKey(out)
		}
	})
	return k.pub, k.err
}

// KeyID implements client.Signer.
func (k *Key) KeyID(ctx context.Context) (string, error) {
	pub, err := k.PublicKey(ctx)
	if err != nil {
		return "", err
	}
	return approvalkey.ID(pub), nil
}

// Sign implements client.Signer. The helper shows the person what the
// statement allows and waits for Touch ID or the Mac's password.
func (k *Key) Sign(ctx context.Context, statement []byte) ([]byte, error) {
	out, err := k.run(ctx, statement, "sign", k.File)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, fmt.Errorf("asiri-touchid printed a bad signature: %w", err)
	}
	return sig, nil
}

var _ client.Signer = (*Key)(nil)
