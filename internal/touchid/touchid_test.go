package touchid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gingered-cat/asiri/internal/approvalkey"
)

// fakeHelper is a shell script with asiri-touchid's interface and exit codes.
func fakeHelper(t *testing.T) (string, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	script := `#!/bin/sh
case "$1" in
  available) echo "no Secure Enclave" >&2; exit 4 ;;
  pubkey|create) echo "` + base64.StdEncoding.EncodeToString(pub) + `" ;;
  sign)
    stmt=$(cat)
    case "$stmt" in
      *cancel*) echo "asiri-touchid: not approved: Canceled by user." >&2; exit 3 ;;
      *) printf 'c2lnbmVk\n' ;;
    esac ;;
  *) echo "asiri-touchid: usage" >&2; exit 2 ;;
esac
`
	p := filepath.Join(t.TempDir(), HelperName)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p, pub
}

func TestKey(t *testing.T) {
	ctx := context.Background()
	helper, pub := fakeHelper(t)
	k := &Key{Helper: helper, File: "unused"}
	id, err := k.KeyID(ctx)
	if err != nil || id != approvalkey.ID(pub) {
		t.Fatalf("key id = %q, %v", id, err)
	}
	sig, err := k.Sign(ctx, []byte("asiri approval v1\n"))
	if err != nil || string(sig) != "signed" {
		t.Fatalf("sign = %q, %v", sig, err)
	}
	if _, err := k.Sign(ctx, []byte("please cancel")); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("cancel: %v", err)
	}
	if err := Available(ctx, helper); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("available: %v", err)
	}
	if _, err := Create(ctx, helper, filepath.Join(t.TempDir(), "k")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := (&Key{Helper: helper}).run(ctx, nil, "bogus"); err == nil || errors.Is(err, ErrNotApproved) {
		t.Fatalf("usage error: %v", err)
	}
}
