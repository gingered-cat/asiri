package vault

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

var ctx = context.Background()

func testKDF(mode string) KDF {
	k := NewKDF(mode)
	if mode == ModePassphrase {
		k.Time, k.MemoryKiB, k.Threads = 1, 1024, 1 // fast for tests
	}
	return k
}

func newVault(t *testing.T) (*Store, *Vault, []byte, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	v := New(s)
	key := randomKey()
	var vk []byte
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		vk, err = v.InitTx(ctx, tx, testKDF(ModeKeyFile), key)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	v.Unseal(vk)
	return s, v, key, path
}

func put(t *testing.T, s *Store, v *Vault, ref string, value string) domain.Item {
	t.Helper()
	r, err := domain.ParseRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	var it domain.Item
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		it, err = v.PutTx(ctx, tx, r, "", domain.NewSecret([]byte(value)), time.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func TestPutGetVersions(t *testing.T) {
	s, v, _, _ := newVault(t)
	a := put(t, s, v, "dev/github", "ghp_one")
	b := put(t, s, v, "dev/github", "ghp_two")
	if a.ID != b.ID || a.Version != 1 || b.Version != 2 {
		t.Fatalf("versions: %+v %+v", a, b)
	}
	ref, _ := domain.ParseRef("dev/github")
	it, sec, err := v.Get(ctx, ref)
	if err != nil || string(sec.Reveal()) != "ghp_two" || it.Version != 2 {
		t.Fatalf("Get = %+v %q %v", it, sec.Reveal(), err)
	}
	items, err := v.List(ctx, "")
	if err != nil || len(items) != 1 || items[0].Version != 2 || items[0].Kind != domain.KindToken {
		t.Fatalf("List = %+v %v", items, err)
	}
	if items, _ := v.List(ctx, "GITH"); len(items) != 1 {
		t.Fatalf("query match failed: %+v", items)
	}
	if items, _ := v.List(ctx, "nope"); len(items) != 0 {
		t.Fatalf("query should not match: %+v", items)
	}
}

func TestSealed(t *testing.T) {
	s, v, key, _ := newVault(t)
	put(t, s, v, "dev/a", "x")
	v.Seal()
	ref, _ := domain.ParseRef("dev/a")
	if _, _, err := v.Get(ctx, ref); domain.CodeOf(err) != domain.CodeSealed {
		t.Fatalf("Get while sealed: %v", err)
	}
	if err := v.Unlock(ctx, randomKey()); domain.CodeOf(err) != domain.CodeNotAllowed {
		t.Fatalf("wrong key: %v", err)
	}
	if err := v.Unlock(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, sec, err := v.Get(ctx, ref); err != nil || string(sec.Reveal()) != "x" {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestPassphraseMode(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v := New(s)
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		_, err := v.InitTx(ctx, tx, testKDF(ModePassphrase), []byte("correct horse"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(ctx, []byte("wrong")); domain.CodeOf(err) != domain.CodeNotAllowed {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := v.Unlock(ctx, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	if m, _ := v.Mode(ctx); m != ModePassphrase {
		t.Fatalf("mode %q", m)
	}
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		_, err := v.InitTx(ctx, tx, testKDF(ModePassphrase), []byte("again"))
		return err
	})
	if domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("second init: %v", err)
	}
}

// Moving one item's ciphertext onto another must fail to decrypt (AAD binding).
func TestCiphertextSwapDetected(t *testing.T) {
	s, v, _, _ := newVault(t)
	a := put(t, s, v, "dev/a", "value-a")
	put(t, s, v, "dev/b", "value-b")
	_, err := s.w.ExecContext(ctx, `UPDATE items SET ciphertext = (SELECT ciphertext FROM items WHERE id = ?),
		nonce = (SELECT nonce FROM items WHERE id = ?), wrapped_dek = (SELECT wrapped_dek FROM items WHERE id = ?),
		dek_nonce = (SELECT dek_nonce FROM items WHERE id = ?) WHERE name = 'b'`, a.ID, a.ID, a.ID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := domain.ParseRef("dev/b")
	if _, sec, err := v.Get(ctx, ref); err == nil {
		t.Fatalf("swapped ciphertext decrypted to %q", sec.Reveal())
	}
}

// The database files on disk must never contain a value in plaintext.
func TestNoPlaintextOnDisk(t *testing.T) {
	s, v, key, path := newVault(t)
	const marker = "PLAINTEXT-MARKER-7f3a9c"
	for i := range 20 {
		put(t, s, v, "dev/item"+string(rune('a'+i)), marker)
	}
	matches, _ := filepath.Glob(path + "*")
	if len(matches) == 0 {
		t.Fatal("no db files")
	}
	for _, f := range matches {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(marker)) {
			t.Fatalf("%s contains a plaintext value", filepath.Base(f))
		}
		if bytes.Contains(b, key) {
			t.Fatalf("%s contains the key file bytes", filepath.Base(f))
		}
		if info, _ := os.Stat(f); filepath.Base(f) == "vault.db" && info.Mode().Perm() != 0o600 {
			t.Fatalf("vault.db mode %v", info.Mode().Perm())
		}
	}
}

func TestKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, NewKeyFile(), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeyFile(p)
	if err != nil || len(k) != 32 {
		t.Fatalf("ReadKeyFile = %d bytes, %v", len(k), err)
	}
	os.WriteFile(p, []byte("not a key"), 0o600)
	if _, err := ReadKeyFile(p); err == nil {
		t.Fatal("bad key file accepted")
	}
}
