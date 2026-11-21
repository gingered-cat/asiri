package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake GitHub API and release downloads.
func release(t *testing.T, tag string, bin []byte, sums string) Source {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"` + tag + `"}`))
	})
	mux.HandleFunc("/dl/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums)) })
	mux.HandleFunc("/dl/"+tag+"/"+AssetName(tag, "darwin", "arm64"), func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Source{API: srv.URL + "/api", Download: srv.URL + "/dl", GOOS: "darwin", GOARCH: "arm64"}
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestFetchVerifies(t *testing.T) {
	ctx := context.Background()
	bin := []byte("#!/bin/sh\necho new asiri\n")
	name := AssetName("v0.2.0", "darwin", "arm64")
	// v0.1.0 wrote paths like ./darwin-arm64/asiri-…; match by base name.
	src := release(t, "v0.2.0", bin, sum(bin)+"  ./darwin-arm64/"+name+"\nabc  other\n")
	if tag, err := src.Latest(ctx); err != nil || tag != "v0.2.0" {
		t.Fatalf("latest %q %v", tag, err)
	}
	got, err := src.Fetch(ctx, "v0.2.0")
	if err != nil || string(got) != string(bin) {
		t.Fatalf("fetch: %v", err)
	}

	bad := release(t, "v0.2.0", bin, strings.Repeat("0", 64)+"  "+name+"\n")
	if _, err := bad.Fetch(ctx, "v0.2.0"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered binary accepted: %v", err)
	}
	missing := release(t, "v0.2.0", bin, sum(bin)+"  asiri-v0.2.0-linux-amd64\n")
	if _, err := missing.Fetch(ctx, "v0.2.0"); err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("missing checksum: %v", err)
	}
	if _, err := src.Fetch(ctx, "v9.9.9"); err == nil || !strings.Contains(err.Error(), "doesn't exist") {
		t.Fatalf("unknown version: %v", err)
	}
	if _, err := src.Fetch(ctx, "latest; rm -rf"); err == nil {
		t.Fatal("bad tag accepted")
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "asiri")
	os.WriteFile(target, []byte("old"), 0o755)
	if err := Replace(target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	fi, _ := os.Stat(target)
	if string(b) != "new" || fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("content %q mode %v", b, fi.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".asiri-update-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.0", true}, {"v0.1.0", "v0.1.0", false}, {"v0.1.0", "v0.2.0", false},
		{"v0.10.0", "v0.9.9", true}, {"v1.0.0", "dev", true}, {"dev", "v0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
