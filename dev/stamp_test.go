package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStamp(t *testing.T) {
	dir := t.TempDir()
	page := `<link rel="stylesheet" href="/style.css"><link href="/docs/docs.v2.css"><script src="/docs/docs.js" type="module"></script><script src="/app.js?v=0123abc" defer></script><a href="/style.css.map">`
	os.MkdirAll(filepath.Join(dir, "docs"), 0o755)
	os.WriteFile(filepath.Join(dir, "docs", "index.html"), []byte(page), 0o644)
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte(`href="/style.css"`), 0o644)
	n, err := stamp(dir, "abcdef123456")
	if err != nil || n != 4 {
		t.Fatalf("stamped %d, %v", n, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "docs", "index.html"))
	for _, want := range []string{`/style.css?v=abcdef123456"`, `/docs/docs.v2.css?v=abcdef123456"`, `/docs/docs.js?v=abcdef123456"`, `/app.js?v=abcdef123456"`, `/style.css.map"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if sh, _ := os.ReadFile(filepath.Join(dir, "install.sh")); string(sh) != `href="/style.css"` {
		t.Error("touched a non-HTML file")
	}
	if _, err := stamp(dir, "not-a-hash"); err == nil {
		t.Error("bad version accepted")
	}
}
