package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShred(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Passwords.csv")
	os.WriteFile(p, make([]byte, 200<<10), 0o600)
	if err := Shred(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
	if err := Shred(t.TempDir()); err == nil {
		t.Fatal("shredded a directory")
	}
}

func TestSyncedFolder(t *testing.T) {
	home := t.TempDir()
	for path, want := range map[string]string{
		"/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Passwords.csv":   "iCloud Drive",
		"/Users/me/Library/CloudStorage/Dropbox/Passwords.csv":                   "Dropbox",
		"/Users/me/Library/CloudStorage/GoogleDrive-me@gmail.com/My Drive/x.csv": "Google Drive",
		"/Users/me/Library/CloudStorage/OneDrive-Personal/x.csv":                 "OneDrive",
		"/Users/me/Downloads/Passwords.csv":                                      "",
	} {
		if got := SyncedFolder(path, home); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	desk := filepath.Join(home, "Desktop", "Passwords.csv")
	if got := SyncedFolder(desk, home); got != "" {
		t.Errorf("Desktop without iCloud Desktop: %q", got)
	}
	os.MkdirAll(filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "Desktop"), 0o755)
	if got := SyncedFolder(desk, home); got != "iCloud Drive (Desktop & Documents)" {
		t.Errorf("Desktop with iCloud Desktop: %q", got)
	}
}
