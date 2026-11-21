package importer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Shred overwrites a file with zeros, flushes it, and removes it.
//
// Best effort: APFS is copy-on-write and SSDs remap blocks, so old copies of
// the data can survive on the disk until reused. Disk encryption (FileVault)
// is what really protects them; this keeps the file from simply sitting there.
func Shred(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New(path + " is not a regular file")
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	zeros := make([]byte, 64<<10)
	for left := fi.Size(); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			f.Close()
			return err
		}
		left -= n
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// SyncedFolder names the cloud service that syncs path, or "". A file there
// has probably been uploaded already, and the service may keep old versions.
func SyncedFolder(path, home string) string {
	p, err := filepath.Abs(path)
	if err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
	}
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(p, "/Library/Mobile Documents/"):
		return "iCloud Drive"
	case strings.Contains(lower, "/library/cloudstorage/dropbox"), strings.Contains(lower, "/dropbox/"):
		return "Dropbox"
	case strings.Contains(lower, "/library/cloudstorage/googledrive"), strings.Contains(lower, "/google drive/"):
		return "Google Drive"
	case strings.Contains(lower, "/library/cloudstorage/onedrive"), strings.Contains(lower, "/onedrive"):
		return "OneDrive"
	case strings.Contains(p, "/Library/CloudStorage/"):
		return "a cloud storage provider"
	}
	// With iCloud "Desktop & Documents Folders" on, ~/Desktop and
	// ~/Documents are uploaded too.
	if home != "" {
		icloudDesktop := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "Desktop")
		if _, err := os.Stat(icloudDesktop); err == nil {
			for _, d := range []string{"Desktop", "Documents"} {
				if strings.HasPrefix(p, filepath.Join(home, d)+string(os.PathSeparator)) {
					return "iCloud Drive (Desktop & Documents)"
				}
			}
		}
	}
	return ""
}

// TimeMachineOn reports whether macOS has a Time Machine destination set up.
func TimeMachineOn() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	out, err := exec.Command("tmutil", "destinationinfo").Output()
	return err == nil && strings.Contains(string(out), "Name")
}
