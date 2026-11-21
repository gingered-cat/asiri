//go:build unix

package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

// fifoPrefix names asiri's temporary pipe directories, so stale ones can be
// found and removed.
const fifoPrefix = "asiri-fifo-"

func (f File) Apply(cmd *exec.Cmd, s domain.Secret) (func(), error) {
	dir, err := os.MkdirTemp("", fifoPrefix)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	path := filepath.Join(dir, strings.ToLower(f.Name))
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	b := append([]byte(nil), s.Reveal()...)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Open blocks until the child opens the pipe for reading. The value
		// is written once: the file can be read one time.
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		w.Write(b)
		w.Close()
	}()
	cmd.Env = append(cmd.Env, f.Name+"="+path)
	return func() {
		// Unblock a writer still waiting for a reader.
		if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			r.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		clear(b)
		os.RemoveAll(dir)
	}, nil
}

// CleanStale removes pipe directories left behind by a crash, older than an hour.
func CleanStale() {
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), fifoPrefix+"*"))
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && time.Since(fi.ModTime()) > time.Hour {
			os.RemoveAll(m)
		}
	}
}
