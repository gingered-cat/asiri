package server

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gingered-cat/asiri/internal/pki"
)

// DataDir is the server's data volume:
//
//	vault.db                 encrypted items, clients, audit (SQLite)
//	tls/ca.crt, tls/ca.key   the CA that signs client certificates
//	tls/server.crt, .key     the server's TLS identity
//
// The TLS keys are plain files (0600). They identify the server and its
// clients; they don't decrypt anything. Values stay encrypted under the
// vault key, which never touches this directory.
type DataDir string

func (d DataDir) DB() string              { return filepath.Join(string(d), "vault.db") }
func (d DataDir) path(name string) string { return filepath.Join(string(d), "tls", name) }

// EnsureTLS loads the CA and server certificate, creating them on first run.
func (d DataDir) EnsureTLS(hosts []string, now time.Time) (ca *pki.CA, certPEM, keyPEM []byte, err error) {
	if err := os.MkdirAll(filepath.Join(string(d), "tls"), 0o700); err != nil {
		return nil, nil, nil, err
	}
	if _, err := os.Stat(d.path("ca.crt")); errors.Is(err, fs.ErrNotExist) {
		ca, caKey, err := pki.NewCA(now)
		if err != nil {
			return nil, nil, nil, err
		}
		certPEM, keyPEM, err := ca.IssueServer(hosts, now)
		if err != nil {
			return nil, nil, nil, err
		}
		for name, b := range map[string][]byte{"ca.key": caKey, "server.crt": certPEM, "server.key": keyPEM, "ca.crt": ca.CertPEM} {
			if err := writeNew(d.path(name), b); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if ca, err = d.LoadCA(); err != nil {
		return nil, nil, nil, err
	}
	if certPEM, err = os.ReadFile(d.path("server.crt")); err != nil {
		return nil, nil, nil, err
	}
	if keyPEM, err = os.ReadFile(d.path("server.key")); err != nil {
		return nil, nil, nil, err
	}
	return ca, certPEM, keyPEM, nil
}

// LoadCA reads the CA written by EnsureTLS.
func (d DataDir) LoadCA() (*pki.CA, error) {
	certPEM, err := os.ReadFile(d.path("ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("no CA in %s (has the server been initialized?): %w", d, err)
	}
	keyPEM, err := os.ReadFile(d.path("ca.key"))
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	return pki.LoadCA(certPEM, keyPEM)
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
