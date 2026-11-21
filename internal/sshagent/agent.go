// Package sshagent is an SSH agent whose keys live in the asiri server. It
// never holds a private key: it lists public keys, learns which host ssh is
// signing in to (OpenSSH's session-bind extension, 8.9+), asks for a grant
// bound to that host's key, and has the server sign.
package sshagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/domain"
)

// API is the part of the asiri server the agent needs.
type API interface {
	SSHKeys(ctx context.Context) ([]domain.Item, error)
	SSHSign(ctx context.Context, gid domain.GrantID, data []byte, flags uint32) (api.SSHSignature, error)
}

// Granter gets a grant for a request, asking a person if needed.
type Granter interface {
	Grant(ctx context.Context, req api.CreateRequest) (domain.GrantID, error)
}

// Agent serves the agent protocol, one session per connection.
type Agent struct {
	API     API
	Granter Granter
	Reason  string    // shown with every request
	Cwd     string    // shown with every request
	Log     io.Writer // one line per sign-in, and refusals
}

// ErrNotSupported answers anything that would put a key into the agent.
var ErrNotSupported = errors.New("asiri keeps keys in its server; add them with `asiri add --ssh-generate` or `asiri add --kind ssh_key`")

const sessionBind = "session-bind@openssh.com"

// Listen makes a unix socket at path that only this user can use.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path) // stale socket from a previous run
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve answers connections on ln until ctx ends or ln closes.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			agent.ServeAgent(&session{a: a, ctx: ctx}, c)
		}()
	}
}

// session is one agent connection, usually one ssh process.
type session struct {
	a   *Agent
	ctx context.Context

	mu        sync.Mutex
	hostFP    string
	sessionID []byte
	forwarded bool
	refs      map[string]domain.Ref // public key blob → item
}

func (s *session) logf(format string, args ...any) {
	if s.a.Log != nil {
		fmt.Fprintf(s.a.Log, "asiri: "+format+"\n", args...)
	}
}

// List returns the asiri SSH keys. Once ssh has said which host it is
// signing in to, only keys allowed on that host are offered.
func (s *session) List() ([]*agent.Key, error) {
	items, err := s.a.API.SSHKeys(s.ctx)
	if err != nil {
		s.logf("can't list SSH keys: %v", err)
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs = map[string]domain.Ref{}
	var keys []*agent.Key
	for _, it := range items {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(it.PublicKey))
		if err != nil {
			continue
		}
		if s.hostFP != "" {
			if _, ok := domain.SSHHostAllowed(it.Policy.SSHHosts, s.hostFP); !ok {
				continue
			}
		}
		s.refs[string(pub.Marshal())] = it.Ref
		keys = append(keys, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: it.Ref.String()})
	}
	return keys, nil
}

func (s *session) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

func (s *session) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s.mu.Lock()
	ref, known := s.refs[string(key.Marshal())]
	hostFP, sessionID, forwarded := s.hostFP, s.sessionID, s.forwarded
	s.mu.Unlock()
	if !known {
		if _, err := s.List(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		ref, known = s.refs[string(key.Marshal())]
		s.mu.Unlock()
		if !known {
			return nil, errors.New("not an asiri key")
		}
	}
	if hostFP == "" {
		s.logf("refused %s: ssh didn't say which host it's signing in to (asiri needs OpenSSH 8.9 or newer)", ref)
		return nil, errors.New("no session-bind")
	}
	if forwarded {
		s.logf("refused %s: asiri keys can't be used through agent forwarding", ref)
		return nil, errors.New("forwarded")
	}
	if !signsSession(data, sessionID) {
		s.logf("refused %s: asiri only signs SSH logins to the bound host, not other data", ref)
		return nil, errors.New("not a login for the bound session")
	}
	gid, err := s.a.Granter.Grant(s.ctx, api.CreateRequest{Ref: ref, BinPath: "ssh", HostFP: hostFP, Cwd: s.a.Cwd, Reason: s.a.Reason})
	if err != nil {
		s.logf("%v", err)
		return nil, err
	}
	sig, err := s.a.API.SSHSign(s.ctx, gid, data, uint32(flags))
	if err != nil {
		s.logf("signing with %s failed: %v", ref, err)
		return nil, err
	}
	return &ssh.Signature{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}, nil
}

// signsSession reports whether data is SSH user-auth data for sessionID:
// it starts with the session identifier as an SSH string (RFC 4252 §7).
func signsSession(data, sessionID []byte) bool {
	prefix := ssh.Marshal(struct{ S []byte }{sessionID})
	return len(sessionID) > 0 && bytes.HasPrefix(data, prefix)
}

type bindMsg struct {
	HostKey    []byte
	SessionID  []byte
	Signature  []byte
	Forwarding bool
}

// Extension handles session-bind: ssh tells the agent the host key and
// session, signed by the host, so the agent knows where a login goes.
func (s *session) Extension(typ string, contents []byte) ([]byte, error) {
	if typ != sessionBind {
		return nil, agent.ErrExtensionUnsupported
	}
	var m bindMsg
	if err := ssh.Unmarshal(contents, &m); err != nil {
		return nil, fmt.Errorf("bad session-bind: %w", err)
	}
	hk, err := ssh.ParsePublicKey(m.HostKey)
	if err != nil {
		return nil, fmt.Errorf("bad host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(m.Signature, &sig); err != nil {
		return nil, fmt.Errorf("bad session-bind signature: %w", err)
	}
	if err := hk.Verify(m.SessionID, &sig); err != nil {
		return nil, fmt.Errorf("session-bind signature doesn't verify: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Forwarding || (s.sessionID != nil && !bytes.Equal(s.sessionID, m.SessionID)) {
		s.forwarded = true
	}
	s.hostFP, s.sessionID = ssh.FingerprintSHA256(hk), m.SessionID
	return nil, nil
}

func (s *session) Add(agent.AddedKey) error       { return ErrNotSupported }
func (s *session) Remove(ssh.PublicKey) error     { return ErrNotSupported }
func (s *session) RemoveAll() error               { return ErrNotSupported }
func (s *session) Lock([]byte) error              { return ErrNotSupported }
func (s *session) Unlock([]byte) error            { return ErrNotSupported }
func (s *session) Signers() ([]ssh.Signer, error) { return nil, ErrNotSupported }

var _ agent.ExtendedAgent = (*session)(nil)
