package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/domain"
)

// fakeServer holds one key and signs with it, as the asiri server would.
type fakeServer struct {
	key      ssh.Signer
	hosts    []string
	requests []api.CreateRequest
}

func (f *fakeServer) SSHKeys(context.Context) ([]domain.Item, error) {
	ref, _ := domain.ParseRef("ops/staging")
	return []domain.Item{{Ref: ref, Kind: domain.KindSSHKey, PublicKey: string(ssh.MarshalAuthorizedKey(f.key.PublicKey())),
		Policy: domain.Policy{SSHHosts: f.hosts}}}, nil
}

func (f *fakeServer) SSHSign(_ context.Context, _ domain.GrantID, data []byte, _ uint32) (api.SSHSignature, error) {
	sig, err := f.key.Sign(rand.Reader, data)
	return api.SSHSignature{Format: sig.Format, Blob: sig.Blob}, err
}

func (f *fakeServer) Grant(_ context.Context, req api.CreateRequest) (domain.GrantID, error) {
	f.requests = append(f.requests, req)
	return "G1", nil
}

func signer(t *testing.T) ssh.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func connect(t *testing.T, f *fakeServer, log *strings.Builder) agent.ExtendedAgent {
	t.Helper()
	a := &Agent{API: f, Granter: f, Log: log, Reason: "deploy"}
	c1, c2 := net.Pipe()
	go agent.ServeAgent(&session{a: a, ctx: context.Background()}, c1)
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return agent.NewClient(c2)
}

func bind(t *testing.T, host ssh.Signer, sid []byte, forwarding bool) []byte {
	sig, err := host.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(bindMsg{HostKey: host.PublicKey().Marshal(), SessionID: sid, Signature: ssh.Marshal(sig), Forwarding: forwarding})
}

func loginData(sid []byte) []byte {
	return append(ssh.Marshal(struct{ S []byte }{sid}), []byte("\x32 rest of a userauth request")...)
}

func TestSignsOnlyBoundLogins(t *testing.T) {
	host, other := signer(t), signer(t)
	f := &fakeServer{key: signer(t), hosts: []string{"staging=" + ssh.FingerprintSHA256(host.PublicKey())}}
	var log strings.Builder
	c := connect(t, f, &log)
	sid := []byte("session-id-0123456789abcdef")

	// Before session-bind: listed, but signing is refused.
	keys, err := c.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "asiri://ops/staging" {
		t.Fatalf("list = %v, %v", keys, err)
	}
	if _, err := c.Sign(f.key.PublicKey(), loginData(sid)); err == nil {
		t.Fatal("signed without session-bind")
	}
	if !strings.Contains(log.String(), "OpenSSH 8.9") {
		t.Fatalf("log %q", log.String())
	}

	// A session-bind whose signature doesn't verify is rejected.
	bad := bind(t, host, sid, false)
	forged := ssh.Marshal(bindMsg{HostKey: host.PublicKey().Marshal(), SessionID: []byte("other"), Signature: bad[len(bad)-90:], Forwarding: false})
	if _, err := c.Extension(sessionBind, forged); err == nil {
		t.Fatal("forged session-bind accepted")
	}

	// Bound to the allowed host: signs logins for that session only.
	if _, err := c.Extension(sessionBind, bind(t, host, sid, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(f.key.PublicKey(), []byte("SSHSIG arbitrary data")); err == nil {
		t.Fatal("signed non-login data")
	}
	data := loginData(sid)
	sig, err := c.Sign(f.key.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.key.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if len(f.requests) != 1 || f.requests[0].HostFP != ssh.FingerprintSHA256(host.PublicKey()) || f.requests[0].Reason != "deploy" {
		t.Fatalf("requests %+v", f.requests)
	}

	// A different host: the key isn't even offered.
	c2 := connect(t, f, &log)
	if _, err := c2.Extension(sessionBind, bind(t, other, sid, false)); err != nil {
		t.Fatal(err)
	}
	if keys, _ := c2.List(); len(keys) != 0 {
		t.Fatalf("key offered to an unlisted host: %v", keys)
	}
}

func TestRefusesForwarding(t *testing.T) {
	host := signer(t)
	f := &fakeServer{key: signer(t), hosts: []string{ssh.FingerprintSHA256(host.PublicKey())}}
	var log strings.Builder
	c := connect(t, f, &log)
	sid := []byte("forwarded-session")
	c.Extension(sessionBind, bind(t, host, sid, true))
	if _, err := c.Sign(f.key.PublicKey(), loginData(sid)); err == nil || !strings.Contains(log.String(), "forwarding") {
		t.Fatalf("forwarded sign: %v / %q", err, log.String())
	}
}

func TestNoKeysAdded(t *testing.T) {
	c := connect(t, &fakeServer{key: signer(t)}, &strings.Builder{})
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.Add(agent.AddedKey{PrivateKey: k}); err == nil {
		t.Fatal("ssh-add accepted")
	}
}
