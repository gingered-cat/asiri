package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/service"
	"github.com/gingered-cat/asiri/internal/vault"
)

var ctx = context.Background()

type env struct {
	url string
	svc *service.Service
}

func setup(t *testing.T) env {
	t.Helper()
	t.Setenv("ASIRI_HOME", t.TempDir())
	dir := t.TempDir()
	dd := DataDir(dir)
	ca, crt, key, err := dd.EnsureTLS([]string{"127.0.0.1", "localhost"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store, err := vault.Open(dd.DB())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "master.key")
	os.WriteFile(keyPath, vault.NewKeyFile(), 0o600)
	svc := service.New(service.Config{Store: store, Vault: vault.New(store), CA: ca, KeyFile: keyPath, FailDelay: time.Millisecond})
	k, _ := vault.ReadKeyFile(keyPath)
	if err := svc.Init(ctx, vault.NewKDF(vault.ModeKeyFile), k); err != nil {
		t.Fatal(err)
	}
	tc, err := TLSConfig(crt, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := New(svc, slog.New(slog.DiscardHandler)).HTTPServer("", tc)
	go hs.ServeTLS(ln, "", "")
	t.Cleanup(func() { hs.Close(); store.Close() })
	return env{url: "https://" + ln.Addr().String(), svc: svc}
}

func (e env) pair(t *testing.T, name string, role domain.Role) *client.Client {
	t.Helper()
	pc, err := e.svc.CreatePairCode(ctx, "", name, role, false)
	if err != nil {
		t.Fatal(err)
	}
	p, resp, err := client.Pair(ctx, e.url, pc.Code, name, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Role != role || resp.Name != name {
		t.Fatalf("paired as %s/%s", resp.Name, resp.Role)
	}
	c, err := client.New(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func code(err error) domain.Code { return domain.CodeOf(err) }

func TestOwnerFlow(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)

	who, err := owner.WhoAmI(ctx)
	if err != nil || who.Role != domain.RoleOwner {
		t.Fatalf("whoami = %+v, %v", who, err)
	}
	ref, _ := domain.ParseRef("asiri://dev/github")
	const value = "ghp_SUPERSECRET_test_value"
	it, err := owner.PutItem(ctx, ref, "", domain.NewSecret([]byte(value)))
	if err != nil || it.Version != 1 || it.Kind != domain.KindToken {
		t.Fatalf("put = %+v, %v", it, err)
	}
	items, err := owner.ListItems(ctx, "")
	if err != nil || len(items) != 1 || items[0].Ref != ref {
		t.Fatalf("list = %+v, %v", items, err)
	}
	if b, _ := json.Marshal(items); strings.Contains(string(b), value) {
		t.Fatal("list leaked the value")
	}

	// Lock, then everything that needs the key says sealed; unlock re-reads the key file.
	if h, err := owner.Lock(ctx); err != nil || !h.Sealed {
		t.Fatalf("lock = %+v, %v", h, err)
	}
	if _, err := owner.ListItems(ctx, ""); code(err) != domain.CodeSealed {
		t.Fatalf("list while sealed: %v", err)
	}
	if _, err := owner.WhoAmI(ctx); err != nil {
		t.Fatalf("whoami should work while sealed: %v", err)
	}
	if h, err := owner.Unlock(ctx, nil); err != nil || h.Sealed {
		t.Fatalf("unlock = %+v, %v", h, err)
	}

	if n, err := owner.VerifyAudit(ctx); err != nil || n < 5 {
		t.Fatalf("verify = %d, %v", n, err)
	}
	evs, err := owner.Audit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ev := range evs {
		names = append(names, ev.Event)
	}
	if got := strings.Join(names, ","); got != "init,pair_code,pair,item_put,lock,unlock" {
		t.Fatalf("audit events = %s", got)
	}

	if err := owner.RevokeClient(ctx, "owner"); code(err) != domain.CodeNotAllowed {
		t.Fatalf("revoking the last owner: %v", err)
	}
}

func TestAgentRole(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	pc, err := owner.CreateClient(ctx, "claude", domain.RoleAgent, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CreateClient(ctx, "owner", domain.RoleOwner, false); code(err) != domain.CodeConflict {
		t.Fatalf("duplicate client: %v", err)
	}
	p, _, err := client.Pair(ctx, e.url, pc.Code, "claude", false)
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := client.New(p)

	if _, err := agent.ListItems(ctx, ""); err != nil {
		t.Fatalf("agent list: %v", err)
	}
	ref, _ := domain.ParseRef("dev/x")
	if _, err := agent.PutItem(ctx, ref, "", domain.NewSecret([]byte("v"))); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent put: %v", err)
	}
	for name, call := range map[string]func() error{
		"unlock":  func() error { _, err := agent.Unlock(ctx, nil); return err },
		"lock":    func() error { _, err := agent.Lock(ctx); return err },
		"clients": func() error { _, err := agent.ListClients(ctx); return err },
		"audit":   func() error { _, err := agent.Audit(ctx, 0, 10); return err },
	} {
		if err := call(); code(err) != domain.CodeNotAllowed {
			t.Errorf("agent %s: %v", name, err)
		}
	}

	if err := owner.RevokeClient(ctx, "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ListItems(ctx, ""); code(err) != domain.CodeUnauthenticated {
		t.Fatalf("revoked agent: %v", err)
	}
}

func TestPairingCodes(t *testing.T) {
	e := setup(t)
	pc, err := e.svc.CreatePairCode(ctx, "", "owner", domain.RoleOwner, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Pair(ctx, e.url, pc.Code, "owner", false); err != nil {
		t.Fatal(err)
	}
	// One use only.
	if _, _, err := client.Pair(ctx, e.url, pc.Code, "owner", true); code(err) != domain.CodeNotAllowed {
		t.Fatalf("reused code: %v", err)
	}
	// Lowercase and without dashes still works.
	pc2, _ := e.svc.CreatePairCode(ctx, "", "laptop", domain.RoleOwner, false)
	fp, rest, _ := strings.Cut(pc2.Code, "-")
	if _, _, err := client.Pair(ctx, e.url, fp+"-"+strings.ToLower(strings.ReplaceAll(rest, "-", "")), "laptop", false); err != nil {
		t.Fatalf("normalized code: %v", err)
	}
	// A code whose fingerprint doesn't match this server is refused before it is sent.
	_, _, err = client.Pair(ctx, e.url, "0000000000000000-AAAA-BBBB-CCCC-DDDD", "other", false)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong CA: %v", err)
	}
	// Wrong secret with the right fingerprint.
	_, _, err = client.Pair(ctx, e.url, fp+"-AAAA-BBBB-CCCC-DDDD", "other", false)
	if code(err) != domain.CodeNotAllowed {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestNoClientCertificate(t *testing.T) {
	e := setup(t)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := hc.Get(e.url + "/v1/items")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, err = hc.Get(e.url + "/v1/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %v %v", resp, err)
	}
	resp.Body.Close()
}
