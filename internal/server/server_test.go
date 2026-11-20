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
	"sync"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/service"
	"github.com/gingered-cat/asiri/internal/vault"
)

var ctx = context.Background()

type env struct {
	url   string
	svc   *service.Service
	clock *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

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
	clk := &clock{t: time.Now()}
	svc := service.New(service.Config{Store: store, Vault: vault.New(store), CA: ca, KeyFile: keyPath,
		FailDelay: time.Millisecond, Now: clk.now})
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
	return env{url: "https://" + ln.Addr().String(), svc: svc, clock: clk}
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

const fakeSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func ghRequest(ref domain.Ref, bin string, args ...string) api.CreateRequest {
	return api.CreateRequest{Ref: ref, BinPath: bin, BinSHA256: fakeSHA, Argv: args, Cwd: "~/proj/api", Reason: "open the PR"}
}

// The whole lifecycle: rules, request, decision, redeem, reuse, once, deny,
// long poll, expiry, kill switch.
func TestGrantLifecycle(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	agent := e.pair(t, "claude", domain.RoleAgent)
	ref, _ := domain.ParseRef("dev/github")
	const value = "ghp_LIFECYCLE_value_42"
	if _, err := owner.PutItem(ctx, ref, "", domain.NewSecret([]byte(value))); err != nil {
		t.Fatal(err)
	}

	// No policy yet: nothing may use it.
	if _, err := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh")); code(err) != domain.CodeNotAllowed {
		t.Fatalf("no policy: %v", err)
	}
	if _, err := agent.SetPolicy(ctx, ref, []string{"gh"}, "15m"); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent set policy: %v", err)
	}
	if _, err := owner.SetPolicy(ctx, ref, []string{"gh"}, "15m"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.CreateRequest(ctx, ghRequest(ref, "/bin/sh", "-c", "echo $GH_TOKEN")); code(err) != domain.CodeInterpreter {
		t.Fatalf("shell: %v", err)
	}
	if _, err := agent.CreateRequest(ctx, ghRequest(ref, "/usr/bin/curl")); code(err) != domain.CodeNotAllowed {
		t.Fatalf("curl: %v", err)
	}

	// A pending request; the prompt text comes from the server, with the
	// value scrubbed out of argv if the caller put it there.
	resp, err := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh", "pr", "create", "--token", value))
	if err != nil || resp.Reused || resp.Request.Status != domain.StatusPending {
		t.Fatalf("create = %+v, %v", resp, err)
	}
	rq := resp.Request
	if rq.Title != "claude wants asiri://dev/github" || strings.Contains(rq.Detail, value) ||
		!strings.Contains(rq.Detail, "gh pr create --token [asiri:asiri://dev/github] · ~/proj/api") {
		t.Fatalf("prompt: %q / %q", rq.Title, rq.Detail)
	}

	// Long poll wakes on the decision. 1h is clamped to the policy's 15m.
	woke := make(chan domain.Request, 1)
	go func() { r, _ := agent.Request(ctx, rq.ID, 10*time.Second); woke <- r }()
	time.Sleep(100 * time.Millisecond)
	decided, err := agent.Decide(ctx, rq.ID, domain.Decide1h, domain.MethodTTY)
	if err != nil || decided.Status != domain.StatusApproved || decided.Decision != domain.Decide15m || decided.GrantID == "" {
		t.Fatalf("decide = %+v, %v", decided, err)
	}
	select {
	case r := <-woke:
		if r.Status != domain.StatusApproved {
			t.Fatalf("long poll saw %s", r.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long poll did not wake")
	}
	// Second decision loses and sees the first.
	if again, err := owner.Decide(ctx, rq.ID, domain.DecideDeny, domain.MethodCLI); code(err) != domain.CodeConflict || again.Status != domain.StatusApproved {
		t.Fatalf("second decision = %+v, %v", again, err)
	}

	// Only the requester can redeem; a timed grant redeems repeatedly.
	if _, _, err := owner.Redeem(ctx, decided.GrantID); code(err) != domain.CodeNotFound {
		t.Fatalf("owner redeem: %v", err)
	}
	for range 2 {
		_, sec, err := agent.Redeem(ctx, decided.GrantID)
		if err != nil || string(sec.Reveal()) != value {
			t.Fatalf("redeem: %v", err)
		}
	}
	// Same client, item and binary within 15m: reused, no prompt.
	reused, err := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh", "pr", "list"))
	if err != nil || !reused.Reused || reused.Request.GrantID != decided.GrantID {
		t.Fatalf("reuse = %+v, %v", reused, err)
	}
	// After 15 minutes it's gone.
	e.clock.add(16 * time.Minute)
	if _, _, err := agent.Redeem(ctx, decided.GrantID); code(err) != domain.CodeExpired {
		t.Fatalf("expired grant: %v", err)
	}

	// Once: one redeem, then spent.
	r2, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	once, err := agent.Decide(ctx, r2.Request.ID, domain.DecideOnce, domain.MethodTTY)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := agent.Redeem(ctx, once.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := agent.Redeem(ctx, once.GrantID); code(err) != domain.CodeSpent {
		t.Fatalf("spent: %v", err)
	}

	// Deny.
	r3, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	if d, err := owner.Decide(ctx, r3.Request.ID, domain.DecideDeny, domain.MethodCLI); err != nil || d.Status != domain.StatusDenied || d.GrantID != "" {
		t.Fatalf("deny = %+v, %v", d, err)
	}

	// Expiry: nobody answers for two minutes.
	r4, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	if p, _ := owner.PendingRequests(ctx); len(p) != 1 || p[0].ID != r4.Request.ID {
		t.Fatalf("pending = %+v", p)
	}
	e.clock.add(3 * time.Minute)
	if n, _ := e.svc.ExpireRequests(ctx); n != 1 {
		t.Fatalf("expired %d", n)
	}
	if got, _ := agent.Request(ctx, r4.Request.ID, 0); got.Status != domain.StatusExpired {
		t.Fatalf("r4 = %s", got.Status)
	}

	// Kill switch: live grants revoked, pending requests denied.
	r5, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	live, _ := agent.Decide(ctx, r5.Request.ID, domain.Decide15m, domain.MethodTTY)
	r6, _ := agent.CreateRequest(ctx, api.CreateRequest{Ref: ref, BinPath: "/usr/local/bin/gh", BinSHA256: strings.Repeat("b", 64)})
	if gs, _ := owner.Grants(ctx); len(gs) != 1 {
		t.Fatalf("active grants = %+v", gs)
	}
	if n, err := owner.RevokeAll(ctx); err != nil || n != 1 {
		t.Fatalf("revoke all = %d, %v", n, err)
	}
	if _, _, err := agent.Redeem(ctx, live.GrantID); code(err) != domain.CodeRevoked {
		t.Fatalf("revoked: %v", err)
	}
	if got, _ := agent.Request(ctx, r6.Request.ID, 0); got.Status != domain.StatusDenied {
		t.Fatalf("pending after kill switch = %s", got.Status)
	}

	// Another agent can't see or decide claude's requests.
	other := e.pair(t, "other", domain.RoleAgent)
	r7, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	if _, err := other.Decide(ctx, r7.Request.ID, domain.DecideOnce, domain.MethodTTY); code(err) != domain.CodeNotFound {
		t.Fatalf("other agent decide: %v", err)
	}

	if _, err := owner.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	evs, _ := owner.Audit(ctx, 0, 1000)
	seen := map[string]int{}
	for _, ev := range evs {
		seen[ev.Event]++
		for _, v := range ev.Detail {
			if strings.Contains(v, value) {
				t.Fatalf("audit leaked the value: %+v", ev)
			}
		}
	}
	for _, want := range []string{"policy_set", "request_rejected", "request", "decision", "redeem", "request_expired", "revoke_all"} {
		if seen[want] == 0 {
			t.Errorf("no %s event in audit", want)
		}
	}
}

func TestRateLimit(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	agent := e.pair(t, "claude", domain.RoleAgent)
	ref, _ := domain.ParseRef("dev/x")
	owner.PutItem(ctx, ref, "", domain.NewSecret([]byte("xxxxxxxx")))
	owner.SetPolicy(ctx, ref, []string{"gh"}, "")
	var last error
	for range 11 {
		_, last = agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	}
	if code(last) != domain.CodeRateLimited {
		t.Fatalf("11th request: %v", last)
	}
	evs, _ := owner.Audit(ctx, 0, 1000)
	if evs[len(evs)-1].Event != "anomaly" {
		t.Fatalf("last event %s", evs[len(evs)-1].Event)
	}
}
