package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/importer"
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
	if _, err := agent.SetPolicy(ctx, ref, domain.Policy{Bins: []string{"gh"}, MaxGrant: "15m"}); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent set policy: %v", err)
	}
	if _, err := owner.SetPolicy(ctx, ref, domain.Policy{Bins: []string{"gh"}, MaxGrant: "15m"}); err != nil {
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
	if _, err := agent.Decide(ctx, rq.ID, domain.DecideOnce, domain.MethodTTY); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent approving itself: %v", err)
	}
	decided, err := owner.Decide(ctx, rq.ID, domain.Decide1h, domain.MethodRex)
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
	once, err := owner.Decide(ctx, r2.Request.ID, domain.DecideOnce, domain.MethodRex)
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
	live, _ := owner.Decide(ctx, r5.Request.ID, domain.Decide15m, domain.MethodRex)
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

	// Another agent can't see claude's requests.
	other := e.pair(t, "other", domain.RoleAgent)
	r7, _ := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh"))
	if _, err := other.Request(ctx, r7.Request.ID, 0); code(err) != domain.CodeNotFound {
		t.Fatalf("other agent read: %v", err)
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
	owner.SetPolicy(ctx, ref, domain.Policy{Bins: []string{"gh"}})
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

func TestSSHKeys(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	agent := e.pair(t, "claude", domain.RoleAgent)
	ref, _ := domain.ParseRef("ops/staging")

	it, err := owner.GenerateSSHKey(ctx, ref)
	if err != nil || it.Kind != domain.KindSSHKey || !strings.HasPrefix(it.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("generate = %+v, %v", it, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(it.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.GenerateSSHKey(ctx, ref); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent generate: %v", err)
	}
	hostA := "SHA256:" + strings.Repeat("A", 43)
	hostB := "SHA256:" + strings.Repeat("B", 43)
	sshReq := func(fp string) api.CreateRequest {
		return api.CreateRequest{Ref: ref, BinPath: "ssh", HostFP: fp, Reason: "deploy"}
	}

	if _, err := agent.CreateRequest(ctx, sshReq(hostA)); code(err) != domain.CodeNotAllowed {
		t.Fatalf("no hosts yet: %v", err)
	}
	if _, err := owner.SetPolicy(ctx, ref, domain.Policy{SSHHosts: []string{"bad entry"}}); code(err) != domain.CodeInvalid {
		t.Fatalf("bad host entry: %v", err)
	}
	if _, err := owner.SetPolicy(ctx, ref, domain.Policy{SSHHosts: []string{"staging=" + hostA}}); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.CreateRequest(ctx, sshReq(hostB)); code(err) != domain.CodeNotAllowed {
		t.Fatalf("unlisted host: %v", err)
	}
	// The SSH key can't go through asiri run.
	if _, err := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh")); code(err) != domain.CodeNotAllowed {
		t.Fatalf("ssh key via run: %v", err)
	}

	resp, err := agent.CreateRequest(ctx, sshReq(hostA))
	if err != nil || resp.Request.Status != domain.StatusPending || !strings.Contains(resp.Request.Detail, "ssh sign-in to staging (SHA256:AAAAAAA") {
		t.Fatalf("request = %+v, %v", resp, err)
	}
	g, err := owner.Decide(ctx, resp.Request.ID, domain.Decide15m, domain.MethodCLI)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("pretend userauth data")
	sig, err := agent.SSHSign(ctx, g.GrantID, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, &ssh.Signature{Format: sig.Format, Blob: sig.Blob}); err != nil {
		t.Fatalf("signature doesn't verify: %v", err)
	}
	// Never handed out, even with a live grant.
	if _, sec, err := agent.Redeem(ctx, g.GrantID); code(err) != domain.CodeNotAllowed || sec.Len() != 0 {
		t.Fatalf("redeem ssh grant: %v", err)
	}
	// Reused for the same host within 15m; a new request for another host is refused by policy.
	if again, err := agent.CreateRequest(ctx, sshReq(hostA)); err != nil || !again.Reused {
		t.Fatalf("reuse: %+v %v", again, err)
	}
	if keys, err := agent.SSHKeys(ctx); err != nil || len(keys) != 1 || keys[0].PublicKey != it.PublicKey {
		t.Fatalf("keys = %+v, %v", keys, err)
	}

	// Importing: a real key is accepted, junk isn't.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	imp, _ := domain.ParseRef("ops/imported")
	if it, err := owner.PutItem(ctx, imp, domain.KindSSHKey, domain.NewSecret(pem.EncodeToMemory(block))); err != nil || it.PublicKey == "" {
		t.Fatalf("import = %+v, %v", it, err)
	}
	if _, err := owner.PutItem(ctx, imp, domain.KindSSHKey, domain.NewSecret([]byte("not a key at all"))); code(err) != domain.CodeInvalid {
		t.Fatalf("junk key: %v", err)
	}
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if _, err := owner.PutItem(ctx, imp, domain.KindSSHKey, domain.NewSecret(pem.EncodeToMemory(enc))); code(err) != domain.CodeInvalid {
		t.Fatalf("passphrase key: %v", err)
	}
}

func TestImport(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	agent := e.pair(t, "claude", domain.RoleAgent)
	csv := "Title,URL,Username,Password,Notes,OTPAuth\n" +
		"GitHub,github.com/,octocat,pw-one,note,otpauth://totp?secret=JBSWY3DPEHPK3PXP\n" +
		"Router,,admin,routerpw,,\n"
	src, entries, err := importer.Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	req := api.ImportRequest{Vault: string(src), Source: string(src), Entries: entries}
	if _, err := agent.Import(ctx, req); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent import: %v", err)
	}
	res, err := owner.Import(ctx, req)
	if err != nil || res != (api.ImportResult{Logins: 2, Created: 2}) {
		t.Fatalf("first import = %+v, %v", res, err)
	}
	items, _ := owner.ListItems(ctx, "apple/")
	got := map[string]domain.Kind{}
	for _, it := range items {
		got[it.Ref.String()] = it.Kind
		if len(it.Policy.Bins) != 0 {
			t.Fatalf("imported item usable by %v", it.Policy.Bins)
		}
	}
	want := map[string]domain.Kind{
		"asiri://apple/github.com/password": domain.KindLogin, "asiri://apple/github.com/username": domain.KindNote,
		"asiri://apple/github.com/url": domain.KindNote, "asiri://apple/github.com/totp": domain.KindToken,
		"asiri://apple/github.com/notes": domain.KindNote, "asiri://apple/router/password": domain.KindLogin,
		"asiri://apple/router/username": domain.KindNote,
	}
	for ref, k := range want {
		if got[ref] != k {
			t.Errorf("%s: kind %q, want %q (all: %v)", ref, got[ref], k, got)
		}
	}
	// The same file again changes nothing.
	if res, err := owner.Import(ctx, req); err != nil || res != (api.ImportResult{Logins: 2, Unchanged: 2}) {
		t.Fatalf("second import = %+v, %v", res, err)
	}
	// A changed password makes a new version of that field only.
	_, entries2, _ := importer.Parse(strings.NewReader(strings.Replace(csv, "pw-one", "pw-two", 1)))
	if res, err := owner.Import(ctx, api.ImportRequest{Vault: "apple", Source: "apple", Entries: entries2}); err != nil ||
		res != (api.ImportResult{Logins: 2, Updated: 1, Unchanged: 1}) {
		t.Fatalf("third import = %+v, %v", res, err)
	}
	items, _ = owner.ListItems(ctx, "apple/github.com/")
	for _, it := range items {
		if want := map[bool]int{true: 2, false: 1}[it.Ref.Field == "password"]; it.Version != want {
			t.Errorf("%s version %d, want %d", it.Ref, it.Version, want)
		}
	}
	// Using an imported login still needs a policy.
	if _, err := agent.CreateRequest(ctx, ghRequest(domain.Ref{Vault: "apple", Name: "github.com", Field: "password"}, "/usr/bin/curl")); code(err) != domain.CodeNotAllowed {
		t.Fatalf("imported login without policy: %v", err)
	}
	evs, _ := owner.Audit(ctx, 0, 1000)
	imports := 0
	for _, ev := range evs {
		if ev.Event == "import" {
			imports++
			for _, v := range ev.Detail {
				if strings.Contains(v, "pw-") || strings.Contains(v, "routerpw") {
					t.Fatalf("audit leaked a value: %+v", ev)
				}
			}
		}
	}
	if imports != 3 {
		t.Fatalf("%d import events", imports)
	}
}
