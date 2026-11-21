package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/domain"
)

const secret = "ghp_MCP_TEST_VALUE_0123456789"

type fake struct {
	deny bool
}

func (f *fake) ListItems(_ context.Context, q string) ([]domain.Item, error) {
	r, _ := domain.ParseRef("dev/github")
	s, _ := domain.ParseRef("ops/staging")
	all := []domain.Item{
		{Ref: r, Kind: domain.KindToken, Policy: domain.Policy{Bins: []string{"printenv"}, MaxGrant: "1h"}},
		{Ref: s, Kind: domain.KindSSHKey, PublicKey: "ssh-ed25519 AAAA test", Policy: domain.Policy{SSHHosts: []string{"staging=SHA256:" + strings.Repeat("A", 43)}, MaxGrant: "1h"}},
	}
	var out []domain.Item
	for _, it := range all {
		if strings.Contains(it.Ref.Vault+"/"+it.Ref.Name+"/"+it.Ref.Field, q) {
			out = append(out, it)
		}
	}
	return out, nil
}
func (f *fake) CreateRequest(_ context.Context, req api.CreateRequest) (api.RequestResponse, error) {
	return api.RequestResponse{Request: domain.Request{ID: "R1", Ref: req.Ref, Status: domain.StatusPending, Title: "claude wants " + req.Ref.String()}}, nil
}
func (f *fake) Request(context.Context, domain.RequestID, time.Duration) (domain.Request, error) {
	if f.deny {
		return domain.Request{ID: "R1", Status: domain.StatusDenied}, nil
	}
	return domain.Request{ID: "R1", Status: domain.StatusApproved, GrantID: "G1"}, nil
}
func (f *fake) Decide(context.Context, domain.RequestID, domain.Decision, domain.Method) (domain.Request, error) {
	panic("the MCP server must never decide")
}
func (f *fake) Redeem(context.Context, domain.GrantID) (domain.Grant, domain.Secret, error) {
	return domain.Grant{ID: "G1"}, domain.NewSecret([]byte(secret)), nil
}
func (f *fake) ReportScrub(context.Context, domain.GrantID, int) error { return nil }
func (f *fake) SSHKeys(context.Context) ([]domain.Item, error)         { return nil, nil }
func (f *fake) SSHSign(context.Context, domain.GrantID, []byte, uint32) (api.SSHSignature, error) {
	return api.SSHSignature{}, nil
}

// decidedElsewhere stands in for Rex: the person answered, the request reads as decided.
type decidedElsewhere struct{ w io.Writer }

func (d decidedElsewhere) Approve(context.Context, approve.Prompt) (approve.Answer, error) {
	io.WriteString(d.w, "asiri: asking in Rex: claude wants asiri://dev/github\n")
	return approve.Answer{}, approve.ErrAlreadyDecided
}

func session(t *testing.T, f *fake) *mcp.ClientSession {
	t.Helper()
	s := &Server{API: f, Version: "test", Approver: func(w io.Writer) approve.Approver { return decidedElsewhere{w} }}
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	return res, string(b)
}

func TestTools(t *testing.T) {
	cs := session(t, &fake{})
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "list_secrets,request_missing_secret,run_with_secrets,ssh_run" {
		t.Fatalf("tools %v", names)
	}
}

func TestListSecrets(t *testing.T) {
	_, raw := call(t, session(t, &fake{}), "list_secrets", map[string]any{})
	for _, want := range []string{`"ref":"asiri://dev/github"`, `"programs":["printenv"]`, `"ssh_hosts":["staging"]`} {
		if !strings.Contains(raw, want) {
			t.Errorf("missing %s in %s", want, raw)
		}
	}
	if strings.Contains(raw, "SHA256:AAAA") || strings.Contains(raw, secret) {
		t.Fatalf("leaked: %s", raw)
	}
}

func TestRunWithSecrets(t *testing.T) {
	res, raw := call(t, session(t, &fake{}), "run_with_secrets", map[string]any{
		"command": []string{"printenv", "GH_TOKEN"}, "env": map[string]string{"GH_TOKEN": "asiri://dev/github"}, "reason": "test",
	})
	if res.IsError || strings.Contains(raw, secret) {
		t.Fatalf("result %s", raw)
	}
	var out RunOut
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &out)
	if out.ExitCode != 0 || strings.TrimSpace(out.Stdout) != "[asiri:asiri://dev/github]" || !strings.Contains(out.Notes, "asking in Rex") {
		t.Fatalf("out %+v", out)
	}
}

func TestRunRefusals(t *testing.T) {
	cs := session(t, &fake{})
	if res, raw := call(t, cs, "run_with_secrets", map[string]any{"command": []string{"printenv"}, "env": map[string]string{"X": "asiri://dev/github"}}); !res.IsError || !strings.Contains(raw, "reason") {
		t.Fatalf("no reason: %s", raw)
	}
	denied := session(t, &fake{deny: true})
	res, raw := call(t, denied, "run_with_secrets", map[string]any{"command": []string{"printenv"}, "env": map[string]string{"X": "asiri://dev/github"}, "reason": "r"})
	if !res.IsError || !strings.Contains(raw, "denied") || strings.Contains(raw, secret) {
		t.Fatalf("denied: %s", raw)
	}
}

func TestRequestMissing(t *testing.T) {
	cs := session(t, &fake{})
	_, raw := call(t, cs, "request_missing_secret", map[string]any{"ref": "asiri://dev/github", "reason": "r"})
	if !strings.Contains(raw, `"exists":true`) {
		t.Fatalf("existing: %s", raw)
	}
	_, raw = call(t, cs, "request_missing_secret", map[string]any{"ref": "asiri://dev/nope", "reason": "r", "wait_seconds": 1})
	if !strings.Contains(raw, `"exists":false`) || !strings.Contains(raw, "asiri add asiri://dev/nope") {
		t.Fatalf("missing: %s", raw)
	}
}

func TestCapped(t *testing.T) {
	var c capped
	c.Write(make([]byte, MaxOutput-10))
	c.Write(make([]byte, 100))
	if c.buf.Len() != MaxOutput || !c.truncated {
		t.Fatalf("len %d truncated %v", c.buf.Len(), c.truncated)
	}
}
