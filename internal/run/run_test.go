package run

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/domain"
)

// fakeAPI approves or denies everything and hands out fixed values.
type fakeAPI struct {
	values    map[string]string // ref → value
	deny      bool
	reqs      []api.CreateRequest
	scrubbed  map[domain.GrantID]int
	decisions []domain.Decision
}

func (f *fakeAPI) CreateRequest(_ context.Context, req api.CreateRequest) (api.RequestResponse, error) {
	f.reqs = append(f.reqs, req)
	return api.RequestResponse{Request: domain.Request{ID: domain.RequestID("R-" + req.Ref.Name), Ref: req.Ref,
		Status: domain.StatusPending, Title: "test wants " + req.Ref.String()}}, nil
}

func (f *fakeAPI) Request(_ context.Context, id domain.RequestID, _ time.Duration) (domain.Request, error) {
	return domain.Request{ID: id, Status: domain.StatusApproved, GrantID: domain.GrantID("G" + id)}, nil
}

func (f *fakeAPI) Decide(_ context.Context, id domain.RequestID, d domain.Decision, _ domain.Method) (domain.Request, error) {
	f.decisions = append(f.decisions, d)
	if f.deny || d == domain.DecideDeny {
		return domain.Request{ID: id, Status: domain.StatusDenied}, nil
	}
	return domain.Request{ID: id, Status: domain.StatusApproved, GrantID: domain.GrantID("G" + id)}, nil
}

func (f *fakeAPI) Redeem(_ context.Context, id domain.GrantID) (domain.Grant, domain.Secret, error) {
	name := strings.TrimPrefix(string(id), "GR-")
	return domain.Grant{ID: id}, domain.NewSecret([]byte(f.values[name])), nil
}

func (f *fakeAPI) ReportScrub(_ context.Context, id domain.GrantID, hits int) error {
	if f.scrubbed == nil {
		f.scrubbed = map[domain.GrantID]int{}
	}
	f.scrubbed[id] += hits
	return nil
}

type yes struct{}

func (yes) Approve(context.Context, approve.Prompt) (approve.Answer, error) {
	return approve.Answer{Decision: domain.DecideOnce, Method: domain.MethodTTY}, nil
}

func ref(s string) domain.Ref { r, _ := domain.ParseRef(s); return r }

func runSpec(t *testing.T, f *fakeAPI, a approve.Approver, spec Spec) (int, string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	spec.Stdout, spec.Stderr = &out, &errb
	r := &Runner{API: f, Approver: a, Notes: &errb}
	code, err := r.Run(context.Background(), spec)
	return code, out.String(), errb.String(), err
}

func TestEnvDeliveryIsScrubbed(t *testing.T) {
	f := &fakeAPI{values: map[string]string{"github": "ghp_TESTVALUE_123"}}
	code, out, _, err := runSpec(t, f, yes{}, Spec{Bin: "printenv", Args: []string{"GH_TOKEN"},
		Deliveries: []Delivery{Env{Name: "GH_TOKEN", R: ref("dev/github")}}, Reason: "test"})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	if strings.Contains(out, "ghp_TESTVALUE_123") || !strings.Contains(out, "[asiri:asiri://dev/github]") {
		t.Fatalf("output %q", out)
	}
	if f.scrubbed["GR-github"] != 1 {
		t.Fatalf("scrub report %v", f.scrubbed)
	}
	if r := f.reqs[0]; !strings.HasPrefix(r.BinPath, "/") || len(r.BinSHA256) != 64 || r.Reason != "test" {
		t.Fatalf("request %+v", r)
	}
}

func TestStdinAndFileDelivery(t *testing.T) {
	f := &fakeAPI{values: map[string]string{"a": "value-from-stdin", "b": "value-from-file"}}
	// cat reads stdin; the output is scrubbed, so check the length went through.
	code, out, _, err := runSpec(t, f, yes{}, Spec{Bin: "wc", Args: []string{"-c"},
		Deliveries: []Delivery{Stdin{R: ref("dev/a")}}})
	if err != nil || code != 0 || strings.TrimSpace(out) != "16" {
		t.Fatalf("stdin: code %d out %q err %v", code, out, err)
	}
	code, out, _, err = runSpec(t, f, yes{}, Spec{Bin: "/bin/sh", Args: []string{"-c", `wc -c < "$SECRET_FILE"; echo "$SECRET_FILE"`},
		Deliveries: []Delivery{File{Name: "SECRET_FILE", R: ref("dev/b")}}})
	if err != nil || code != 0 {
		t.Fatalf("file: code %d err %v", code, err)
	}
	lines := strings.Fields(out)
	if len(lines) != 2 || lines[0] != "15" || !strings.Contains(lines[1], fifoPrefix) {
		t.Fatalf("file output %q", out)
	}
}

func TestExitCodes(t *testing.T) {
	f := &fakeAPI{values: map[string]string{"x": "xxxxxxxx"}}
	d := []Delivery{Env{Name: "X", R: ref("dev/x")}}
	if code, _, _, _ := runSpec(t, f, yes{}, Spec{Bin: "false", Deliveries: d}); code != 1 {
		t.Fatalf("false: %d", code)
	}
	if code, _, _, err := runSpec(t, f, yes{}, Spec{Bin: "no-such-binary-asiri", Deliveries: d}); code != ExitNotFound || err == nil {
		t.Fatalf("missing: %d %v", code, err)
	}
	f.deny = true
	code, _, _, err := runSpec(t, f, yes{}, Spec{Bin: "true", Deliveries: d})
	if code != ExitDenied || domain.CodeOf(err) != domain.CodeDenied {
		t.Fatalf("denied: %d %v", code, err)
	}
	f.deny = false
	if code, _, _, err := runSpec(t, f, approve.Chain{}, Spec{Bin: "true", Deliveries: d}); code != ExitDenied || err == nil {
		t.Fatalf("no approver: %d %v", code, err)
	}
	if code, _, _, err := runSpec(t, f, yes{}, Spec{Bin: "true"}); code != ExitFailed || err == nil {
		t.Fatalf("no deliveries: %d %v", code, err)
	}
	two := []Delivery{Stdin{R: ref("dev/x")}, Stdin{R: ref("dev/x")}}
	if code, _, _, err := runSpec(t, f, yes{}, Spec{Bin: "true", Deliveries: two}); code != ExitFailed || err == nil {
		t.Fatalf("two stdin: %d %v", code, err)
	}
}

func TestDecidedElsewhere(t *testing.T) {
	f := &fakeAPI{values: map[string]string{"x": "xxxxxxxx"}}
	elsewhere := approve.Chain{fixedErr{approve.ErrAlreadyDecided}}
	code, _, _, err := runSpec(t, f, elsewhere, Spec{Bin: "true", Deliveries: []Delivery{Env{Name: "X", R: ref("dev/x")}}})
	if err != nil || code != 0 || len(f.decisions) != 0 {
		t.Fatalf("code %d err %v decisions %v", code, err, f.decisions)
	}
}

type fixedErr struct{ err error }

func (e fixedErr) Approve(context.Context, approve.Prompt) (approve.Answer, error) {
	return approve.Answer{}, e.err
}

func TestParseDeliveries(t *testing.T) {
	if e, err := ParseEnv("GH_TOKEN=asiri://dev/github"); err != nil || e.Name != "GH_TOKEN" || e.R.Name != "github" {
		t.Fatalf("env %+v %v", e, err)
	}
	for _, bad := range []string{"GH_TOKEN", "1X=dev/a", "X=nope"} {
		if _, err := ParseEnv(bad); err == nil {
			t.Errorf("ParseEnv(%q) accepted", bad)
		}
	}
	nul := Env{Name: "X"}
	if _, err := nul.Apply(nil, domain.NewSecret([]byte("a\x00b"))); err == nil || errors.Is(err, nil) {
		t.Error("NUL in env accepted")
	}
}

func TestContextStopsProgram(t *testing.T) {
	f := &fakeAPI{values: map[string]string{"x": "xxxxxxxx"}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := &Runner{API: f, Approver: yes{}}
	start := time.Now()
	code, err := r.Run(ctx, Spec{Bin: "sleep", Args: []string{"30"}, Deliveries: []Delivery{Env{Name: "X", R: ref("dev/x")}}})
	if err != nil || code != 128+15 || time.Since(start) > 5*time.Second {
		t.Fatalf("code %d err %v after %s", code, err, time.Since(start))
	}
}
