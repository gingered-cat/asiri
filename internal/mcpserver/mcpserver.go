// Package mcpserver exposes asiri to agents over MCP (stdio). No tool ever
// returns a secret's value: agents get names, and the results of commands
// that used secrets, with the secrets scrubbed out.
package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/run"
	"github.com/gingered-cat/asiri/internal/sshagent"
)

// API is what the tools need from the asiri server.
type API interface {
	run.API
	sshagent.API
	ListItems(ctx context.Context, query string) ([]domain.Item, error)
}

// Server builds the MCP server.
type Server struct {
	API API
	// Approver builds the approval chain for one call; progress notes go to w.
	Approver func(w io.Writer) approve.Approver
	Version  string
}

// MaxOutput caps each of stdout and stderr in a tool result.
const MaxOutput = 256 << 10

func (s *Server) MCP() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "asiri", Title: "asiri", Version: s.Version}, &mcp.ServerOptions{
		Instructions: "asiri lets you use secrets without seeing them. Never ask the person to paste a secret into the chat. " +
			"Find secrets with list_secrets, then use them with run_with_secrets or ssh_run: asiri asks the person to approve, " +
			"delivers the secret to the program, and returns the output with the secret scrubbed out. " +
			"If a secret doesn't exist, call request_missing_secret. A denied request is final: don't retry with another program or secret.",
	})
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Title:       "List secrets",
		Description: "List the secrets asiri has, by reference (asiri://vault/name/field), with the programs or SSH hosts each may be used with. Never returns values.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listSecrets)
	mcp.AddTool(srv, &mcp.Tool{
		Name:  "run_with_secrets",
		Title: "Run a program with secrets",
		Description: "Run one program (no shell) with secrets delivered to it as environment variables, stdin or one-time files. " +
			"The person approves first (Rex or their terminal). Output comes back with every secret replaced by [asiri:REF]. " +
			"Only programs allowed by the secret's policy may receive it; shells and interpreters never do.",
	}, s.runWithSecrets)
	mcp.AddTool(srv, &mcp.Tool{
		Name:  "ssh_run",
		Title: "Run a command over SSH",
		Description: "Run a command on a remote host over ssh, signing in with an asiri SSH key. The key never leaves asiri; " +
			"it only signs in to hosts its policy allows, after the person approves.",
	}, s.sshRun)
	mcp.AddTool(srv, &mcp.Tool{
		Name:  "request_missing_secret",
		Title: "Ask the person to add a secret",
		Description: "When a secret you need doesn't exist, ask the person to add it (they type it into asiri, never into the chat). " +
			"Waits until it exists or the wait runs out.",
	}, s.requestMissing)
	return srv
}

// ---- notes: approval progress, shown live and in the result ----

type notes struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ctx context.Context
	req *mcp.CallToolRequest
}

func (n *notes) Write(p []byte) (int, error) {
	n.mu.Lock()
	n.buf.Write(p)
	n.mu.Unlock()
	if n.req != nil && n.req.Session != nil {
		if msg := strings.TrimSpace(string(p)); msg != "" {
			n.req.Session.Log(n.ctx, &mcp.LoggingMessageParams{Level: "info", Logger: "asiri", Data: msg})
		}
	}
	return len(p), nil
}

func (n *notes) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.TrimSpace(n.buf.String())
}

// capped keeps the first MaxOutput bytes.
type capped struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := MaxOutput - c.buf.Len(); room < len(p) {
		c.buf.Write(p[:max(room, 0)])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func timeout(sec int) time.Duration {
	switch {
	case sec <= 0:
		return 3 * time.Minute
	case sec > 1800:
		return 30 * time.Minute
	}
	return time.Duration(sec) * time.Second
}

// ---- list_secrets ----

type ListIn struct {
	Query string `json:"query,omitempty" jsonschema:"only references containing this text"`
}

type SecretInfo struct {
	Ref       string   `json:"ref"`
	Kind      string   `json:"kind"`
	Programs  []string `json:"programs,omitempty" jsonschema:"programs that may receive it (run_with_secrets)"`
	SSHHosts  []string `json:"ssh_hosts,omitempty" jsonschema:"hosts it may sign in to (ssh_run)"`
	MaxGrant  string   `json:"max_grant"`
	PublicKey string   `json:"public_key,omitempty"`
}

type ListOut struct {
	Secrets []SecretInfo `json:"secrets"`
}

func (s *Server) listSecrets(ctx context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, ListOut, error) {
	items, err := s.API.ListItems(ctx, in.Query)
	if err != nil {
		return nil, ListOut{}, err
	}
	out := ListOut{Secrets: []SecretInfo{}}
	for _, it := range items {
		info := SecretInfo{Ref: it.Ref.String(), Kind: string(it.Kind), Programs: it.Policy.Bins, MaxGrant: it.Policy.MaxGrant, PublicKey: it.PublicKey}
		for _, h := range it.Policy.SSHHosts {
			name, _, _ := strings.Cut(h, "=")
			info.SSHHosts = append(info.SSHHosts, name)
		}
		out.Secrets = append(out.Secrets, info)
	}
	return nil, out, nil
}

// ---- run_with_secrets ----

type RunIn struct {
	Command        []string          `json:"command" jsonschema:"the program and its arguments, e.g. [\"gh\", \"pr\", \"create\", \"--fill\"]; no shell"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"environment variable name to asiri:// reference, e.g. {\"GH_TOKEN\": \"asiri://dev/github\"}"`
	Stdin          string            `json:"stdin,omitempty" jsonschema:"asiri:// reference to write to the program's stdin (preferred when the program supports it)"`
	Files          map[string]string `json:"files,omitempty" jsonschema:"environment variable name to asiri:// reference; the variable holds the path of a one-time pipe with the secret"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"working directory"`
	Reason         string            `json:"reason" jsonschema:"why you need it; the person sees this when approving"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"stop the program after this long (default 180, max 1800)"`
}

type RunOut struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated,omitempty"`
	Notes     string `json:"notes,omitempty" jsonschema:"what asiri did to get approval"`
}

func (s *Server) runWithSecrets(ctx context.Context, req *mcp.CallToolRequest, in RunIn) (*mcp.CallToolResult, RunOut, error) {
	if len(in.Command) == 0 {
		return nil, RunOut{}, errors.New("command is empty")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, RunOut{}, errors.New("reason is required: say why you need the secret, the person sees it")
	}
	var ds []run.Delivery
	for _, name := range sortedKeys(in.Env) {
		d, err := run.ParseEnv(name + "=" + in.Env[name])
		if err != nil {
			return nil, RunOut{}, err
		}
		ds = append(ds, d)
	}
	for _, name := range sortedKeys(in.Files) {
		d, err := run.ParseFile(name + "=" + in.Files[name])
		if err != nil {
			return nil, RunOut{}, err
		}
		ds = append(ds, d)
	}
	if in.Stdin != "" {
		d, err := run.ParseStdin(in.Stdin)
		if err != nil {
			return nil, RunOut{}, err
		}
		ds = append(ds, d)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout(in.TimeoutSeconds))
	defer cancel()
	n := &notes{ctx: ctx, req: req}
	var stdout, stderr capped
	r := &run.Runner{API: s.API, Approver: s.Approver(n), Notes: n}
	code, err := r.Run(ctx, run.Spec{Bin: in.Command[0], Args: in.Command[1:], Deliveries: ds, Reason: in.Reason,
		Dir: in.Cwd, Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		return nil, RunOut{}, withNotes(err, n)
	}
	return nil, RunOut{ExitCode: code, Stdout: stdout.buf.String(), Stderr: stderr.buf.String(),
		Truncated: stdout.truncated || stderr.truncated, Notes: n.String()}, nil
}

func withNotes(err error, n *notes) error {
	if s := n.String(); s != "" {
		return fmt.Errorf("%w\n\n%s", err, s)
	}
	return err
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- ssh_run ----

type SSHIn struct {
	Destination    string   `json:"destination" jsonschema:"ssh destination: a Host from ~/.ssh/config, or user@host"`
	Command        string   `json:"command" jsonschema:"the command to run on the remote host"`
	SSHArgs        []string `json:"ssh_args,omitempty" jsonschema:"extra ssh options, e.g. [\"-p\", \"2222\"]"`
	Reason         string   `json:"reason" jsonschema:"why; the person sees this when approving"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"stop after this long (default 180, max 1800)"`
}

func (s *Server) sshRun(ctx context.Context, req *mcp.CallToolRequest, in SSHIn) (*mcp.CallToolResult, RunOut, error) {
	if in.Destination == "" || strings.HasPrefix(in.Destination, "-") {
		return nil, RunOut{}, errors.New("destination is required (and can't start with '-')")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, RunOut{}, errors.New("reason is required: say why, the person sees it")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return nil, RunOut{}, errors.New("ssh is not installed")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout(in.TimeoutSeconds))
	defer cancel()
	dir, err := os.MkdirTemp("", "asiri-ssh-")
	if err != nil {
		return nil, RunOut{}, err
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "agent.sock")
	ln, err := sshagent.Listen(sock)
	if err != nil {
		return nil, RunOut{}, err
	}
	n := &notes{ctx: ctx, req: req}
	cwd, _ := os.Getwd()
	agent := &sshagent.Agent{API: s.API, Granter: &run.Runner{API: s.API, Approver: s.Approver(n), Notes: n},
		Reason: in.Reason, Cwd: cwd, Log: n}
	go agent.Serve(ctx, ln)

	args := append([]string{"-o", "IdentityAgent=" + sock, "-o", "BatchMode=yes"}, in.SSHArgs...)
	args = append(args, "--", in.Destination, in.Command)
	var stdout, stderr capped
	cmd := exec.CommandContext(ctx, sshBin, args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(""), &stdout, &stderr
	err = cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		return nil, RunOut{}, withNotes(err, n)
	}
	return nil, RunOut{ExitCode: code, Stdout: stdout.buf.String(), Stderr: stderr.buf.String(),
		Truncated: stdout.truncated || stderr.truncated, Notes: n.String()}, nil
}

// ---- request_missing_secret ----

type MissingIn struct {
	Ref         string `json:"ref" jsonschema:"the reference you need, e.g. asiri://dev/github"`
	Reason      string `json:"reason" jsonschema:"what it's for; the person sees this"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the person to add it (default 120, max 600)"`
}

type MissingOut struct {
	Ref     string `json:"ref"`
	Exists  bool   `json:"exists"`
	Message string `json:"message"`
}

func (s *Server) requestMissing(ctx context.Context, req *mcp.CallToolRequest, in MissingIn) (*mcp.CallToolResult, MissingOut, error) {
	ref, err := domain.ParseRef(in.Ref)
	if err != nil {
		return nil, MissingOut{}, err
	}
	exists := func() (bool, error) {
		items, err := s.API.ListItems(ctx, ref.Vault+"/"+ref.Name+"/"+ref.Field)
		if err != nil {
			return false, err
		}
		for _, it := range items {
			if it.Ref == ref {
				return true, nil
			}
		}
		return false, nil
	}
	if ok, err := exists(); err != nil || ok {
		return nil, MissingOut{Ref: ref.String(), Exists: ok, Message: "it already exists; use it with run_with_secrets"}, err
	}
	wait := 120 * time.Second
	if in.WaitSeconds > 0 {
		wait = min(time.Duration(in.WaitSeconds)*time.Second, 10*time.Minute)
	}
	ask := fmt.Sprintf("an agent needs %s (%s). Add it in your own terminal, never in the chat:\n\n  asiri add %s\n", ref, in.Reason, ref)
	(&notes{ctx: ctx, req: req}).Write([]byte(ask))
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, MissingOut{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if ok, err := exists(); err != nil {
			return nil, MissingOut{}, err
		} else if ok {
			return nil, MissingOut{Ref: ref.String(), Exists: true, Message: "added; use it with run_with_secrets (its policy may still need a program allowed)"}, nil
		}
	}
	return nil, MissingOut{Ref: ref.String(), Exists: false,
		Message: "not added yet. Ask the person, in your reply, to run `asiri add " + ref.String() + "` in their own terminal, then try again."}, nil
}
