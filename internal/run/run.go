// Package run starts a program with secrets delivered to it, and scrubs
// those secrets out of what it prints.
package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/domain"
)

// Exit codes for asiri's own failures, as in `docker run`. Any other code is
// the program's own.
const (
	ExitFailed   = 125 // asiri couldn't run the program
	ExitDenied   = 126 // refused, denied or expired
	ExitNotFound = 127 // the program doesn't exist
)

// ExitError carries the exit code asiri should end with.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// API is the part of the server the runner needs. It is an interface so
// tests can run the runner without a server.
type API interface {
	CreateRequest(ctx context.Context, req api.CreateRequest) (api.RequestResponse, error)
	Request(ctx context.Context, id domain.RequestID, wait time.Duration) (domain.Request, error)
	Decide(ctx context.Context, id domain.RequestID, d domain.Decision, m domain.Method) (domain.Request, error)
	Redeem(ctx context.Context, id domain.GrantID) (domain.Grant, domain.Secret, error)
	ReportScrub(ctx context.Context, id domain.GrantID, hits int) error
}

// Spec is one program to run.
type Spec struct {
	Bin        string
	Args       []string
	Deliveries []Delivery
	Reason     string
	Dir        string   // working directory; "" is the current one
	Env        []string // base environment; nil means os.Environ()
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

// Runner is the facade behind `asiri run` and the MCP tool: resolve,
// request, approve, redeem, deliver, run, scrub, clean up.
type Runner struct {
	API      API
	Approver approve.Approver
	// Notes is where the runner prints progress (approval waits). Usually stderr.
	Notes io.Writer
}

// Run runs spec and returns the program's exit code. A non-nil error is an
// *ExitError with asiri's own exit code.
func (r *Runner) Run(ctx context.Context, spec Spec) (int, error) {
	bin, sum, err := resolve(spec.Bin)
	if err != nil {
		return ExitNotFound, &ExitError{ExitNotFound, err}
	}
	if err := checkDeliveries(spec.Deliveries); err != nil {
		return ExitFailed, &ExitError{ExitFailed, err}
	}
	cwd := spec.Dir
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	// One grant per delivery, asked for in order.
	type got struct {
		d     Delivery
		grant domain.Grant
		sec   domain.Secret
	}
	var redeemed []got
	defer func() {
		for _, g := range redeemed {
			g.sec.Zero()
		}
	}()
	for _, d := range spec.Deliveries {
		gid, err := r.grant(ctx, api.CreateRequest{Ref: d.Ref(), BinPath: bin, BinSHA256: sum,
			Argv: spec.Args, Cwd: tildeHome(cwd), Reason: spec.Reason})
		if err != nil {
			var ee *ExitError
			if errors.As(err, &ee) {
				return ee.Code, ee
			}
			return exitCode(err), &ExitError{exitCode(err), err}
		}
		g, sec, err := r.API.Redeem(ctx, gid)
		if err != nil {
			return ExitDenied, &ExitError{ExitDenied, fmt.Errorf("%s: %w", d.Ref(), err)}
		}
		redeemed = append(redeemed, got{d: d, grant: g, sec: sec})
	}

	cmd := exec.Command(bin, spec.Args...)
	cmd.Args[0] = spec.Bin
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Stdin = spec.Stdin
	var values []Value
	for _, g := range redeemed {
		cleanup, err := g.d.Apply(cmd, g.sec)
		if err != nil {
			return ExitFailed, &ExitError{ExitFailed, err}
		}
		defer cleanup()
		values = append(values, Value{Secret: g.sec.Reveal(), Label: g.d.Ref().String()})
	}
	stdout := NewScrubber(orDiscard(spec.Stdout), values)
	stderr := NewScrubber(orDiscard(spec.Stderr), values)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	if err := cmd.Start(); err != nil {
		return ExitFailed, &ExitError{ExitFailed, err}
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	waitErr := cmd.Wait()
	signal.Stop(sigs)
	close(sigs)
	stdout.Flush()
	stderr.Flush()

	// Tell the server if the program printed a secret it was given.
	so, se := stdout.Hits(), stderr.Hits()
	for i, g := range redeemed {
		if n := so[i] + se[i]; n > 0 {
			r.API.ReportScrub(context.WithoutCancel(ctx), g.grant.ID, n)
		}
	}
	return childExit(waitErr)
}

// grant returns a grant for req: reused, or approved by a person.
func (r *Runner) grant(ctx context.Context, req api.CreateRequest) (domain.GrantID, error) {
	resp, err := r.API.CreateRequest(ctx, req)
	if err != nil {
		return "", err
	}
	rq := resp.Request
	if rq.Status == domain.StatusPending {
		ans, aerr := r.Approver.Approve(ctx, approve.Prompt{RequestID: rq.ID, Title: rq.Title, Detail: rq.Detail, ExpiresAt: rq.ExpiresAt})
		switch {
		case errors.Is(aerr, approve.ErrAlreadyDecided):
			rq, err = r.API.Request(ctx, rq.ID, 0)
		case errors.Is(aerr, approve.ErrUnavailable):
			return "", &ExitError{ExitDenied, fmt.Errorf("nobody could be asked to approve %s", req.Ref)}
		case aerr != nil:
			return "", &ExitError{ExitDenied, aerr}
		default:
			rq, err = r.API.Decide(ctx, rq.ID, ans.Decision, ans.Method)
			if domain.CodeOf(err) == domain.CodeConflict {
				err = nil // decided elsewhere first; rq is its current state
			}
		}
		if err != nil {
			return "", err
		}
	}
	switch rq.Status {
	case domain.StatusApproved:
		return rq.GrantID, nil
	case domain.StatusDenied:
		return "", &ExitError{ExitDenied, domain.Errorf(domain.CodeDenied, "%s: denied", req.Ref)}
	case domain.StatusExpired:
		return "", &ExitError{ExitDenied, domain.Errorf(domain.CodeExpired, "%s: nobody approved in time", req.Ref)}
	}
	return "", &ExitError{ExitFailed, fmt.Errorf("%s: request is %s", req.Ref, rq.Status)}
}

func exitCode(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	switch domain.CodeOf(err) {
	case domain.CodeNotAllowed, domain.CodeInterpreter, domain.CodeDenied, domain.CodeExpired,
		domain.CodeSpent, domain.CodeRevoked, domain.CodeNotFound:
		return ExitDenied
	}
	return ExitFailed
}

func childExit(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return ExitFailed, &ExitError{ExitFailed, err}
}

// resolve finds bin on PATH and returns its real path and SHA-256.
func resolve(bin string) (string, string, error) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", "", fmt.Errorf("%s: not found", bin)
	}
	if p, err = filepath.Abs(p); err != nil {
		return "", "", err
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return "", "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return p, hex.EncodeToString(h.Sum(nil)), nil
}

func checkDeliveries(ds []Delivery) error {
	if len(ds) == 0 {
		return errors.New("nothing to deliver: pass --env NAME=REF, --stdin REF or --file NAME=REF")
	}
	stdin := 0
	names := map[string]bool{}
	for _, d := range ds {
		switch d := d.(type) {
		case Stdin:
			stdin++
		case Env:
			if names[d.Name] {
				return fmt.Errorf("%s is set twice", d.Name)
			}
			names[d.Name] = true
		case File:
			if names[d.Name] {
				return fmt.Errorf("%s is set twice", d.Name)
			}
			names[d.Name] = true
		}
	}
	if stdin > 1 {
		return errors.New("only one secret can go to stdin")
	}
	return nil
}

func tildeHome(p string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" && (p == h || strings.HasPrefix(p, h+string(os.PathSeparator))) {
		return "~" + p[len(h):]
	}
	return p
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
