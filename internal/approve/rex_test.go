package approve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRex writes a shell script standing in for the rex CLI: it records its
// arguments and prints out.
func fakeRex(t *testing.T, out string, exit int) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "rex")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nprintf '%s' '" + out + "'\necho 'rex: no client connected' >&2\nexit " +
		string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestRexApprover(t *testing.T) {
	p := Prompt{RequestID: "R1", Title: "claude wants asiri://dev/github", Detail: "gh pr create", ExpiresAt: time.Now().Add(time.Minute)}
	ctx := context.Background()

	bin, argsFile := fakeRex(t, `{"result":"15m"}`, 0)
	if _, err := (Rex{Bin: bin}).Approve(ctx, p); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("answered: %v", err)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"--autostart=false", "do", "asiri_approve", `"id":"R1"`, `"title":"claude wants asiri://dev/github"`, "--json"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("rex args missing %q:\n%s", want, args)
		}
	}

	for name, out := range map[string]string{
		"unavailable": `{"result":"unavailable","reason":"no_client"}`,
		"garbage":     `not json`,
	} {
		bin, _ := fakeRex(t, out, 0)
		if _, err := (Rex{Bin: bin}).Approve(ctx, p); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bin, _ = fakeRex(t, "", 1) // rex not running, or the plugin isn't installed
	var notes strings.Builder
	if _, err := (Rex{Bin: bin, Out: &notes}).Approve(ctx, p); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rex failed: %v", err)
	}
	if !strings.Contains(notes.String(), "no client connected") {
		t.Fatalf("notes %q", notes.String())
	}
	bin, _ = fakeRex(t, `{"result":"error","reason":"not paired"}`, 0)
	if _, err := (Rex{Bin: bin}).Approve(ctx, p); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("plugin error: %v", err)
	}
	if _, err := (Rex{Bin: filepath.Join(t.TempDir(), "missing")}).Approve(ctx, p); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing rex: %v", err)
	}
}
