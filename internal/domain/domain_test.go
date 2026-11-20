package domain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		in      string
		want    Ref
		str     string
		wantErr bool
	}{
		{in: "asiri://dev/github", want: Ref{"dev", "github", "value"}, str: "asiri://dev/github"},
		{in: "dev/github", want: Ref{"dev", "github", "value"}, str: "asiri://dev/github"},
		{in: "asiri://apple/github.com/password", want: Ref{"apple", "github.com", "password"}, str: "asiri://apple/github.com/password"},
		{in: "asiri://dev", wantErr: true},
		{in: "asiri://dev/a/b/c", wantErr: true},
		{in: "asiri://dev/../x", wantErr: true},
		{in: "asiri://dev/-x", wantErr: true},
		{in: "asiri:///x", wantErr: true},
		{in: "asiri://dev/" + strings.Repeat("a", 65), wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseRef(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseRef(%q) = %v, want error", tt.in, got)
			} else if CodeOf(err) != CodeInvalid {
				t.Errorf("ParseRef(%q) code = %s, want invalid", tt.in, CodeOf(err))
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseRef(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
			continue
		}
		if got.String() != tt.str {
			t.Errorf("String() = %q, want %q", got.String(), tt.str)
		}
	}
}

func TestRefJSON(t *testing.T) {
	b, err := json.Marshal(struct{ R Ref }{Ref{"dev", "github", "value"}})
	if err != nil || string(b) != `{"R":"asiri://dev/github"}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	var v struct{ R Ref }
	if err := json.Unmarshal(b, &v); err != nil || v.R.Name != "github" {
		t.Fatalf("unmarshal = %+v, %v", v, err)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret([]byte("hunter2-very-secret"))
	var sb strings.Builder
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		fmt.Fprintf(&sb, f, s)
		fmt.Fprintf(&sb, f, struct{ S Secret }{s})
	}
	j, _ := json.Marshal(map[string]any{"s": s})
	sb.Write(j)
	slog.New(slog.NewTextHandler(&sb, nil)).Info("x", "secret", s)
	if strings.Contains(sb.String(), "hunter2") || strings.Contains(sb.String(), fmt.Sprintf("%x", "hunter2")) {
		t.Fatalf("secret leaked: %s", sb.String())
	}
	s.Zero()
	if string(s.Reveal()) == "hunter2-very-secret" {
		t.Fatal("Zero did not clear")
	}
}

func TestNewIDSortsAndIsUnique(t *testing.T) {
	a := newIDAt(time.UnixMilli(1_000))
	b := newIDAt(time.UnixMilli(2_000))
	if len(a) != 26 || a >= b {
		t.Fatalf("ids %q %q", a, b)
	}
	seen := map[string]bool{}
	for range 10_000 {
		id := NewID()
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
	}
}

func TestIsInterpreter(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/bin/bash", "/opt/homebrew/bin/python3.12", "/usr/bin/python3", "node",
		"/usr/bin/env", "/usr/bin/xargs", "/usr/bin/awk", "/opt/homebrew/bin/pwsh", "/usr/bin/sudo", "ruby3.3"} {
		if !IsInterpreter(p) {
			t.Errorf("%s should be refused", p)
		}
	}
	for _, p := range []string{"/opt/homebrew/bin/gh", "/usr/bin/psql", "/usr/local/bin/terraform", "/usr/bin/curl", "/usr/bin/printenv"} {
		if IsInterpreter(p) {
			t.Errorf("%s should be allowed", p)
		}
	}
}

func TestClampAndAllowed(t *testing.T) {
	if Decide1h.Clamp("15m") != Decide15m || Decide15m.Clamp("1h") != Decide15m || Decide1h.Clamp("once") != DecideOnce ||
		DecideDeny.Clamp("once") != DecideDeny || Decide1h.Clamp("") != Decide1h {
		t.Fatal("clamp")
	}
	if !BinAllowed([]string{"gh"}, "/opt/homebrew/bin/gh") || !BinAllowed([]string{"/usr/bin/psql"}, "/usr/bin/psql") ||
		BinAllowed([]string{"gh"}, "/usr/bin/ghx") {
		t.Fatal("allowed")
	}
}
