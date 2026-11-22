package approvalkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var req = Request{
	Action: ActionUse, Server: "ab12cd34", ID: "r1", Client: "claude", ClientID: "c1", Ref: "asiri://dev/github",
	Program: "/opt/homebrew/bin/gh", SHA256: "00ff", Decision: "15m",
	ExpiresAt: time.Date(2026, 11, 22, 12, 0, 0, 0, time.FixedZone("x", 3600)),
}

func TestStatement(t *testing.T) {
	got := string(Statement(req))
	want := "asiri approval v1\naction: use\nserver: ab12cd34\nrequest: r1\nclient: claude\nclient_id: c1\nsecret: asiri://dev/github\n" +
		"program: /opt/homebrew/bin/gh\nprogram_sha256: 00ff\nhost: \ndecision: 15m\nexpires: 2026-11-22T11:00:00Z\n"
	if got != want {
		t.Fatalf("statement:\n%s\nwant:\n%s", got, want)
	}
}

// A program path is chosen by the agent. It must not be able to add a line
// that changes what the person reads or what the server checks.
func TestStatementQuotesControlCharacters(t *testing.T) {
	r := req
	r.Program = "/tmp/gh\ndecision: once"
	s := string(Statement(r))
	if strings.Count(s, "\ndecision: ") != 1 || !strings.Contains(s, `program: "/tmp/gh\ndecision: once"`) {
		t.Fatalf("not quoted:\n%s", s)
	}
	d, err := Describe([]byte(s))
	if err != nil || !strings.HasSuffix(d, "for 15 minutes") {
		t.Fatalf("describe = %q, %v", d, err)
	}
}

func TestVerify(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	msg := Statement(req)
	sum := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	other := req
	other.Decision = "1h"
	if Verify(pub, Statement(other), sig) == nil {
		t.Fatal("signature for 15m accepted for 1h")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pub384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKey(pub384); err == nil {
		t.Fatal("P-384 key accepted")
	}
	if len(ID(pub)) != 16 {
		t.Fatalf("id %q", ID(pub))
	}
}

// testdata/describe holds statements and the sentence each must produce.
// The Swift helper's CI job runs the same files, so both stay in step.
func TestDescribe(t *testing.T) {
	files, _ := filepath.Glob("testdata/describe/*.stmt")
	if len(files) < 4 {
		t.Fatalf("only %d cases", len(files))
	}
	for _, f := range files {
		msg, _ := os.ReadFile(f)
		want, _ := os.ReadFile(strings.TrimSuffix(f, ".stmt") + ".want")
		got, err := Describe(msg)
		if err != nil {
			got = "error"
		}
		if got != strings.TrimSpace(string(want)) {
			t.Errorf("%s: got %q, want %q", filepath.Base(f), got, strings.TrimSpace(string(want)))
		}
	}
}

func TestDescribeMatchesStatement(t *testing.T) {
	for _, d := range []string{"once", "15m", "1h"} {
		r := req
		r.Decision = d
		if _, err := Describe(Statement(r)); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
	if _, err := Describe(EnrollStatement("ab", []byte("k"))); err != nil {
		t.Fatal(err)
	}
}
