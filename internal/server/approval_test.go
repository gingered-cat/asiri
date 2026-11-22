package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approvalkey"
	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
)

// softKey stands in for the Secure Enclave helper: same curve, same
// signature encoding, no Touch ID.
type softKey struct {
	k      *ecdsa.PrivateKey
	pub    []byte
	signed [][]byte // statements it was asked to sign
}

func newSoftKey(t *testing.T) *softKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return &softKey{k: k, pub: pub}
}

func (s *softKey) KeyID(context.Context) (string, error) { return approvalkey.ID(s.pub), nil }

func (s *softKey) Sign(_ context.Context, msg []byte) ([]byte, error) {
	s.signed = append(s.signed, msg)
	sum := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.k, sum[:])
}

func (s *softKey) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// enroll adds key, endorsed by endorser when one is already enrolled.
func enroll(t *testing.T, c *client.Client, key, endorser *softKey) (domain.ApprovalKey, error) {
	t.Helper()
	ch, err := c.EnrollChallenge(ctx, key.pub)
	if err != nil {
		return domain.ApprovalKey{}, err
	}
	req := api.EnrollApprovalKeyRequest{Name: "test mac", PublicKey: key.pub, Proof: key.sign(t, ch.Statement)}
	if endorser != nil {
		req.EndorsedBy, _ = endorser.KeyID(ctx)
		req.Endorsement = endorser.sign(t, ch.Statement)
	}
	return c.EnrollApprovalKey(ctx, req)
}

func TestSignedApprovals(t *testing.T) {
	e := setup(t)
	owner := e.pair(t, "owner", domain.RoleOwner)
	agent := e.pair(t, "claude", domain.RoleAgent)
	ref, _ := domain.ParseRef("dev/github")
	if _, err := owner.PutItem(ctx, ref, "", domain.NewSecret([]byte("ghp_SIGNED_value"))); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.SetPolicy(ctx, ref, domain.Policy{Bins: []string{"gh"}, MaxGrant: "1h"}); err != nil {
		t.Fatal(err)
	}
	pending := func() domain.Request {
		t.Helper()
		r, err := agent.CreateRequest(ctx, ghRequest(ref, "/opt/homebrew/bin/gh", "pr", "create"))
		if err != nil || r.Request.Status != domain.StatusPending {
			t.Fatalf("create = %+v, %v", r, err)
		}
		return r.Request
	}

	// No key enrolled: v0.1 behaviour, an owner approves without signing.
	if d, err := owner.Decide(ctx, pending().ID, domain.DecideOnce, domain.MethodCLI); err != nil || d.Method != domain.MethodCLI {
		t.Fatalf("unsigned before enrolment = %+v, %v", d, err)
	}

	// Enrolment: agents can't; a key must prove itself; then it's live.
	mac := newSoftKey(t)
	if _, err := agent.EnrollChallenge(ctx, mac.pub); code(err) != domain.CodeNotAllowed {
		t.Fatalf("agent enroll: %v", err)
	}
	ch, _ := owner.EnrollChallenge(ctx, mac.pub)
	if d, err := approvalkey.Describe(ch.Statement); err != nil || !strings.HasPrefix(d, "use this Mac to approve") {
		t.Fatalf("enroll statement %q: %v", d, err)
	}
	impostor := newSoftKey(t)
	if _, err := owner.EnrollApprovalKey(ctx, api.EnrollApprovalKeyRequest{Name: "x", PublicKey: mac.pub,
		Proof: impostor.sign(t, ch.Statement)}); code(err) != domain.CodeNotAllowed {
		t.Fatalf("enroll with someone else's proof: %v", err)
	}
	k, err := enroll(t, owner, mac, nil)
	if err != nil || k.ID != approvalkey.ID(mac.pub) {
		t.Fatalf("enroll = %+v, %v", k, err)
	}
	if keys, _ := owner.ApprovalKeys(ctx); len(keys) != 1 || keys[0].ID != k.ID {
		t.Fatalf("keys = %+v", keys)
	}

	// Holding the owner profile is no longer enough to allow.
	rq := pending()
	if _, err := owner.Decide(ctx, rq.ID, domain.DecideOnce, domain.MethodCLI); !errors.Is(err, client.ErrNoApprovalKey) {
		t.Fatalf("owner without a signer: %v", err)
	}
	raw := api.DecisionRequest{Decision: domain.DecideOnce, Method: domain.MethodCLI}
	if _, err := e.svc.Decide(ctx, ownerClient(t, e), rq.ID, raw); code(err) != domain.CodeNotAllowed ||
		!strings.Contains(err.Error(), "need Touch ID") {
		t.Fatalf("unsigned allow straight to the service: %v", err)
	}
	// A deny needs no signature.
	if d, err := owner.Decide(ctx, pending().ID, domain.DecideDeny, domain.MethodCLI); err != nil || d.Status != domain.StatusDenied {
		t.Fatalf("unsigned deny = %+v, %v", d, err)
	}

	// Signed: the signer saw this request's statement, and the decision is
	// recorded as touchid.
	owner.Signer = mac
	d, err := owner.Decide(ctx, rq.ID, domain.Decide15m, domain.MethodRex)
	if err != nil || d.Status != domain.StatusApproved || d.Method != domain.MethodTouchID {
		t.Fatalf("signed decide = %+v, %v", d, err)
	}
	last := string(mac.signed[len(mac.signed)-1])
	for _, want := range []string{"action: use", "request: " + string(rq.ID), "client: claude", "client_id: " + string(rq.ClientID), "secret: asiri://dev/github",
		"program: /opt/homebrew/bin/gh", "decision: 15m"} {
		if !strings.Contains(last, want) {
			t.Fatalf("statement lacks %q:\n%s", want, last)
		}
	}

	// Clear the 15m grant so the next requests wait for a decision again.
	if _, err := owner.RevokeAll(ctx); err != nil {
		t.Fatal(err)
	}
	// A signature only works for the request and decision it was made for.
	r2, r3 := pending(), pending()
	chOnce, _ := owner.ApprovalChallenge(ctx, r2.ID, domain.DecideOnce)
	sigOnce := mac.sign(t, chOnce.Statement)
	for name, try := range map[string]struct {
		id domain.RequestID
		d  domain.Decision
	}{"other decision": {r2.ID, domain.Decide1h}, "other request": {r3.ID, domain.DecideOnce}} {
		_, err := e.svc.Decide(ctx, ownerClient(t, e), try.id, api.DecisionRequest{Decision: try.d,
			Method: domain.MethodCLI, KeyID: k.ID, Signature: sigOnce})
		if code(err) != domain.CodeNotAllowed {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A key that isn't enrolled can't sign, even if it signs correctly.
	if _, err := e.svc.Decide(ctx, ownerClient(t, e), r2.ID, api.DecisionRequest{Decision: domain.DecideOnce,
		Method: domain.MethodCLI, KeyID: approvalkey.ID(impostor.pub), Signature: impostor.sign(t, chOnce.Statement)}); code(err) != domain.CodeNotAllowed {
		t.Fatalf("unenrolled key: %v", err)
	}
	if d, err := e.svc.Decide(ctx, ownerClient(t, e), r2.ID, api.DecisionRequest{Decision: domain.DecideOnce,
		Method: domain.MethodCLI, KeyID: k.ID, Signature: sigOnce}); err != nil || d.Method != domain.MethodTouchID {
		t.Fatalf("correct signature = %+v, %v", d, err)
	}

	// A second key needs the first one's endorsement.
	laptop := newSoftKey(t)
	if _, err := enroll(t, owner, laptop, nil); code(err) != domain.CodeNotAllowed {
		t.Fatalf("second key without endorsement: %v", err)
	}
	if _, err := enroll(t, owner, laptop, impostor); code(err) != domain.CodeNotAllowed {
		t.Fatalf("second key endorsed by a stranger: %v", err)
	}
	if _, err := enroll(t, owner, laptop, mac); err != nil {
		t.Fatalf("endorsed second key: %v", err)
	}
	owner.Signer = laptop
	if _, err := owner.Decide(ctx, r3.ID, domain.DecideOnce, domain.MethodCLI); err != nil {
		t.Fatalf("approve with the second key: %v", err)
	}

	// Reset (server-side only) goes back to unsigned approvals.
	if n, err := e.svc.ResetApprovalKeys(ctx); err != nil || n != 2 {
		t.Fatalf("reset = %d, %v", n, err)
	}
	owner.Signer = nil
	if _, err := owner.Decide(ctx, pending().ID, domain.DecideOnce, domain.MethodCLI); err != nil {
		t.Fatalf("unsigned after reset: %v", err)
	}

	// The audit log tells the story, and the chain still verifies.
	evs, err := owner.Audit(ctx, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, ev := range evs {
		seen[ev.Event]++
		if ev.Event == audit.Decision && ev.Detail["key"] != "" && ev.Detail["via"] == "" {
			t.Fatalf("signed decision without via: %+v", ev.Detail)
		}
	}
	if seen[audit.KeyEnroll] != 2 || seen[audit.KeysReset] != 1 || seen[audit.Anomaly] == 0 {
		t.Fatalf("audit events: %v", seen)
	}
	if _, err := owner.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func ownerClient(t *testing.T, e env) domain.Client {
	t.Helper()
	cs, err := e.svc.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Name == "owner" {
			return c
		}
	}
	t.Fatal("no owner")
	return domain.Client{}
}
