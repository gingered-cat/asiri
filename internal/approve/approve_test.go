package approve

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

type fixed struct {
	ans Answer
	err error
}

func (f fixed) Approve(context.Context, Prompt) (Answer, error) { return f.ans, f.err }

func TestChain(t *testing.T) {
	ctx := context.Background()
	c := Chain{fixed{err: ErrUnavailable}, fixed{ans: Answer{domain.Decide15m, domain.MethodTTY}}, fixed{err: errors.New("never")}}
	if a, err := c.Approve(ctx, Prompt{}); err != nil || a.Decision != domain.Decide15m {
		t.Fatalf("chain = %+v, %v", a, err)
	}
	if _, err := (Chain{fixed{err: ErrUnavailable}}).Approve(ctx, Prompt{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("all unavailable: %v", err)
	}
}

func TestAsk(t *testing.T) {
	for in, want := range map[string]domain.Decision{
		"\n": domain.DecideOnce, "f\n": domain.Decide15m, "H\n": domain.Decide1h, "d\n": domain.DecideDeny,
		"what\nd\n": domain.DecideDeny, "": domain.DecideDeny,
	} {
		var out bytes.Buffer
		got, err := ask(context.Background(), strings.NewReader(in), &out, Prompt{Title: "claude wants asiri://dev/x", Detail: "gh"})
		if err != nil || got != want {
			t.Errorf("ask(%q) = %s, %v; want %s", in, got, err, want)
		}
		if !strings.Contains(out.String(), "claude wants asiri://dev/x") {
			t.Errorf("prompt missing title: %q", out.String())
		}
	}
}

type waiter struct{ calls int }

func (w *waiter) Request(context.Context, domain.RequestID, time.Duration) (domain.Request, error) {
	w.calls++
	if w.calls < 3 {
		return domain.Request{Status: domain.StatusPending}, nil
	}
	return domain.Request{Status: domain.StatusApproved}, nil
}

func TestWait(t *testing.T) {
	var out bytes.Buffer
	w := &waiter{}
	_, err := Wait{API: w, Out: &out}.Approve(context.Background(), Prompt{RequestID: "R1", Title: "t", Detail: "d"})
	if !errors.Is(err, ErrAlreadyDecided) || w.calls != 3 {
		t.Fatalf("wait = %v after %d calls", err, w.calls)
	}
	if !strings.Contains(out.String(), "asiri approve R1") {
		t.Fatalf("no instructions: %q", out.String())
	}
}
