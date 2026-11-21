// Package approve asks a person whether a request may go ahead. Approvers
// are tried in order; one that can't ask right now returns ErrUnavailable
// and the next one gets a turn.
package approve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/gingered-cat/asiri/internal/domain"
)

// Prompt is what the person sees. Title and Detail come from the server.
type Prompt struct {
	RequestID domain.RequestID
	Title     string // "claude wants asiri://dev/github"
	Detail    string // "gh pr create · ~/proj/api · \"open the PR\""
	ExpiresAt time.Time
}

// Answer is a person's decision and how it was made.
type Answer struct {
	Decision domain.Decision
	Method   domain.Method
}

type Approver interface {
	Approve(ctx context.Context, p Prompt) (Answer, error)
}

var (
	// ErrUnavailable means this approver can't ask right now; try the next.
	ErrUnavailable = errors.New("approver unavailable")
	// ErrAlreadyDecided means the decision was recorded elsewhere (for
	// example `asiri approve` in another terminal); read the request again.
	ErrAlreadyDecided = errors.New("decided elsewhere")
)

// Chain tries each approver in order.
type Chain []Approver

func (c Chain) Approve(ctx context.Context, p Prompt) (Answer, error) {
	for _, a := range c {
		ans, err := a.Approve(ctx, p)
		if errors.Is(err, ErrUnavailable) {
			continue
		}
		return ans, err
	}
	return Answer{}, ErrUnavailable
}

// TTY asks in the terminal. It only asks when stdin is a terminal, which
// means a person ran the command; agents run commands with piped stdin and
// get the next approver instead.
type TTY struct{}

func (TTY) Approve(ctx context.Context, p Prompt) (Answer, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return Answer{}, ErrUnavailable
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Answer{}, ErrUnavailable
	}
	defer tty.Close()
	d, err := ask(ctx, tty, tty, p)
	return Answer{Decision: d, Method: domain.MethodTTY}, err
}

func ask(ctx context.Context, in io.Reader, out io.Writer, p Prompt) (domain.Decision, error) {
	fmt.Fprintf(out, "\nasiri  %s\n       %s\n", p.Title, p.Detail)
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for {
		fmt.Fprint(out, "       [return] once  [f] 15 min  [h] 1 hour  [d] deny: ")
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			return "", ctx.Err()
		case line, ok := <-lines:
			if !ok {
				return domain.DecideDeny, nil
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "", "o", "once", "y", "yes":
				return domain.DecideOnce, nil
			case "f", "15", "15m":
				return domain.Decide15m, nil
			case "h", "1h", "hour":
				return domain.Decide1h, nil
			case "d", "n", "no", "deny":
				return domain.DecideDeny, nil
			}
		}
	}
}

// RequestWaiter reads a request, waiting while it is pending.
type RequestWaiter interface {
	Request(ctx context.Context, id domain.RequestID, wait time.Duration) (domain.Request, error)
}

// Wait prints how to approve from another terminal and waits for the
// decision. It always ends with ErrAlreadyDecided (or a context error).
type Wait struct {
	API RequestWaiter
	Out io.Writer
}

func (w Wait) Approve(ctx context.Context, p Prompt) (Answer, error) {
	fmt.Fprintf(w.Out, "asiri: %s\nasiri:   %s\nasiri: waiting for approval (until %s). in your terminal, run:\n\n  asiri approve %s\n\n",
		p.Title, p.Detail, p.ExpiresAt.Local().Format("15:04:05"), p.RequestID)
	for {
		r, err := w.API.Request(ctx, p.RequestID, 25*time.Second)
		if err != nil {
			return Answer{}, err
		}
		if r.Status != domain.StatusPending {
			return Answer{}, ErrAlreadyDecided
		}
	}
}
