package approve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Rex asks in the Rex command palette on every connected app, through the
// asiri_approve action that `asiri rex install` adds. The action records the
// answer itself with the owner's profile, so this approver never returns a
// decision: it returns ErrAlreadyDecided, or ErrUnavailable when Rex isn't
// there to ask (not installed, not running, no app connected, busy, timed out).
type Rex struct {
	Bin    string    // rex binary; "" looks it up on PATH
	Server string    // rex -S value (a host label or socket); "" is the local server
	Out    io.Writer // progress notes
}

type rexResult struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
}

func (r Rex) Approve(ctx context.Context, p Prompt) (Answer, error) {
	bin := r.Bin
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("rex"); err != nil {
			return Answer{}, ErrUnavailable
		}
	}
	args, _ := json.Marshal(map[string]string{"id": string(p.RequestID), "title": p.Title, "detail": p.Detail})
	wait := time.Until(p.ExpiresAt) + 5*time.Second
	if wait < 10*time.Second {
		wait = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, wait+5*time.Second)
	defer cancel()
	if r.Out != nil {
		fmt.Fprintf(r.Out, "asiri: asking in Rex: %s\n", p.Title)
	}
	argv := []string{"--autostart=false", "--timeout", wait.Round(time.Second).String()}
	if r.Server != "" {
		argv = append(argv, "-S", r.Server)
	}
	argv = append(argv, "do", "asiri_approve", "--args", string(args), "--json")
	cmd := exec.CommandContext(ctx, bin, argv...)
	out, err := cmd.Output()
	if err != nil {
		if r.Out != nil {
			fmt.Fprintf(r.Out, "asiri: Rex couldn't ask (%s)\n", rexReason(err))
		}
		return Answer{}, ErrUnavailable
	}
	var res rexResult
	if err := json.Unmarshal(out, &res); err != nil {
		return Answer{}, ErrUnavailable
	}
	switch res.Result {
	case "once", "15m", "1h", "deny":
		return Answer{}, ErrAlreadyDecided
	case "error":
		return Answer{}, fmt.Errorf("the Rex plugin couldn't record the answer: %s", res.Reason)
	}
	if r.Out != nil && res.Reason != "" {
		fmt.Fprintf(r.Out, "asiri: Rex couldn't ask (%s)\n", res.Reason)
	}
	return Answer{}, ErrUnavailable
}

func rexReason(err error) string {
	var ee *exec.ExitError
	if ok := asExit(err, &ee); ok && len(ee.Stderr) > 0 {
		line := strings.TrimSpace(strings.SplitN(string(ee.Stderr), "\n", 2)[0])
		if line != "" {
			return line
		}
	}
	return err.Error()
}

func asExit(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
