// Command asiri lets agents use secrets without seeing them.
//
// The same binary is the server (`asiri server ...`, usually in a container)
// and the CLI that people and agents run on the host.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/server"
)

// Exit codes, as in `docker run`: 125 asiri itself failed. 126 and 127 are
// kept for `asiri run` (denied, binary not found).
const (
	exitUsage = 2
	exitAsiri = 125
)

type command struct {
	usage string
	help  string
	run   func(ctx context.Context, args []string) error
}

var commands map[string]command

func init() {
	commands = map[string]command{
		"server":  {"server <init|run|keygen|pair-code|health> ...", "run or set up the server (in the container)", serverCmd},
		"pair":    {"pair --code CODE [--server URL] [--profile P] [--force]", "pair this machine with a server", pairCmd},
		"add":     {"add REF [--kind K] [--stdin]", "store a secret (typed without echo, or from stdin)", addCmd},
		"ls":      {"ls [QUERY] [--json]", "list secrets (names only, never values)", lsCmd},
		"status":  {"status", "show the profile, server and lock state", statusCmd},
		"unlock":  {"unlock", "unlock the vault", unlockCmd},
		"lock":    {"lock", "lock the vault now", lockCmd},
		"clients": {"clients <add NAME [--role R] [--replace] | ls | revoke NAME>", "manage paired clients", clientsCmd},
		"log":     {"log [--since N] [--limit N] [--json] | log verify", "read or verify the audit log", logCmd},
		"version": {"version", "print the version", func(context.Context, []string) error { fmt.Println("asiri", server.Version); return nil }},
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage(os.Stdout)
		return
	}
	c, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "asiri: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(exitUsage)
	}
	if err := c.run(ctx, os.Args[2:]); err != nil {
		var ue usageError
		if errors.As(err, &ue) || errors.Is(err, flag.ErrHelp) {
			if !errors.Is(err, flag.ErrHelp) {
				fmt.Fprintln(os.Stderr, "asiri:", err)
			}
			fmt.Fprintln(os.Stderr, "usage: asiri", c.usage)
			os.Exit(exitUsage)
		}
		var de *domain.Error
		if errors.As(err, &de) {
			fmt.Fprintf(os.Stderr, "asiri: %s (%s)\n", de.Msg, de.Code)
		} else {
			fmt.Fprintln(os.Stderr, "asiri:", err)
		}
		os.Exit(exitAsiri)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, "asiri: let agents use secrets without seeing them\n\nusage:\n")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  asiri %-8s %s\n", n, commands[n].help)
	}
	fmt.Fprint(w, "\nprofiles: --profile NAME or ASIRI_PROFILE (default owner); config in $ASIRI_HOME (~/.config/asiri)\n")
}

// parse parses flags that may come before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// readHidden reads a line from the terminal without echo. It uses /dev/tty,
// not stdin, so it works even when stdin is piped.
func readHidden(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no terminal to read from; pass the value on stdin with --stdin")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return b, err
}

func readStdin() ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 64<<10 {
		clear(b)
		return nil, errors.New("value is larger than 64 KiB")
	}
	// Drop one trailing newline, as `echo` and here-strings add it.
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
