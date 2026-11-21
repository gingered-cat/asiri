package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/run"
	"github.com/gingered-cat/asiri/internal/sshagent"
)

// approvers is the chain for this profile: Rex, then the terminal (owners
// only, since agents can't approve), then "run asiri approve ID".
func approvers(ctx context.Context, c *client.Client) approve.Chain {
	chain := approve.Chain{approve.Rex{Server: os.Getenv("ASIRI_REX_SERVER"), Out: os.Stderr}}
	if who, err := c.WhoAmI(ctx); err == nil && who.Role == domain.RoleOwner {
		chain = append(chain, approve.TTY{})
	}
	return append(chain, approve.Wait{API: c, Out: os.Stderr})
}

func newAgent(ctx context.Context, c *client.Client, reason string) *sshagent.Agent {
	// x/crypto's agent server logs failures with the standard logger; asiri
	// already says why it refused, in plain words.
	log.SetOutput(io.Discard)
	cwd, _ := os.Getwd()
	r := &run.Runner{API: c, Approver: approvers(ctx, c), Notes: os.Stderr}
	return &sshagent.Agent{API: c, Granter: r, Reason: reason, Cwd: cwd, Log: os.Stderr}
}

// asiri ssh [--reason R] [--] SSH-ARGS...: ssh with asiri's agent only for
// this connection. The key stays in the server; ssh gets signatures.
func sshCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profile := profileFlag(fs)
	reason := fs.String("reason", "", "why; shown to the person approving")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return usageError{"missing the ssh destination"}
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return &run.ExitError{Code: run.ExitNotFound, Err: errors.New("ssh: not found")}
	}
	c, _, err := connect(*profile)
	if err != nil {
		return &run.ExitError{Code: run.ExitFailed, Err: err}
	}
	dir, err := os.MkdirTemp("", "asiri-ssh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "agent.sock")
	ln, err := sshagent.Listen(sock)
	if err != nil {
		return err
	}
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	go newAgent(actx, c, *reason).Serve(actx, ln)

	cmd := exec.Command(sshBin, append([]string{"-o", "IdentityAgent=" + sock}, rest...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if err := cmd.Start(); err != nil {
		return &run.ExitError{Code: run.ExitFailed, Err: err}
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigs)
	close(sigs)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitStatus(ee.ExitCode())
	}
	if err != nil {
		return &run.ExitError{Code: run.ExitFailed, Err: err}
	}
	return exitStatus(0)
}

// asiri ssh-agent: a long-running agent for any ssh, git or rsync.
func sshAgentCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh-agent", flag.ContinueOnError)
	profile := profileFlag(fs)
	home, _ := os.UserHomeDir()
	sock := fs.String("socket", filepath.Join(home, ".asiri", "agent.sock"), "socket path")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	ln, err := sshagent.Listen(*sock)
	if err != nil {
		return err
	}
	defer os.Remove(*sock)
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", *sock)
	fmt.Fprintf(os.Stderr, "asiri: ssh agent on %s; approvals go to Rex (or `asiri approve`). Ctrl-C stops it.\n", *sock)
	return newAgent(ctx, c, "").Serve(ctx, ln)
}

// asiri pubkey REF: the public key, for authorized_keys.
func pubkeyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	profile := profileFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"want one reference"}
	}
	ref, err := domain.ParseRef(pos[0])
	if err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	it, err := lookup(ctx, c, ref)
	if err != nil {
		return err
	}
	if it.PublicKey == "" {
		return fmt.Errorf("%s is not an SSH key", ref)
	}
	fmt.Println(it.PublicKey)
	return nil
}

var literalHost = regexp.MustCompile(`^([^=]+=)?SHA256:[A-Za-z0-9+/]{43}$`)

// resolveSSHHosts turns host names into "name=SHA256:…" entries from the
// user's known_hosts, after ssh -G applies ~/.ssh/config (HostName, Port,
// HostKeyAlias, UserKnownHostsFile). Literal "name=SHA256:…" entries pass.
func resolveSSHHosts(ctx context.Context, hosts []string) ([]string, error) {
	var out []string
	for _, h := range hosts {
		if literalHost.MatchString(h) {
			out = append(out, h)
			continue
		}
		fps, err := hostKeys(ctx, h)
		if err != nil {
			return nil, err
		}
		for _, fp := range fps {
			out = append(out, h+"="+fp)
		}
	}
	return out, nil
}

func hostKeys(ctx context.Context, host string) ([]string, error) {
	cfg, err := exec.CommandContext(ctx, "ssh", "-G", host).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G %s: %w", host, err)
	}
	opt := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(cfg))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		if _, seen := opt[k]; !seen {
			opt[k] = v
		}
	}
	name := opt["hostname"]
	if a := opt["hostkeyalias"]; a != "" && a != "none" {
		name = a
	}
	if p := opt["port"]; p != "" && p != "22" {
		name = "[" + name + "]:" + p
	}
	var files []string
	for _, f := range strings.Fields(opt["userknownhostsfile"]) {
		if strings.HasPrefix(f, "~/") {
			home, _ := os.UserHomeDir()
			f = filepath.Join(home, f[2:])
		}
		files = append(files, f)
	}
	seen := map[string]bool{}
	var fps []string
	for _, f := range files {
		out, err := exec.CommandContext(ctx, "ssh-keygen", "-F", name, "-f", f).Output()
		if err != nil {
			continue // not found in this file
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if fields[0] == "@cert-authority" || fields[0] == "@revoked" {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
			if err != nil {
				continue
			}
			if fp := ssh.FingerprintSHA256(pub); !seen[fp] {
				seen[fp] = true
				fps = append(fps, fp)
			}
		}
	}
	if len(fps) == 0 {
		return nil, fmt.Errorf("%s (%s) isn't in known_hosts; connect once with ssh to check its host key, or pass %s=SHA256:…", host, name, host)
	}
	return fps, nil
}
