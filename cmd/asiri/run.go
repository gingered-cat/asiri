package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/rexplug"
	"github.com/gingered-cat/asiri/internal/run"
)

// exitStatus ends asiri with a child's exit code, printing nothing.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func runCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profile := profileFlag(fs)
	var envs, files multi
	fs.Var(&envs, "env", "NAME=REF: set env var NAME to the secret (repeatable)")
	fs.Var(&files, "file", "NAME=REF: put the secret in a one-time pipe, NAME holds its path (repeatable)")
	stdin := fs.String("stdin", "", "REF: write the secret to the program's stdin")
	reason := fs.String("reason", "", "why; shown to the person approving")
	// Flags stop at the program name, so its own flags pass through.
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
		return usageError{"missing the program to run"}
	}
	var ds []run.Delivery
	for _, e := range envs {
		d, err := run.ParseEnv(e)
		if err != nil {
			return usageError{err.Error()}
		}
		ds = append(ds, d)
	}
	for _, f := range files {
		d, err := run.ParseFile(f)
		if err != nil {
			return usageError{err.Error()}
		}
		ds = append(ds, d)
	}
	if *stdin != "" {
		d, err := run.ParseStdin(*stdin)
		if err != nil {
			return usageError{err.Error()}
		}
		ds = append(ds, d)
	}
	run.CleanStale()
	c, _, err := connect(*profile)
	if err != nil {
		return &run.ExitError{Code: run.ExitFailed, Err: err}
	}
	// Rex first, then this terminal (owners only: agents can't approve),
	// then "run asiri approve ID".
	chain := approve.Chain{approve.Rex{Server: os.Getenv("ASIRI_REX_SERVER"), Out: os.Stderr}}
	if who, err := c.WhoAmI(ctx); err == nil && who.Role == domain.RoleOwner {
		chain = append(chain, approve.TTY{})
	}
	chain = append(chain, approve.Wait{API: c, Out: os.Stderr})
	r := &run.Runner{API: c, Approver: chain, Notes: os.Stderr}
	code, err := r.Run(ctx, run.Spec{Bin: rest[0], Args: rest[1:], Deliveries: ds, Reason: *reason,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		return err
	}
	return exitStatus(code)
}

func policyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	profile := profileFlag(fs)
	bins := fs.String("bins", "", "comma-separated programs that may receive the secret (names or absolute paths)")
	maxGrant := fs.String("max-grant", "", "longest approval allowed: once, 15m or 1h")
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
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	it, err := lookup(ctx, c, ref)
	if err != nil {
		return err
	}
	if set["bins"] || set["max-grant"] {
		b, mg := it.Policy.Bins, it.Policy.MaxGrant
		if set["bins"] {
			b = splitList(*bins)
		}
		if set["max-grant"] {
			mg = *maxGrant
		}
		if it, err = c.SetPolicy(ctx, ref, b, mg); err != nil {
			return err
		}
		for _, x := range b {
			if domain.IsInterpreter(x) {
				fmt.Fprintf(os.Stderr, "warning: %s can run any code, so it can print or send %s anywhere\n", x, ref)
			}
		}
	}
	printPolicy(it)
	return nil
}

func printPolicy(it domain.Item) {
	bins := "nothing yet (asiri policy " + it.Ref.String() + " --bins gh)"
	if len(it.Policy.Bins) > 0 {
		bins = strings.Join(it.Policy.Bins, ", ")
	}
	fmt.Printf("%s\n  may be used by  %s\n  longest grant   %s\n", it.Ref, bins, it.Policy.MaxGrant)
}

func lookup(ctx context.Context, c interface {
	ListItems(context.Context, string) ([]domain.Item, error)
}, ref domain.Ref) (domain.Item, error) {
	items, err := c.ListItems(ctx, ref.Vault+"/"+ref.Name+"/"+ref.Field)
	if err != nil {
		return domain.Item{}, err
	}
	for _, it := range items {
		if it.Ref == ref {
			return it, nil
		}
	}
	return domain.Item{}, domain.Errorf(domain.CodeNotFound, "%s does not exist", ref)
}

func approveCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	profile := profileFlag(fs)
	dur := fs.String("for", "once", "once, 15m or 1h")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		d := domain.Decision(*dur)
		if d == domain.DecideDeny || !d.Valid() {
			return usageError{"--for must be once, 15m or 1h"}
		}
		return decideOne(ctx, c, domain.RequestID(pos[0]), d)
	}
	if len(pos) > 1 {
		return usageError{"at most one request id"}
	}
	pending, err := c.PendingRequests(ctx)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("nothing is waiting for approval")
		return nil
	}
	for _, rq := range pending {
		ans, err := approve.TTY{}.Approve(ctx, approve.Prompt{RequestID: rq.ID, Title: rq.Title, Detail: rq.Detail, ExpiresAt: rq.ExpiresAt})
		if errors.Is(err, approve.ErrUnavailable) {
			for _, rq := range pending {
				fmt.Printf("%s  %s\n    %s\n", rq.ID, rq.Title, rq.Detail)
			}
			fmt.Println("\napprove with: asiri approve ID [--for 15m]   deny with: asiri deny ID")
			return nil
		}
		if err != nil {
			return err
		}
		if err := decide(ctx, c, rq.ID, ans.Decision, domain.MethodTTY); err != nil {
			return err
		}
	}
	return nil
}

func denyCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deny", flag.ContinueOnError)
	profile := profileFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"want one request id"}
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	return decideOne(ctx, c, domain.RequestID(pos[0]), domain.DecideDeny)
}

type decider interface {
	Decide(context.Context, domain.RequestID, domain.Decision, domain.Method) (domain.Request, error)
}

func decideOne(ctx context.Context, c decider, id domain.RequestID, d domain.Decision) error {
	return decide(ctx, c, id, d, domain.MethodCLI)
}

func decide(ctx context.Context, c decider, id domain.RequestID, d domain.Decision, m domain.Method) error {
	rq, err := c.Decide(ctx, id, d, m)
	if err != nil {
		return err
	}
	switch rq.Status {
	case domain.StatusApproved:
		fmt.Printf("approved %s for %s (%s)\n", rq.Ref, rq.ClientName, rq.Decision)
	default:
		fmt.Printf("%s %s for %s\n", rq.Status, rq.Ref, rq.ClientName)
	}
	return nil
}

func grantsCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("grants", flag.ContinueOnError)
	profile := profileFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	gs, err := c.Grants(ctx)
	if err != nil {
		return err
	}
	if len(gs) == 0 {
		fmt.Println("no active grants")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLIENT\tREF\tPROGRAM\tGRANT\tLEFT")
	for _, g := range gs {
		left := time.Until(g.ExpiresAt).Round(time.Second).String()
		if g.UsesLeft != nil {
			left = fmt.Sprintf("%d use, %s", *g.UsesLeft, left)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.ClientName, g.Ref, baseName(g.BinPath), g.Decision, left)
	}
	return tw.Flush()
}

func revokeCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	profile := profileFlag(fs)
	all := fs.Bool("all", false, "revoke every grant and deny every pending request")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *all == (len(pos) == 1) || len(pos) > 1 {
		return usageError{"give a grant id, or --all"}
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	if *all {
		n, err := c.RevokeAll(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("revoked %d grants; pending requests denied\n", n)
		return nil
	}
	if err := c.RevokeGrant(ctx, domain.GrantID(pos[0])); err != nil {
		return err
	}
	fmt.Println("revoked", pos[0])
	return nil
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pendingCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pending", flag.ContinueOnError)
	profile := profileFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON (used by the Rex plugin)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	rs, err := c.PendingRequests(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(rs)
	}
	if len(rs) == 0 {
		fmt.Println("nothing is waiting for approval")
		return nil
	}
	for _, rq := range rs {
		fmt.Printf("%s  %s\n    %s\n", rq.ID, rq.Title, rq.Detail)
	}
	return nil
}

func rexCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{"missing subcommand: install, uninstall or status"}
	}
	fs := flag.NewFlagSet("rex", flag.ContinueOnError)
	profile := fs.String("profile", client.DefaultProfile, "the owner profile the plugin approves with")
	sub := args[0]
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	switch sub {
	case "install":
		bin, err := installedBinary()
		if err != nil {
			return err
		}
		c, _, err := connect(*profile)
		if err != nil {
			return fmt.Errorf("the Rex plugin approves as profile %q: %w", *profile, err)
		}
		if who, err := c.WhoAmI(ctx); err != nil {
			return err
		} else if who.Role != domain.RoleOwner {
			return fmt.Errorf("profile %q is %s; the Rex plugin needs an owner profile to approve with", *profile, who.Role)
		}
		res, err := rexplug.Install(ctx, rexplug.SystemRex, bin, *profile)
		if err != nil {
			return err
		}
		fmt.Printf("asiri is in Rex's command palette. Press cmd+shift+p and type asiri.\n")
		fmt.Printf("  Asiri: Approve Waiting Requests…   answer agents' requests (they also pop up by themselves)\n")
		fmt.Printf("  Asiri: Revoke Everything            the kill switch\n")
		fmt.Printf("  Asiri: Lock the Vault\n")
		fmt.Printf("plugin  %s\nconfig  %s (asiri's block only)\n", res.Plugin, res.Config)
		if !res.Reloaded {
			fmt.Printf("Rex isn't running, so it picks this up when it starts (%v)\n", res.ReloadErr)
		}
		return nil
	case "uninstall":
		res, err := rexplug.Uninstall(ctx, rexplug.SystemRex)
		if err != nil {
			return err
		}
		fmt.Printf("removed asiri from Rex (%s)\n", res.Config)
		return nil
	case "status":
		ok, config, err := rexplug.Installed()
		if err != nil {
			return err
		}
		if ok {
			fmt.Printf("installed in %s\n", config)
		} else {
			fmt.Printf("not installed; run: asiri rex install\n")
		}
		return nil
	}
	return usageError{fmt.Sprintf("unknown rex subcommand %q", sub)}
}

// installedBinary is this asiri's real path. The plugin runs it later, so a
// `go run` build in a temp directory won't do.
func installedBinary() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return "", err
	}
	if strings.Contains(bin, "go-build") {
		return "", errors.New("this asiri was started with `go run`; build or install it first (go run ./dev bin)")
	}
	return bin, nil
}
