package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/touchid"
)

func profileFlag(fs *flag.FlagSet) *string {
	return fs.String("profile", "", "profile to use (default $ASIRI_PROFILE or owner)")
}

func connect(profile string) (*client.Client, *client.Profile, error) {
	p, err := client.LoadProfile(client.ProfileName(profile))
	if err != nil {
		return nil, nil, err
	}
	c, err := client.New(p)
	if err != nil {
		return nil, nil, err
	}
	// On a Mac with an approval key, allow decisions get signed (Touch ID).
	if k := touchid.ForProfile(p); k != nil {
		c.Signer = k
	}
	return c, p, nil
}

func pairCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	profile := profileFlag(fs)
	server := fs.String("server", envOr("ASIRI_SERVER", "https://127.0.0.1:"+api.DefaultPort), "server URL")
	code := fs.String("code", "", "pairing code from `asiri server pair-code` or `asiri clients add`")
	force := fs.Bool("force", false, "replace an existing profile")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *code == "" {
		return usageError{"--code is required"}
	}
	p, resp, err := client.Pair(ctx, *server, *code, client.ProfileName(*profile), *force)
	if err != nil {
		return err
	}
	fmt.Printf("paired as %q (%s) with %s\nprofile: %s\n", resp.Name, resp.Role, p.Server, p.Dir)
	if p.Name != client.DefaultProfile {
		fmt.Printf("use it with --profile %s or ASIRI_PROFILE=%s\n", p.Name, p.Name)
	}
	return nil
}

func addCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	profile := profileFlag(fs)
	kind := fs.String("kind", "", "token, password, ssh_key, login or note (default: token, or the existing kind)")
	stdin := fs.Bool("stdin", false, "read the value from stdin instead of the terminal")
	generate := fs.Bool("ssh-generate", false, "make a new Ed25519 SSH key inside the server and print its public key")
	bins := fs.String("bins", "", "comma-separated programs that may receive it (same as asiri policy --bins)")
	sshHosts := fs.String("ssh-hosts", "", "SSH keys: comma-separated hosts it may sign in to (same as asiri policy --ssh-hosts)")
	maxGrant := fs.String("max-grant", "", "longest approval allowed: once, 15m or 1h")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"want exactly one reference, e.g. asiri add dev/github"}
	}
	ref, err := domain.ParseRef(pos[0])
	if err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	var it domain.Item
	if *generate {
		if it, err = c.GenerateSSHKey(ctx, ref); err != nil {
			return err
		}
		fmt.Printf("made %s (ssh key, version %d); the private key stays in the asiri server\n", it.Ref, it.Version)
	} else {
		var b []byte
		if *stdin {
			b, err = readStdin()
		} else {
			b, err = readHidden(fmt.Sprintf("value for %s (hidden): ", ref))
		}
		if err != nil {
			return err
		}
		sec := domain.NewSecret(b)
		defer sec.Zero()
		if sec.Len() == 0 {
			return fmt.Errorf("empty value; nothing stored")
		}
		if it, err = c.PutItem(ctx, ref, domain.Kind(*kind), sec); err != nil {
			return err
		}
		fmt.Printf("stored %s (%s, version %d)\n", it.Ref, it.Kind, it.Version)
	}
	if *bins != "" || *maxGrant != "" || *sshHosts != "" {
		p := it.Policy
		if *bins != "" {
			p.Bins = splitList(*bins)
		}
		if *maxGrant != "" {
			p.MaxGrant = *maxGrant
		}
		if *sshHosts != "" {
			if p.SSHHosts, err = resolveSSHHosts(ctx, splitList(*sshHosts)); err != nil {
				return err
			}
		}
		if it, err = c.SetPolicy(ctx, ref, p); err != nil {
			return err
		}
	}
	switch {
	case it.Kind == domain.KindSSHKey:
		fmt.Printf("public key (put it in the host's ~/.ssh/authorized_keys):\n\n  %s\n\n", it.PublicKey)
		if len(it.Policy.SSHHosts) == 0 {
			fmt.Printf("no host may use it yet; allow one with: asiri policy %s --ssh-hosts HOST\n", it.Ref)
		} else {
			fmt.Printf("may sign in to %s\n", strings.Join(it.Policy.SSHHosts, ", "))
		}
	case len(it.Policy.Bins) == 0:
		fmt.Printf("no program may use it yet; allow one with: asiri policy %s --bins gh\n", it.Ref)
	default:
		fmt.Printf("may be used by %s\n", strings.Join(it.Policy.Bins, ", "))
	}
	return nil
}

func lsCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	profile := profileFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	items, err := c.ListItems(ctx, strings.Join(pos, " "))
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(items)
	}
	if len(items) == 0 {
		fmt.Println("no secrets yet; add one with: asiri add dev/github")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REF\tKIND\tVER\tPROGRAMS\tUPDATED")
	for _, it := range items {
		bins := strings.Join(it.Policy.Bins, ",")
		if it.Kind == domain.KindSSHKey {
			var names []string
			for _, h := range it.Policy.SSHHosts {
				n, _, _ := strings.Cut(h, "=")
				names = append(names, "ssh:"+n)
			}
			bins = strings.Join(names, ",")
		}
		if bins == "" {
			bins = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", it.Ref, it.Kind, it.Version, bins, it.UpdatedAt.Local().Format("2006-01-02 15:04"))
	}
	return tw.Flush()
}

func statusCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	profile := profileFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, p, err := connect(*profile)
	if err != nil {
		return err
	}
	h, err := c.Health(ctx)
	if err != nil {
		return err
	}
	who, err := c.WhoAmI(ctx)
	if err != nil {
		return err
	}
	state := "unlocked"
	if h.Sealed {
		state = "locked (run asiri unlock)"
	}
	fmt.Printf("profile  %s as %q (%s)\nserver   %s · %s · %s\n", p.Name, who.Name, who.Role, p.Server, h.Version, state)
	return nil
}

func unlockCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	profile := profileFlag(fs)
	keyFileMode := fs.Bool("key-file", false, "tell the server to re-read its key file (no passphrase)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	var pass []byte
	if !*keyFileMode {
		if pass, err = readHidden("vault passphrase (empty for key-file mode): "); err != nil {
			return err
		}
		defer clear(pass)
	}
	h, err := c.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	if !h.Sealed {
		fmt.Println("unlocked")
	}
	return nil
}

func lockCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	profile := profileFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	if _, err := c.Lock(ctx); err != nil {
		return err
	}
	fmt.Println("locked")
	return nil
}

func clientsCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{"missing subcommand: add, ls or revoke"}
	}
	fs := flag.NewFlagSet("clients", flag.ContinueOnError)
	profile := profileFlag(fs)
	role := fs.String("role", "agent", "owner or agent")
	replace := fs.Bool("replace", false, "pair again even if the client exists")
	sub := args[0]
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	c, p, err := connect(*profile)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		if len(pos) != 1 {
			return usageError{"want a client name, e.g. asiri clients add claude"}
		}
		pc, err := c.CreateClient(ctx, pos[0], domain.Role(*role), *replace)
		if err != nil {
			return err
		}
		printPairCode(pc, p.Server)
		return nil
	case "ls":
		cs, err := c.ListClients(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tROLE\tPAIRED\tSTATE")
		for _, cl := range cs {
			state := "active"
			if cl.RevokedAt != nil {
				state = "revoked " + cl.RevokedAt.Local().Format("2006-01-02")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", cl.Name, cl.Role, cl.CreatedAt.Local().Format("2006-01-02 15:04"), state)
		}
		return tw.Flush()
	case "revoke":
		if len(pos) != 1 {
			return usageError{"want a client name"}
		}
		if err := c.RevokeClient(ctx, pos[0]); err != nil {
			return err
		}
		fmt.Printf("revoked %q\n", pos[0])
		return nil
	}
	return usageError{fmt.Sprintf("unknown clients subcommand %q", sub)}
}

func logCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	profile := profileFlag(fs)
	since := fs.Int64("since", 0, "only events after this sequence number")
	limit := fs.Int("limit", 100, "at most this many events")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	if len(pos) == 1 && pos[0] == "verify" {
		n, err := c.VerifyAudit(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("ok: %d events, chain intact\n", n)
		return nil
	}
	if len(pos) > 0 {
		return usageError{"unexpected arguments"}
	}
	evs, err := c.Audit(ctx, *since, *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(evs)
	}
	names := map[domain.ClientID]string{}
	if cs, err := c.ListClients(ctx); err == nil {
		for _, cl := range cs {
			names[cl.ID] = cl.Name
		}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME\tCLIENT\tEVENT\tDETAIL")
	for _, ev := range evs {
		who := names[ev.ClientID]
		if who == "" {
			who = "server"
		}
		var detail []string
		for _, k := range []string{"ref", "bin", "decision", "method", "asked", "hits", "code", "version", "kind", "name", "role", "mode", "bins", "max_grant", "reason", "grants", "requests", "source", "vault", "logins", "created", "updated", "unchanged"} {
			if v, ok := ev.Detail[k]; ok {
				detail = append(detail, k+"="+v)
			}
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", ev.Seq, ev.TS.Local().Format("01-02 15:04:05"), who, ev.Event, strings.Join(detail, " "))
	}
	return tw.Flush()
}
