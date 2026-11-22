package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approvalkey"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/touchid"
)

// asiri touchid: make approvals need Touch ID (or the Mac's password).
func touchidCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{"missing subcommand: enroll or status"}
	}
	switch args[0] {
	case "enroll":
		return touchidEnroll(ctx, args[1:])
	case "status":
		return touchidStatus(ctx, args[1:])
	}
	return usageError{fmt.Sprintf("unknown touchid subcommand %q", args[0])}
}

func touchidEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("touchid enroll", flag.ContinueOnError)
	profile := profileFlag(fs)
	name := fs.String("name", "", "a name for this Mac's key (default: the host name)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, p, err := connect(*profile)
	if err != nil {
		return err
	}
	if who, err := c.WhoAmI(ctx); err != nil {
		return err
	} else if who.Role != domain.RoleOwner {
		return fmt.Errorf("profile %q is %s; enroll with the owner profile", p.Name, who.Role)
	}
	helper, err := touchid.FindHelper()
	if err != nil {
		return err
	}
	if err := touchid.Available(ctx, helper); err != nil {
		return err
	}
	if *name == "" {
		*name, _ = os.Hostname()
		*name = strings.TrimSuffix(*name, ".local")
	}

	// Reuse this profile's key if it has one, so enrolling again is safe.
	file := filepath.Join(p.Dir, touchid.KeyFileName)
	var key *touchid.Key
	if _, err := os.Stat(file); err == nil {
		key = &touchid.Key{Helper: helper, File: file}
	} else if errors.Is(err, iofs.ErrNotExist) {
		if key, err = touchid.Create(ctx, helper, file); err != nil {
			return err
		}
		fmt.Printf("created an approval key in this Mac's Secure Enclave (%s)\n", file)
	} else {
		return err
	}
	pub, err := key.PublicKey(ctx)
	if err != nil {
		return err
	}
	id := approvalkey.ID(pub)

	ch, err := c.EnrollChallenge(ctx, pub)
	if err != nil {
		return err
	}
	for _, k := range ch.KeyIDs {
		if k == id {
			fmt.Printf("key %s is already enrolled; approvals on %s need Touch ID\n", id, p.Server)
			return nil
		}
	}
	if ch.Required {
		return fmt.Errorf("another approval key is already enrolled (%s); to replace it, run `asiri server reset-approval-keys` where the server runs, then enroll again",
			strings.Join(ch.KeyIDs, ", "))
	}
	fmt.Println("confirm with Touch ID or your password…")
	proof, err := key.Sign(ctx, ch.Statement)
	if err != nil {
		return err
	}
	k, err := c.EnrollApprovalKey(ctx, api.EnrollApprovalKeyRequest{Name: *name, PublicKey: pub, Proof: proof})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled key %s (%s). From now on, allowing a request on %s needs Touch ID or your password; denying doesn't.\n",
		k.ID, k.Name, p.Server)
	return nil
}

func touchidStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("touchid status", flag.ContinueOnError)
	profile := profileFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	p, err := client.LoadProfile(client.ProfileName(*profile))
	if err != nil {
		return err
	}
	helper, herr := touchid.FindHelper()
	switch {
	case herr != nil:
		fmt.Printf("helper   %v\n", herr)
	case touchid.Available(ctx, helper) != nil:
		fmt.Printf("helper   %s (%v)\n", helper, touchid.Available(ctx, helper))
	default:
		fmt.Printf("helper   %s (Touch ID or password available)\n", helper)
	}
	localID := ""
	if k := touchid.ForProfile(p); k != nil {
		if localID, err = k.KeyID(ctx); err != nil {
			fmt.Printf("key      %s: %v\n", k.File, err)
		} else {
			fmt.Printf("key      %s (%s)\n", localID, k.File)
		}
	} else {
		fmt.Println("key      none for this profile; run `asiri touchid enroll`")
	}
	c, err := client.New(p)
	if err != nil {
		return err
	}
	keys, err := c.ApprovalKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Printf("server   %s: no approval key enrolled; an owner profile can approve without Touch ID\n", p.Server)
		return nil
	}
	fmt.Printf("server   %s: allowing a request needs Touch ID\n", p.Server)
	for _, k := range keys {
		mark := ""
		if k.ID == localID {
			mark = "  ← this Mac"
		}
		fmt.Printf("         %s  %s  enrolled %s%s\n", k.ID, k.Name, k.CreatedAt.Local().Format("2006-01-02 15:04"), mark)
	}
	return nil
}
