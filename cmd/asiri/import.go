package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/importer"
)

// asiri import FILE: read an Apple Passwords or Google Password Manager
// export, store it, then shred the file.
func importCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	profile := profileFlag(fs)
	vaultName := fs.String("vault", "", "vault to import into (default: apple or google)")
	dryRun := fs.Bool("dry-run", false, "show what would be imported, store nothing, keep the file")
	keep := fs.Bool("keep", false, "don't delete the export file afterwards")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"want the exported CSV file, e.g. asiri import ~/Downloads/Passwords.csv"}
	}
	path := pos[0]
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	src, entries, err := importer.Parse(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	v := string(src)
	if *vaultName != "" {
		v = *vaultName
	}
	if _, err := domain.ParseRef(v + "/x"); err != nil {
		return usageError{fmt.Sprintf("vault name %q: use letters, digits, '.', '_' or '-'", v)}
	}
	withPW, withTOTP := 0, 0
	for _, e := range entries {
		if e.Password != "" {
			withPW++
		}
		if e.TOTP != "" {
			withTOTP++
		}
	}
	fmt.Printf("%s export: %d logins (%d with passwords, %d with one-time codes) → vault %q\n", src, len(entries), withPW, withTOTP, v)
	if *dryRun {
		for _, e := range entries {
			fmt.Printf("  asiri://%s/%s\n", v, e.Name)
		}
		fmt.Println("dry run: nothing stored, file kept")
		return nil
	}

	c, _, err := connect(*profile)
	if err != nil {
		return err
	}
	res, err := c.Import(ctx, api.ImportRequest{Vault: v, Source: string(src), Entries: entries})
	for i := range entries { // best effort: drop the plaintext copies
		entries[i] = importer.Entry{}
	}
	if err != nil {
		return err
	}
	fmt.Printf("imported: %d new, %d updated, %d unchanged\n", res.Created, res.Updated, res.Unchanged)
	fmt.Printf("refs look like asiri://%s/<site>/password (also /username, /url, /totp, /notes); see them with: asiri ls %s/\n", v, v)
	fmt.Printf("no program may use them yet; allow one per login, e.g.: asiri policy %s/<site>/password --bins psql\n", v)

	home, _ := os.UserHomeDir()
	synced := importer.SyncedFolder(path, home)
	if *keep {
		fmt.Printf("kept %s (--keep). It holds every password in plain text: delete it soon.\n", path)
	} else if err := importer.Shred(path); err != nil {
		fmt.Fprintf(os.Stderr, "asiri: couldn't delete %s: %v\nDelete it yourself: it holds every password in plain text.\n", path, err)
	} else {
		fmt.Printf("overwrote and deleted %s\n", path)
	}
	if synced != "" {
		fmt.Fprintf(os.Stderr, "warning: %s was in a folder synced by %s, so it has probably been uploaded, and %s may keep old versions or a recently-deleted copy. Remove it there too.\n", path, synced, synced)
	}
	if importer.TimeMachineOn() {
		fmt.Fprintf(os.Stderr, "note: Time Machine is set up. If a backup ran while the file existed, the backup has a copy (tmutil listbackups).\n")
	}
	if !*keep {
		fmt.Fprintf(os.Stderr, "note: on SSDs and APFS, deleted data can linger until the space is reused; FileVault is what protects it.\n")
	}
	return nil
}
