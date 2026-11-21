package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/rexplug"
	"github.com/gingered-cat/asiri/internal/server"
	"github.com/gingered-cat/asiri/internal/update"
)

// asiri update: replace this binary with the latest (or a given) release,
// verified against the release's checksums, then refresh the Rex plugin.
func updateCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only say whether an update is available")
	version := fs.String("version", "", "install this release instead of the latest, e.g. v0.1.0")
	force := fs.Bool("force", false, "replace a development build, or install an older release")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	src := update.Source{}
	current := server.Version
	target := *version
	if target == "" {
		var err error
		if target, err = src.Latest(ctx); err != nil {
			return err
		}
	}

	if *check {
		switch {
		case !update.IsRelease(current):
			fmt.Printf("asiri %s (development build); latest release is %s\n", current, target)
		case update.Newer(target, current):
			fmt.Printf("asiri %s; %s is available: run asiri update\n", current, target)
		default:
			fmt.Printf("asiri %s is up to date\n", current)
		}
		return nil
	}
	switch {
	case target == current && !*force:
		fmt.Printf("asiri %s is up to date\n", current)
		return nil
	case !update.IsRelease(current) && !*force:
		return fmt.Errorf("this asiri is a development build (%s); pass --force to replace it with %s", current, target)
	case update.IsRelease(current) && update.Newer(current, target) && !*force:
		return fmt.Errorf("%s is older than this asiri (%s); pass --force to downgrade", target, current)
	}

	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return err
	}
	if strings.Contains(bin, "go-build") {
		return errors.New("this asiri was started with `go run`; there is no installed binary to update")
	}
	fmt.Printf("downloading %s for %s\n", target, update.AssetName(target, src.GOOSOrRuntime(), src.GOARCHOrRuntime()))
	b, err := src.Fetch(ctx, target)
	if err != nil {
		return err
	}
	if err := update.Replace(bin, b); err != nil {
		return err
	}
	fmt.Printf("updated %s: %s → %s (checksum verified)\n", bin, current, target)

	// The Rex plugin is embedded in the binary: let the new binary rewrite it.
	if rexBin, profile, ok := rexplug.InstalledWith(); ok && sameFile(rexBin, bin) {
		out, err := exec.CommandContext(ctx, bin, "rex", "install", "--profile", profile).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "asiri: couldn't refresh the Rex plugin; run `asiri rex install --profile %s`: %s\n", profile, strings.TrimSpace(string(out)))
		} else {
			fmt.Println("refreshed the Rex plugin")
		}
	}

	// The server is a separate process (usually a container); say if it lags.
	if p, err := client.LoadProfile(client.ProfileName("")); err == nil {
		if c, err := client.New(p); err == nil {
			if h, err := c.Health(ctx); err == nil && h.Version != target {
				fmt.Printf("the server at %s is still %s; update it too: docker compose -f deploy/compose.yaml pull && docker compose -f deploy/compose.yaml up -d\n", p.Server, h.Version)
			}
		}
	}
	return nil
}

func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}
