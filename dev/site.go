package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// siteTask deploys a git revision's site/ (default main) to the Cloudflare
// Pages project "asiri" with wrangler. It exports the revision with git
// archive, so local edits and untracked files are never uploaded. The
// GitHub workflow .github/workflows/site.yml does the same on every push.
func siteTask(args []string) error {
	rev := "main"
	if len(args) == 1 {
		rev = args[0]
	} else if len(args) > 1 {
		return fmt.Errorf("usage: go run ./dev site [REVISION]")
	}
	out, err := exec.Command("git", "rev-parse", "--verify", rev+"^{commit}").Output()
	if err != nil {
		return fmt.Errorf("no git revision %q", rev)
	}
	sha := strings.TrimSpace(string(out))
	dir, err := os.MkdirTemp("", "asiri-site-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	archive := exec.Command("git", "archive", "--format=tar", sha, "site")
	untar := exec.Command("tar", "-x", "-C", dir)
	if untar.Stdin, err = archive.StdoutPipe(); err != nil {
		return err
	}
	if err := untar.Start(); err != nil {
		return err
	}
	if err := archive.Run(); err != nil {
		return fmt.Errorf("git archive %s site: %w", rev, err)
	}
	if err := untar.Wait(); err != nil {
		return err
	}
	fmt.Printf("deploying site/ from %s (%s)\n", rev, sha[:12])
	deploy := exec.Command("npx", "--yes", "wrangler", "pages", "deploy", "site",
		"--project-name", "asiri", "--branch", "main",
		"--commit-hash", sha, "--commit-message", rev+" "+sha[:12])
	deploy.Dir = dir
	deploy.Stdout, deploy.Stderr = os.Stdout, os.Stderr
	return deploy.Run()
}
