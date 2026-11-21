// Command dev is Asiri's task runner, in Go so the project needs nothing but
// the go command.
//
//	go run ./dev          # list tasks
//	go run ./dev ci       # everything CI runs
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type task struct {
	help string
	run  func(args []string) error
}

var tasks map[string]task

func init() {
	tasks = map[string]task{
		"docs":  {"build the static docs site (--check to detect stale output)", docsTask},
		"site":  {"deploy a revision's site/ (default main) to Cloudflare Pages with wrangler", siteTask},
		"fmt":   {"fail if any file needs gofmt (-w to rewrite)", fmtTask},
		"vet":   {"go vet ./...", func([]string) error { return goCmd("vet", "./...") }},
		"test":  {"go test -race ./...", testTask},
		"build": {"cross-compile for linux and darwin, amd64 and arm64, without cgo", buildTask},
		"ci":    {"fmt, vet, test, build", ciTask},
		"bin":   {"build ./bin/asiri for this machine", func([]string) error { return goCmd("build", "-o", "bin/asiri", "./cmd/asiri") }},
		"image": {"docker build -t ghcr.io/gingered-cat/asiri:dev .", func([]string) error {
			return run(nil, "docker", "build", "-t", "ghcr.io/gingered-cat/asiri:dev", ".")
		}},
	}
}

var targets = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"}

func main() {
	if err := chdirRoot(); err != nil {
		fail(err)
	}
	if len(os.Args) < 2 {
		usage()
		return
	}
	t, ok := tasks[os.Args[1]]
	if !ok {
		usage()
		fail(fmt.Errorf("unknown task %q", os.Args[1]))
	}
	if err := t.run(os.Args[2:]); err != nil {
		fail(err)
	}
}

func usage() {
	names := make([]string, 0, len(tasks))
	for n := range tasks {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println("usage: go run ./dev <task>")
	for _, n := range names {
		fmt.Printf("  %-6s %s\n", n, tasks[n].help)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "dev:", err)
	os.Exit(1)
}

func chdirRoot() error {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return err
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return errors.New("not inside the asiri module")
	}
	return os.Chdir(filepath.Dir(gomod))
}

func step(name string) { fmt.Printf("\n▸ %s\n", name) }

func run(env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func goCmd(args ...string) error { return run(nil, "go", args...) }

func fmtTask(args []string) error {
	if len(args) > 0 && args[0] == "-w" {
		return run(nil, "gofmt", "-w", ".")
	}
	out, err := exec.Command("gofmt", "-l", ".").Output()
	if err != nil {
		return err
	}
	if bad := strings.Fields(string(out)); len(bad) > 0 {
		return fmt.Errorf("gofmt needed (go run ./dev fmt -w):\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

func testTask([]string) error {
	args := []string{"test", "-count=1"}
	if out, err := exec.Command("go", "env", "CGO_ENABLED").Output(); err == nil &&
		strings.TrimSpace(string(out)) == "1" && runtime.GOOS != "windows" {
		args = append(args, "-race")
	}
	return goCmd(append(args, "./...")...)
}

func buildTask([]string) error {
	for _, t := range targets {
		goos, goarch, _ := strings.Cut(t, "/")
		fmt.Printf("  %s\n", t)
		if err := run([]string{"CGO_ENABLED=0", "GOOS=" + goos, "GOARCH=" + goarch},
			"go", "build", "-o", os.DevNull, "./cmd/..."); err != nil {
			return err
		}
	}
	return nil
}

func ciTask([]string) error {
	for _, s := range []string{"fmt", "vet", "test", "build"} {
		step(s)
		if err := tasks[s].run(nil); err != nil {
			return err
		}
	}
	fmt.Println("\nci ok")
	return nil
}
