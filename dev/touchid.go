package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// The Touch ID helper is Swift (macos/touchid/main.swift), because the
// Secure Enclave is only reachable through Apple's frameworks. It builds
// with the Command Line Tools' swiftc; nothing else is needed.

const helperSource = "macos/touchid/main.swift"

func binTask([]string) error {
	if err := goCmd("build", "-o", "bin/asiri", "./cmd/asiri"); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		return nil
	}
	if _, err := exec.LookPath("xcrun"); err != nil {
		fmt.Println("skipping bin/asiri-touchid: no xcrun (xcode-select --install)")
		return nil
	}
	return touchidTask([]string{"-o", "bin/asiri-touchid"})
}

// touchidTask builds the helper and runs every statement in
// internal/approvalkey/testdata/describe through it: the sentence the
// person reads must match approvalkey.Describe exactly.
func touchidTask(args []string) error {
	fs := flag.NewFlagSet("touchid", flag.ContinueOnError)
	out := fs.String("o", "bin/asiri-touchid", "output path")
	arch := fs.String("arch", "", "arm64 or amd64 (default: this Mac)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		return errors.New("the Touch ID helper builds on macOS only")
	}
	swiftArgs := []string{"swiftc", "-O", helperSource, "-o", *out}
	switch *arch {
	case "":
	case "arm64":
		swiftArgs = append(swiftArgs, "-target", "arm64-apple-macos13")
	case "amd64":
		swiftArgs = append(swiftArgs, "-target", "x86_64-apple-macos13")
	default:
		return fmt.Errorf("-arch %q: want arm64 or amd64", *arch)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := run(nil, "xcrun", swiftArgs...); err != nil {
		return err
	}
	if *arch != "" && *arch != map[string]string{"arm64": "arm64", "amd64": "amd64"}[runtime.GOARCH] {
		fmt.Printf("built %s for %s (not run: different architecture)\n", *out, *arch)
		return nil
	}
	cases, _ := filepath.Glob("internal/approvalkey/testdata/describe/*.stmt")
	if len(cases) == 0 {
		return errors.New("no describe test cases")
	}
	for _, c := range cases {
		stmt, err := os.ReadFile(c)
		if err != nil {
			return err
		}
		want, err := os.ReadFile(strings.TrimSuffix(c, ".stmt") + ".want")
		if err != nil {
			return err
		}
		cmd := exec.Command(*out, "describe")
		cmd.Stdin = bytes.NewReader(stmt)
		got, _ := cmd.Output() // "error" and exit 1 for bad statements
		if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
			return fmt.Errorf("%s: helper says %q, Go says %q", filepath.Base(c), strings.TrimSpace(string(got)), strings.TrimSpace(string(want)))
		}
	}
	fmt.Printf("built %s; its prompts match Go on %d statements\n", *out, len(cases))
	return nil
}
