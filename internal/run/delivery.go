package run

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gingered-cat/asiri/internal/domain"
)

// Delivery is how one secret reaches the child process.
type Delivery interface {
	Ref() domain.Ref
	// Apply sets up cmd before it starts. cleanup runs after it exits.
	Apply(cmd *exec.Cmd, s domain.Secret) (cleanup func(), err error)
	String() string
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func parseNameRef(kind, s string) (string, domain.Ref, error) {
	name, ref, ok := strings.Cut(s, "=")
	if !ok || !envName.MatchString(name) {
		return "", domain.Ref{}, fmt.Errorf("--%s %q: want NAME=asiri://vault/name", kind, s)
	}
	r, err := domain.ParseRef(ref)
	return name, r, err
}

// Env sets an environment variable. Other processes running as the same
// user can read a process's environment (ps eww on macOS), so prefer Stdin
// or File when the program supports them.
type Env struct {
	Name string
	R    domain.Ref
}

func ParseEnv(s string) (Env, error) {
	name, r, err := parseNameRef("env", s)
	return Env{Name: name, R: r}, err
}

func (e Env) Ref() domain.Ref { return e.R }
func (e Env) String() string  { return "env " + e.Name }

func (e Env) Apply(cmd *exec.Cmd, s domain.Secret) (func(), error) {
	if bytes.IndexByte(s.Reveal(), 0) >= 0 {
		return nil, fmt.Errorf("%s contains a NUL byte and can't go in an environment variable; use --stdin or --file", e.R)
	}
	cmd.Env = append(cmd.Env, e.Name+"="+string(s.Reveal()))
	return func() {}, nil
}

// Stdin writes the value to the child's standard input, then closes it.
type Stdin struct{ R domain.Ref }

func ParseStdin(s string) (Stdin, error) {
	r, err := domain.ParseRef(s)
	return Stdin{R: r}, err
}

func (d Stdin) Ref() domain.Ref { return d.R }
func (d Stdin) String() string  { return "stdin" }

func (d Stdin) Apply(cmd *exec.Cmd, s domain.Secret) (func(), error) {
	b := append([]byte(nil), s.Reveal()...)
	cmd.Stdin = bytes.NewReader(b)
	return func() { clear(b) }, nil
}

// File puts the value in a named pipe and sets NAME to its path. The value
// is never written to disk, and the pipe can be read once. It lives in a
// fresh 0700 directory that is removed when the child exits.
type File struct {
	Name string
	R    domain.Ref
}

func ParseFile(s string) (File, error) {
	name, r, err := parseNameRef("file", s)
	return File{Name: name, R: r}, err
}

func (f File) Ref() domain.Ref { return f.R }
func (f File) String() string  { return "file " + f.Name }
