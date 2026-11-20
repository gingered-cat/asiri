// Package client is the CLI side of the API: profiles, pairing and typed calls.
package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultProfile is used when neither --profile nor ASIRI_PROFILE is set.
const DefaultProfile = "owner"

// Profile is one paired identity:
//
//	$ASIRI_HOME/<name>/server       server URL
//	$ASIRI_HOME/<name>/ca.crt       pinned server CA
//	$ASIRI_HOME/<name>/client.crt   this profile's certificate
//	$ASIRI_HOME/<name>/client.key   its private key (0600)
type Profile struct {
	Name   string
	Dir    string
	Server string
}

// Home is $ASIRI_HOME, or ~/.config/asiri.
func Home() (string, error) {
	if h := os.Getenv("ASIRI_HOME"); h != "" {
		return h, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "asiri"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "asiri"), nil
}

// ProfileName picks flag, then $ASIRI_PROFILE, then "owner".
func ProfileName(flag string) string {
	if flag != "" {
		return flag
	}
	if e := os.Getenv("ASIRI_PROFILE"); e != "" {
		return e
	}
	return DefaultProfile
}

var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func profileDir(name string) (string, error) {
	if !profileName.MatchString(name) {
		return "", fmt.Errorf("profile name %q: use lowercase letters, digits, '.', '_' or '-'", name)
	}
	home, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, name), nil
}

// LoadProfile reads a paired profile.
func LoadProfile(name string) (*Profile, error) {
	dir, err := profileDir(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "server"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("profile %q is not paired; run `asiri pair --profile %s --code ...`", name, name)
	}
	if err != nil {
		return nil, err
	}
	return &Profile{Name: name, Dir: dir, Server: strings.TrimSpace(string(b))}, nil
}

func (p *Profile) file(name string) string { return filepath.Join(p.Dir, name) }

func (p *Profile) save(caPEM, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	for name, b := range map[string][]byte{
		"ca.crt": caPEM, "client.crt": certPEM, "client.key": keyPEM, "server": []byte(p.Server + "\n"),
	} {
		tmp := p.file(name + ".tmp")
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, p.file(name)); err != nil {
			return err
		}
	}
	return nil
}
