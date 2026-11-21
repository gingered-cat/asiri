// Package update replaces the asiri binary with a released one, after
// checking it against the release's published SHA-256 checksums.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Source says where releases come from. The zero value is GitHub.
type Source struct {
	API      string // e.g. https://api.github.com/repos/gingered-cat/asiri
	Download string // e.g. https://github.com/gingered-cat/asiri/releases/download
	HTTP     *http.Client
	GOOS     string
	GOARCH   string
}

const (
	defaultAPI      = "https://api.github.com/repos/gingered-cat/asiri"
	defaultDownload = "https://github.com/gingered-cat/asiri/releases/download"
	maxBinary       = 256 << 20
)

func (s Source) withDefaults() Source {
	if s.API == "" {
		s.API = defaultAPI
	}
	if s.Download == "" {
		s.Download = defaultDownload
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: 2 * time.Minute}
	}
	if s.GOOS == "" {
		s.GOOS = runtime.GOOS
	}
	if s.GOARCH == "" {
		s.GOARCH = runtime.GOARCH
	}
	return s
}

func (s Source) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "asiri-update")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return b, nil
}

var errNotFound = errors.New("not found")

// Latest returns the tag of the newest published release.
func (s Source) Latest(ctx context.Context) (string, error) {
	s = s.withDefaults()
	b, err := s.get(ctx, s.API+"/releases/latest", 1<<20)
	if err != nil {
		return "", fmt.Errorf("can't find the latest release: %w", err)
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &r); err != nil || !tagRE.MatchString(r.Tag) {
		return "", fmt.Errorf("unexpected release data from %s", s.API)
	}
	return r.Tag, nil
}

// AssetName is the release file for an OS and architecture.
func AssetName(version, goos, goarch string) string {
	return "asiri-" + version + "-" + goos + "-" + goarch
}

// Fetch downloads the binary for version and checks it against the
// release's checksums.txt. It never returns unverified bytes.
func (s Source) Fetch(ctx context.Context, version string) ([]byte, error) {
	s = s.withDefaults()
	if !tagRE.MatchString(version) {
		return nil, fmt.Errorf("version %q: want a tag like v0.1.0", version)
	}
	name := AssetName(version, s.GOOS, s.GOARCH)
	base := s.Download + "/" + version + "/"
	sums, err := s.get(ctx, base+"checksums.txt", 1<<20)
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("release %s doesn't exist (or has no checksums.txt)", version)
	}
	if err != nil {
		return nil, err
	}
	want, err := checksumFor(sums, name)
	if err != nil {
		return nil, err
	}
	bin, err := s.get(ctx, base+name, maxBinary)
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("release %s has no build for %s/%s", version, s.GOOS, s.GOARCH)
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bin)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("%s: checksum mismatch (want %s, got %s); not installing it", name, want, got)
	}
	return bin, nil
}

// checksumFor finds name in sha256sum output, matching the file's base
// name (v0.1.0 lists ./darwin-arm64/asiri-…, later releases list asiri-…).
func checksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && path.Base(strings.TrimPrefix(f[1], "*")) == name {
			if len(f[0]) != 64 {
				break
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

// Replace swaps the file at target for bin: write a temporary file in the
// same directory, then rename over target, so the switch is atomic and a
// running copy keeps working.
func Replace(target string, bin []byte) error {
	dir := filepath.Dir(target)
	mode := os.FileMode(0o755)
	if fi, err := os.Stat(target); err == nil {
		mode = fi.Mode().Perm() | 0o100
	}
	f, err := os.CreateTemp(dir, ".asiri-update-*")
	if err != nil {
		return fmt.Errorf("can't write next to %s (%w); reinstall with the install script, or run with permission to write there", target, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(bin); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

var tagRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// Newer reports whether release tag a is newer than b. A b that isn't a
// release tag (such as "dev") counts as older than any release.
func Newer(a, b string) bool {
	pa, pb := tagRE.FindStringSubmatch(a), tagRE.FindStringSubmatch(b)
	if pa == nil {
		return false
	}
	if pb == nil {
		return true
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// IsRelease reports whether v is a release tag (not a development build).
func IsRelease(v string) bool { return tagRE.MatchString(v) }

// GOOSOrRuntime and GOARCHOrRuntime are the platform Fetch will download for.
func (s Source) GOOSOrRuntime() string   { return s.withDefaults().GOOS }
func (s Source) GOARCHOrRuntime() string { return s.withDefaults().GOARCH }
