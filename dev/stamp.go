package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The scripts and styles the site's HTML loads. Their URLs get ?v=<version>
// at deploy time, so a deploy always reaches browsers: Cloudflare's 4-hour
// browser cache would otherwise keep serving the previous files.
var assetURL = regexp.MustCompile(`((?:href|src)="/(?:app\.js|style\.css|docs/docs\.js|docs/docs\.v2\.css))(?:\?v=[0-9a-f]+)?"`)

// stampTask rewrites asset URLs in every .html file under dir.
func stampTask(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: go run ./dev stamp DIR VERSION")
	}
	n, err := stamp(args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Printf("stamped %d asset URLs with ?v=%s\n", n, args[1])
	return nil
}

func stamp(dir, version string) (int, error) {
	if !regexp.MustCompile(`^[0-9a-f]{7,40}$`).MatchString(version) {
		return 0, fmt.Errorf("version %q: want a commit hash", version)
	}
	total := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		n := len(assetURL.FindAllIndex(b, -1))
		if n == 0 {
			return nil
		}
		total += n
		out := assetURL.ReplaceAll(b, []byte(`${1}?v=`+version+`"`))
		return os.WriteFile(path, out, 0o644)
	})
	return total, err
}
