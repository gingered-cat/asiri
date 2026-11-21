// Package importer reads password-manager CSV exports: Apple Passwords (and
// Safari), and Google Password Manager (and Chrome).
package importer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Source is where an export came from. It is also the default vault name.
type Source string

const (
	Apple  Source = "apple"
	Google Source = "google"
)

func (s Source) String() string {
	switch s {
	case Apple:
		return "Apple Passwords"
	case Google:
		return "Google Password Manager"
	}
	return string(s)
}

// The exact headers each app writes.
var headers = map[Source][]string{
	Apple:  {"title", "url", "username", "password", "notes", "otpauth"},
	Google: {"name", "url", "username", "password", "note"},
}

// Entry is one login. Name is the item name it will be stored under.
type Entry struct {
	Name     string `json:"name"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TOTP     string `json:"totp,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// MaxEntries guards against feeding in something that isn't an export.
const MaxEntries = 20000

// Parse reads an export, detects which app wrote it from its header, and
// names every entry.
func Parse(r io.Reader) (Source, []Entry, error) {
	br := bufio.NewReader(r)
	if b, err := br.Peek(3); err == nil && string(b) == "\xef\xbb\xbf" {
		br.Discard(3) // UTF-8 BOM
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return "", nil, fmt.Errorf("can't read the header row: %w", err)
	}
	src, cols, err := detect(head)
	if err != nil {
		return "", nil, err
	}
	var entries []Entry
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("row %d: %w", line, err)
		}
		get := func(col string) string {
			if i, ok := cols[col]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		e := Entry{URL: get("url"), Username: get("username"), Password: get("password")}
		switch src {
		case Apple:
			e.Title, e.Notes, e.TOTP = get("title"), get("notes"), get("otpauth")
		case Google:
			e.Title, e.Notes = get("name"), get("note")
		}
		if e.Password == "" && e.TOTP == "" && e.Username == "" {
			continue // nothing worth keeping (e.g. a passkey-only row)
		}
		entries = append(entries, e)
		if len(entries) > MaxEntries {
			return "", nil, fmt.Errorf("more than %d logins; this doesn't look like a password export", MaxEntries)
		}
	}
	AssignNames(entries)
	return src, entries, nil
}

func detect(head []string) (Source, map[string]int, error) {
	cols := map[string]int{}
	for i, h := range head {
		cols[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, src := range []Source{Apple, Google} {
		ok := true
		for _, h := range headers[src] {
			if _, found := cols[h]; !found {
				ok = false
				break
			}
		}
		if ok {
			return src, cols, nil
		}
	}
	return "", nil, fmt.Errorf("unrecognised header %q: want an Apple Passwords export (%s) or a Google Password Manager export (%s)",
		strings.Join(head, ","), strings.Join(headers[Apple], ","), strings.Join(headers[Google], ","))
}

var notName = regexp.MustCompile(`[^a-z0-9._-]+`)

// slug turns s into a valid ref segment, or "".
func slug(s string) string {
	s = notName.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-._")
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "-._")
	}
	return s
}

// host returns the site's host name without "www.", or "".
func host(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw // Apple writes "github.com/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

// AssignNames gives each entry a stable item name: the site's host, or the
// title. When a site has several accounts, each gets the host plus its
// username ("github.com-octocat"); any clash left gets "-2", "-3", ….
func AssignNames(entries []Entry) {
	base := make([]string, len(entries))
	count := map[string]int{}
	for i, e := range entries {
		h := host(e.URL)
		b := slug(h)
		if b == "" || (net.ParseIP(h) != nil && slug(e.Title) != "") {
			b = slug(e.Title) // "router" reads better than 192.168.1.1
		}
		if b == "" {
			b = "login"
		}
		base[i] = b
		count[b]++
	}
	// Sort so names don't depend on export order.
	idx := make([]int, len(entries))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ea, eb := entries[idx[a]], entries[idx[b]]
		if base[idx[a]] != base[idx[b]] {
			return base[idx[a]] < base[idx[b]]
		}
		if ea.Username != eb.Username {
			return ea.Username < eb.Username
		}
		if ea.URL != eb.URL {
			return ea.URL < eb.URL
		}
		return ea.Title < eb.Title
	})
	used := map[string]bool{}
	for _, i := range idx {
		name := base[i]
		if count[name] > 1 {
			user := entries[i].Username
			if at := strings.IndexByte(user, '@'); at > 0 {
				user = user[:at]
			}
			if u := slug(user); u != "" {
				name = slug(name + "-" + u)
			}
		}
		final := name
		for n := 2; used[final]; n++ {
			final = slug(name+"-") + "-" + strconv.Itoa(n)
		}
		used[final] = true
		entries[i].Name = final
	}
}
