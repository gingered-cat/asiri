package importer

import (
	"strings"
	"testing"
)

const appleCSV = "\xef\xbb\xbfTitle,URL,Username,Password,Notes,OTPAuth\n" +
	"GitHub,github.com/,octocat,correct-horse-battery,Personal account,otpauth://totp?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30\n" +
	"GitHub (work),https://github.com/,octo@work.example,s3cret,\"multi\nline, with \"\"quotes\"\"\",\n" +
	"Router,http://192.168.1.1/,admin,routerpw,,\n" +
	"Passkey only,example.com,,,,\n"

const googleCSV = "name,url,username,password,note\n" +
	"accounts.google.com,https://accounts.google.com/signin,me@gmail.com,gpw,\n" +
	"www.example.com,https://www.example.com/login,me,pw1,a note\n" +
	"example.com,https://example.com/,me,pw2,\n"

func TestParseApple(t *testing.T) {
	src, es, err := Parse(strings.NewReader(appleCSV))
	if err != nil || src != Apple {
		t.Fatalf("src %s err %v", src, err)
	}
	if len(es) != 3 {
		t.Fatalf("want 3 entries (passkey-only row skipped), got %d: %+v", len(es), es)
	}
	byName := map[string]Entry{}
	for _, e := range es {
		byName[e.Name] = e
	}
	gh := byName["github.com-octocat"]
	if gh.Password != "correct-horse-battery" || !strings.HasPrefix(gh.TOTP, "otpauth://totp?secret=") || gh.Notes != "Personal account" {
		t.Fatalf("github entry %+v (names %v)", gh, keys(byName))
	}
	if w := byName["github.com-octo"]; w.Notes != "multi\nline, with \"quotes\"" || w.Username != "octo@work.example" {
		t.Fatalf("work entry %+v", w)
	}
	if r := byName["router"]; r.Password != "routerpw" {
		t.Fatalf("router (named from title) %+v", r)
	}
}

func TestParseGoogle(t *testing.T) {
	src, es, err := Parse(strings.NewReader(googleCSV))
	if err != nil || src != Google || len(es) != 3 {
		t.Fatalf("src %s n %d err %v", src, len(es), err)
	}
	names := map[string]string{}
	for _, e := range es {
		names[e.Name] = e.Password
	}
	// www. is dropped, so example.com has two accounts with the same username: -2.
	if names["accounts.google.com"] != "gpw" || len(names) != 3 {
		t.Fatalf("names %v", names)
	}
	if _, ok := names["example.com-me"]; !ok {
		t.Fatalf("names %v", names)
	}
	if _, ok := names["example.com-me-2"]; !ok {
		t.Fatalf("names %v", names)
	}
}

func TestNamesAreStableAcrossOrder(t *testing.T) {
	_, a, _ := Parse(strings.NewReader(googleCSV))
	lines := strings.Split(strings.TrimSpace(googleCSV), "\n")
	reversed := lines[0] + "\n" + lines[3] + "\n" + lines[2] + "\n" + lines[1] + "\n"
	_, b, _ := Parse(strings.NewReader(reversed))
	pw := func(es []Entry) map[string]string {
		m := map[string]string{}
		for _, e := range es {
			m[e.Name] = e.Password + "/" + e.Notes
		}
		return m
	}
	ma, mb := pw(a), pw(b)
	for k, v := range ma {
		if mb[k] != v {
			t.Fatalf("name %s: %q vs %q", k, v, mb[k])
		}
	}
}

func TestUnknownHeader(t *testing.T) {
	_, _, err := Parse(strings.NewReader("Label,User Name,Password,Website,Note\nx,y,z,w,v\n"))
	if err == nil || !strings.Contains(err.Error(), "unrecognised header") {
		t.Fatalf("err %v", err)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"GitHub (work)": "github-work", "..x..": "x", "a b/c": "a-b-c", "": "", strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func keys(m map[string]Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
