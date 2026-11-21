package run

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	mrand "math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

func scrubAll(t *testing.T, values []Value, input []byte, chunks func(n int) int) (string, *Scrubber) {
	t.Helper()
	var out bytes.Buffer
	s := NewScrubber(&out, values)
	for len(input) > 0 {
		n := min(len(input), max(1, chunks(len(input))))
		if _, err := s.Write(input[:n]); err != nil {
			t.Fatal(err)
		}
		input = input[n:]
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String(), s
}

func TestScrubBasic(t *testing.T) {
	v := []Value{{Secret: []byte("ghp_abcdef123456"), Label: "asiri://dev/github"}}
	in := "token=ghp_abcdef123456\nb64=" + base64.StdEncoding.EncodeToString([]byte("ghp_abcdef123456")) +
		"\nhex=" + hex.EncodeToString([]byte("ghp_abcdef123456")) + "\nnothing here\n"
	got, s := scrubAll(t, v, []byte(in), func(int) int { return 1 << 20 })
	want := "token=[asiri:asiri://dev/github]\nb64=[asiri:asiri://dev/github]\nhex=[asiri:asiri://dev/github]\nnothing here\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if s.Hits()[0] != 3 {
		t.Fatalf("hits %v", s.Hits())
	}
}

func TestScrubPassThroughAndShortValues(t *testing.T) {
	got, _ := scrubAll(t, nil, []byte("plain output"), func(int) int { return 3 })
	if got != "plain output" {
		t.Fatalf("got %q", got)
	}
	// Values under MinScrubLen are not scrubbed (they would match everything).
	got, _ = scrubAll(t, []Value{{Secret: []byte("ab"), Label: "x"}}, []byte("abab"), func(int) int { return 1 })
	if got != "abab" {
		t.Fatalf("short value: %q", got)
	}
}

// Random values, random encodings, random chunk boundaries: no form of any
// value may survive, and everything else must come through unchanged.
func TestScrubFuzz(t *testing.T) {
	for seed := range uint64(8) {
		scrubFuzz(t, mrand.New(mrand.NewPCG(seed, 2)))
	}
}

func scrubFuzz(t *testing.T, r *mrand.Rand) {
	for iter := range 500 {
		var values []Value
		var forms []string
		for k := range 1 + r.IntN(3) {
			b := make([]byte, 6+r.IntN(40))
			rand.Read(b)
			if r.IntN(2) == 0 { // printable values too
				b = []byte(base64.RawURLEncoding.EncodeToString(b))
			}
			values = append(values, Value{Secret: b, Label: "v" + string(rune('0'+k))})
			for _, f := range encodings(b) {
				forms = append(forms, string(f))
			}
		}
		var in, want strings.Builder
		for range 20 + r.IntN(30) {
			if r.IntN(3) == 0 {
				v := values[r.IntN(len(values))]
				enc := encodings(v.Secret)
				in.Write(enc[r.IntN(len(enc))])
				want.WriteString("[asiri:" + v.Label + "]")
			} else {
				filler := strings.Repeat(string(rune('a'+r.IntN(26))), 1+r.IntN(30)) + " \n"
				in.WriteString(filler)
				want.WriteString(filler)
			}
		}
		got, _ := scrubAll(t, values, []byte(in.String()), func(n int) int { return 1 + r.IntN(min(n, 64)) })
		for _, f := range forms {
			if len(f) >= MinScrubLen && strings.Contains(got, f) {
				t.Fatalf("iter %d: a form of a value survived: %q in %q", iter, f, got)
			}
		}
		// Overlapping copies of one value are replaced by a single label.
		if collapse(got, values) != collapse(want.String(), values) {
			t.Fatalf("iter %d: output changed\ngot  %q\nwant %q", iter, got, want.String())
		}
	}
}

func collapse(s string, values []Value) string {
	for _, v := range values {
		tok := "[asiri:" + v.Label + "]"
		for strings.Contains(s, tok+tok) {
			s = strings.ReplaceAll(s, tok+tok, tok)
		}
	}
	return s
}

func TestEncodingsIncludeURLForms(t *testing.T) {
	v := []byte("p@ss w/rd!")
	found := false
	for _, e := range encodings(v) {
		if string(e) == url.QueryEscape(string(v)) {
			found = true
		}
	}
	if !found {
		t.Fatal("query-escaped form missing")
	}
}

func BenchmarkScrub(b *testing.B) {
	values := []Value{{Secret: []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789"), Label: "a"},
		{Secret: []byte("postgres://user:hunter2hunter2@db:5432/app"), Label: "b"}}
	chunk := bytes.Repeat([]byte("ordinary build output line with nothing secret in it\n"), 600) // ~32 KiB
	var sink bytes.Buffer
	s := NewScrubber(&sink, values)
	b.SetBytes(int64(len(chunk)))
	for b.Loop() {
		sink.Reset()
		s.Write(chunk)
	}
}

// Regression: base64 padding of one value overlapped the start of the next
// value, and the next value's remainder leaked.
func TestScrubOverlappingValues(t *testing.T) {
	values := []Value{{Secret: []byte("abcd"), Label: "a"}, {Secret: []byte("==xyzw-secret-tail"), Label: "b"}}
	in := base64.RawStdEncoding.EncodeToString([]byte("abcd")) + "==xyzw-secret-tail\n" // "YWJjZA" + value b
	for _, chunk := range []int{1, 3, 7, 1 << 20} {
		got, _ := scrubAll(t, values, []byte(in), func(int) int { return chunk })
		if strings.Contains(got, "xyzw") || got != "[asiri:a][asiri:b]\n" {
			t.Fatalf("chunk %d: %q", chunk, got)
		}
	}
}
