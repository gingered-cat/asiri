package run

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"sort"
	"sync"
)

// MinScrubLen is the shortest value the scrubber looks for. Shorter values
// would match ordinary output; they are delivered but not scrubbed.
const MinScrubLen = 4

type pattern struct {
	b     []byte
	label int // index into Scrubber.labels
}

// Scrubber is an io.Writer that replaces known secret values, and common
// encodings of them, before passing output on. It holds back the last
// (longest pattern - 1) bytes between writes, so a value split across two
// writes is still caught. Call Flush when the writer is done.
//
// It is a safety net, not the defence: a program can always transform a
// value (reverse it, encrypt it) into something no scrubber recognises.
type Scrubber struct {
	mu       sync.Mutex
	w        io.Writer
	patterns []pattern
	repl     [][]byte
	maxLen   int
	pending  []byte
	hits     []int
	err      error
}

// Value is a secret to look for, with the label to print instead.
type Value struct {
	Secret []byte
	Label  string // e.g. asiri://dev/github
}

// NewScrubber writes to w with every value (and its encodings) replaced by
// "[asiri:<label>]".
func NewScrubber(w io.Writer, values []Value) *Scrubber {
	s := &Scrubber{w: w, hits: make([]int, len(values))}
	for i, v := range values {
		s.repl = append(s.repl, []byte("[asiri:"+v.Label+"]"))
		if len(v.Secret) < MinScrubLen {
			continue
		}
		seen := map[string]bool{}
		for _, form := range encodings(v.Secret) {
			if len(form) < MinScrubLen || seen[string(form)] {
				continue
			}
			seen[string(form)] = true
			s.patterns = append(s.patterns, pattern{b: form, label: i})
			s.maxLen = max(s.maxLen, len(form))
		}
	}
	return s
}

func encodings(v []byte) [][]byte {
	return [][]byte{
		v,
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawStdEncoding.EncodeToString(v)),
		[]byte(base64.URLEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
		[]byte(hex.EncodeToString(v)),
		bytes.ToUpper([]byte(hex.EncodeToString(v))),
		[]byte(url.QueryEscape(string(v))),
		[]byte(url.PathEscape(string(v))),
	}
}

// Hits returns how many replacements were made for each value.
func (s *Scrubber) Hits() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.hits...)
}

func (s *Scrubber) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if len(s.patterns) == 0 {
		_, s.err = s.w.Write(p)
		return len(p), s.err
	}
	s.pending = append(s.pending, p...)
	out, rest := s.scan(s.pending, false)
	s.pending = append(s.pending[:0], rest...)
	if len(out) > 0 {
		_, s.err = s.w.Write(out)
	}
	return len(p), s.err
}

// Flush writes whatever is held back.
func (s *Scrubber) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil || len(s.pending) == 0 {
		return s.err
	}
	out, _ := s.scan(s.pending, true)
	clear(s.pending)
	s.pending = s.pending[:0]
	_, s.err = s.w.Write(out)
	return s.err
}

// scan replaces every complete match in buf. Overlapping matches (two values
// back to back, or a value and a longer encoding of it) are merged and
// replaced together, so no part of either survives. Unless final, it keeps
// back the tail that a later write could still turn into a match.
func (s *Scrubber) scan(buf []byte, final bool) (out, rest []byte) {
	type match struct{ start, end, label int }
	var ms []match
	for _, p := range s.patterns {
		for off := 0; off < len(buf); {
			k := bytes.Index(buf[off:], p.b)
			if k < 0 {
				break
			}
			ms = append(ms, match{off + k, off + k + len(p.b), p.label})
			off += k + 1
		}
	}
	sort.Slice(ms, func(a, b int) bool {
		if ms[a].start != ms[b].start {
			return ms[a].start < ms[b].start
		}
		return ms[a].end > ms[b].end
	})

	// Any match still incomplete at the end of buf starts at or after
	// boundary, so groups that end by then can't grow any more.
	boundary := len(buf)
	if !final {
		boundary = max(0, len(buf)-(s.maxLen-1))
	}
	i, cut := 0, boundary
	for g := 0; g < len(ms); {
		start, end := ms[g].start, ms[g].end
		labels := []int{ms[g].label}
		g++
		for g < len(ms) && ms[g].start < end {
			end = max(end, ms[g].end)
			if ms[g].label != labels[len(labels)-1] {
				labels = append(labels, ms[g].label)
			}
			g++
		}
		if end > boundary {
			cut = min(cut, start)
			break
		}
		out = append(out, buf[i:start]...)
		for _, l := range labels {
			out = append(out, s.repl[l]...)
			s.hits[l]++
		}
		i = end
	}
	cut = max(cut, i)
	out = append(out, buf[i:cut]...)
	return out, buf[cut:]
}
