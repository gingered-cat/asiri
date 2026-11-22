package domain

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type (
	RequestID string
	GrantID   string
)

// RequestStatus is a request's place in its lifecycle:
//
//	pending → approved | denied | expired
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
)

// Decision is the person's answer to a request.
type Decision string

const (
	DecideOnce    Decision = "once"
	Decide15m     Decision = "15m"
	Decide1h      Decision = "1h"
	DecideDeny    Decision = "deny"
	OnceRedeemTTL          = 5 * time.Minute // a once-grant must be used within this
)

func (d Decision) Valid() bool {
	switch d {
	case DecideOnce, Decide15m, Decide1h, DecideDeny:
		return true
	}
	return false
}

// Duration is how long an approving decision lasts.
func (d Decision) Duration() time.Duration {
	switch d {
	case Decide15m:
		return 15 * time.Minute
	case Decide1h:
		return time.Hour
	}
	return OnceRedeemTTL
}

// Clamp limits d to the item's max_grant ("once", "15m" or "1h").
func (d Decision) Clamp(max string) Decision {
	rank := map[Decision]int{DecideOnce: 0, Decide15m: 1, Decide1h: 2}
	m := Decision(max)
	if _, ok := rank[m]; !ok || d == DecideDeny {
		return d
	}
	if rank[d] > rank[m] {
		return m
	}
	return d
}

// Method says how a decision was made.
type Method string

const (
	MethodRex  Method = "rex"
	MethodTTY  Method = "tty"
	MethodCLI  Method = "cli"
	MethodWait Method = "wait"
	// MethodTouchID: signed by an enrolled approval key, which took Touch ID
	// or the Mac's password.
	MethodTouchID Method = "touchid"
)

func (m Method) Valid() bool {
	switch m {
	case MethodRex, MethodTTY, MethodCLI, MethodWait, MethodTouchID:
		return true
	}
	return false
}

// Request asks to use one item with one binary.
type Request struct {
	ID         RequestID     `json:"id"`
	ClientID   ClientID      `json:"client_id"`
	ClientName string        `json:"client_name"`
	Ref        Ref           `json:"ref"`
	ItemID     ItemID        `json:"item_id"`
	BinPath    string        `json:"bin_path"`
	HostFP     string        `json:"host_fp,omitempty"` // SSH requests: the destination's host key
	Argv       string        `json:"argv"`
	Cwd        string        `json:"cwd"`
	Reason     string        `json:"reason"`
	Status     RequestStatus `json:"status"`
	Decision   Decision      `json:"decision,omitempty"`
	Method     Method        `json:"method,omitempty"`
	GrantID    GrantID       `json:"grant_id,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"` // when a pending request expires
	Title      string        `json:"title"`
	Detail     string        `json:"detail"`
}

// Grant is an approved right to redeem an item's value.
type Grant struct {
	ID         GrantID    `json:"id"`
	RequestID  RequestID  `json:"request_id"`
	ClientID   ClientID   `json:"client_id"`
	ClientName string     `json:"client_name"`
	ItemID     ItemID     `json:"item_id"`
	Ref        Ref        `json:"ref"`
	BinPath    string     `json:"bin_path"`
	HostFP     string     `json:"host_fp,omitempty"`
	Decision   Decision   `json:"decision"`
	Method     Method     `json:"method"`
	UsesLeft   *int       `json:"uses_left,omitempty"` // nil for timed grants
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Programs that run arbitrary code or other programs. A secret given to one
// of these can be printed or sent anywhere, so asiri refuses them unless the
// item's policy names them explicitly.
var interpreters = map[string]bool{
	// shells
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true, "ksh": true, "mksh": true,
	"tcsh": true, "csh": true, "ash": true, "nu": true, "elvish": true, "xonsh": true, "pwsh": true, "powershell": true,
	// language runtimes
	"python": true, "pypy": true, "node": true, "nodejs": true, "deno": true, "bun": true, "ruby": true,
	"irb": true, "perl": true, "php": true, "lua": true, "luajit": true, "tclsh": true, "wish": true,
	"expect": true, "osascript": true, "swift": true, "julia": true, "Rscript": true, "R": true, "java": true,
	"jshell": true, "groovy": true, "scala": true, "kotlin": true, "elixir": true, "iex": true, "erl": true,
	"ghci": true, "runghc": true, "guile": true, "racket": true, "sbcl": true, "clojure": true,
	// text tools that can execute commands
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true, "gsed": true, "vim": true, "vi": true,
	"nvim": true, "emacs": true, "ed": true,
	// programs that run other programs
	"env": true, "xargs": true, "sudo": true, "doas": true, "su": true, "nohup": true, "nice": true,
	"timeout": true, "time": true, "watch": true, "script": true, "find": true, "make": true, "gmake": true,
	"npx": true, "bunx": true, "uvx": true, "pipx": true, "parallel": true, "strace": true, "ltrace": true,
	"gdb": true, "lldb": true, "busybox": true, "flock": true, "setsid": true, "exec": true, "eval": true,
	"tmux": true, "screen": true, "ssh": true, "docker": true, "podman": true, "kubectl": true,
}

var versionSuffix = regexp.MustCompile(`[0-9][0-9.]*$`)

// IsInterpreter reports whether the program at path (by base name, ignoring
// a version suffix such as python3.12) is on the interpreter list.
func IsInterpreter(path string) bool {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".exe")
	if interpreters[base] {
		return true
	}
	trimmed := strings.TrimRight(versionSuffix.ReplaceAllString(base, ""), "-")
	return trimmed != "" && interpreters[trimmed]
}

// BinAllowed reports whether a policy bins list names the binary at path,
// by base name or by absolute path.
func BinAllowed(bins []string, path string) bool {
	base := filepath.Base(path)
	for _, b := range bins {
		if b == path || b == base {
			return true
		}
	}
	return false
}

// SSHHostAllowed reports whether a policy's ssh_hosts names the host key
// fingerprint fp, and returns the entry's label.
func SSHHostAllowed(hosts []string, fp string) (string, bool) {
	for _, h := range hosts {
		name, f, ok := strings.Cut(h, "=")
		if !ok {
			name, f = "", h
		}
		if f == fp {
			return name, true
		}
	}
	return "", false
}

// ApprovalKey is an enrolled Secure Enclave key whose signature an "allow"
// decision needs. PublicKey is PKIX DER; ID is approvalkey.ID(PublicKey).
type ApprovalKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	ClientID  ClientID   `json:"client_id"`
	PublicKey []byte     `json:"public_key"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
