package service

import (
	"path/filepath"
	"regexp"

	"github.com/gingered-cat/asiri/internal/domain"
)

// RuleInput is what a rule sees about a request.
type RuleInput struct {
	Client domain.Client
	Item   domain.Item
	In     RequestInput
}

// Rule rejects a request by returning an error. Rules run in order and the
// first error wins.
type Rule func(RuleInput) error

func defaultRules() []Rule {
	return []Rule{ruleBinary, ruleKind, ruleInterpreter, ruleAllowList, ruleSSHHost}
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isSSH(r RuleInput) bool { return r.In.HostFP != "" }

func ruleBinary(r RuleInput) error {
	if isSSH(r) {
		return nil
	}
	if !filepath.IsAbs(r.In.BinPath) || !sha256Hex.MatchString(r.In.BinSHA256) {
		return domain.Errorf(domain.CodeInvalid, "a request needs the binary's absolute path and sha256")
	}
	return nil
}

func ruleKind(r RuleInput) error {
	if isSSH(r) {
		if r.Item.Kind != domain.KindSSHKey {
			return domain.Errorf(domain.CodeNotAllowed, "%s is not an SSH key", r.Item.Ref)
		}
		return nil
	}
	if r.Item.Kind == domain.KindSSHKey {
		return domain.Errorf(domain.CodeNotAllowed, "%s is an SSH key; SSH keys are used through `asiri ssh`, not `asiri run`", r.Item.Ref)
	}
	return nil
}

func ruleInterpreter(r RuleInput) error {
	if isSSH(r) {
		return nil
	}
	if domain.IsInterpreter(r.In.BinPath) && !domain.BinAllowed(r.Item.Policy.Bins, r.In.BinPath) {
		return domain.Errorf(domain.CodeInterpreter,
			"%s can run any code, so it can print or send %s anywhere; asiri won't give it a secret "+
				"(if you really mean it: asiri policy %s --bins %s)",
			filepath.Base(r.In.BinPath), r.Item.Ref, r.Item.Ref, filepath.Base(r.In.BinPath))
	}
	return nil
}

func ruleAllowList(r RuleInput) error {
	if isSSH(r) {
		return nil
	}
	if len(r.Item.Policy.Bins) == 0 {
		return domain.Errorf(domain.CodeNotAllowed, "no program may use %s yet; allow one with: asiri policy %s --bins %s",
			r.Item.Ref, r.Item.Ref, filepath.Base(r.In.BinPath))
	}
	if !domain.BinAllowed(r.Item.Policy.Bins, r.In.BinPath) {
		return domain.Errorf(domain.CodeNotAllowed, "%s may only be used by %v, not %s",
			r.Item.Ref, r.Item.Policy.Bins, filepath.Base(r.In.BinPath))
	}
	return nil
}

var sshFP = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// ruleSSHHost binds an SSH key to the host keys in its policy.
func ruleSSHHost(r RuleInput) error {
	if !isSSH(r) {
		return nil
	}
	if !sshFP.MatchString(r.In.HostFP) {
		return domain.Errorf(domain.CodeInvalid, "host key fingerprint %q: want SHA256:…", r.In.HostFP)
	}
	if len(r.Item.Policy.SSHHosts) == 0 {
		return domain.Errorf(domain.CodeNotAllowed, "no host may use %s yet; allow one with: asiri policy %s --ssh-hosts HOST",
			r.Item.Ref, r.Item.Ref)
	}
	if _, ok := domain.SSHHostAllowed(r.Item.Policy.SSHHosts, r.In.HostFP); !ok {
		return domain.Errorf(domain.CodeNotAllowed, "%s may not sign in to the host with key %s (allowed: %v)",
			r.Item.Ref, r.In.HostFP, r.Item.Policy.SSHHosts)
	}
	return nil
}
