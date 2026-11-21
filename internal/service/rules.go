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
	return []Rule{ruleBinary, ruleKind, ruleInterpreter, ruleAllowList}
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ruleBinary(r RuleInput) error {
	if !filepath.IsAbs(r.In.BinPath) || !sha256Hex.MatchString(r.In.BinSHA256) {
		return domain.Errorf(domain.CodeInvalid, "a request needs the binary's absolute path and sha256")
	}
	return nil
}

func ruleKind(r RuleInput) error {
	if r.Item.Kind == domain.KindSSHKey {
		return domain.Errorf(domain.CodeNotAllowed, "%s is an SSH key; SSH keys are used through `asiri ssh`, not `asiri run`", r.Item.Ref)
	}
	return nil
}

func ruleInterpreter(r RuleInput) error {
	if domain.IsInterpreter(r.In.BinPath) && !domain.BinAllowed(r.Item.Policy.Bins, r.In.BinPath) {
		return domain.Errorf(domain.CodeInterpreter,
			"%s can run any code, so it can print or send %s anywhere; asiri won't give it a secret "+
				"(if you really mean it: asiri policy %s --bins %s)",
			filepath.Base(r.In.BinPath), r.Item.Ref, r.Item.Ref, filepath.Base(r.In.BinPath))
	}
	return nil
}

func ruleAllowList(r RuleInput) error {
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
