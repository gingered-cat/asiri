// Package rexplug installs asiri as a Rex plugin: a Lua file beside Rex's
// config, and a marked block in init.lua that loads it. Nothing outside the
// marked block is touched, and a config Rex rejects is rolled back.
package rexplug

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed asiri.lua
var Source string

const (
	begin   = "-- >>> asiri >>>"
	end     = "-- <<< asiri <<<"
	version = "-- plugin: "
)

// ConfigPath is Rex's init.lua: $REX_CONFIG, else $XDG_CONFIG_HOME/rex/init.lua,
// else ~/.config/rex/init.lua.
func ConfigPath() (string, error) {
	if p := os.Getenv("REX_CONFIG"); p != "" {
		return p, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "rex", "init.lua"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "rex", "init.lua"), nil
}

// PluginPath is where the Lua file goes, next to init.lua.
func PluginPath(config string) string {
	return filepath.Join(filepath.Dir(config), "plugins", "asiri", "init.lua")
}

// Rex runs the rex CLI.
type Rex func(ctx context.Context, args ...string) error

// SystemRex runs the rex on PATH without starting a server that isn't running.
func SystemRex(ctx context.Context, args ...string) error {
	bin, err := exec.LookPath("rex")
	if err != nil {
		return errors.New("rex is not installed (https://www.superlogical.com/rex)")
	}
	out, err := exec.CommandContext(ctx, bin, append([]string{"--autostart=false"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rex %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// Result says what Install or Uninstall did.
type Result struct {
	Config, Plugin string
	Reloaded       bool
	ReloadErr      error
}

// Install writes the plugin and its block, checks the config with Rex, and
// reloads it. bin is the asiri binary the plugin runs; profile is the asiri
// profile it approves with.
func Install(ctx context.Context, rex Rex, bin, profile string) (Result, error) {
	config, err := ConfigPath()
	if err != nil {
		return Result{}, err
	}
	plugin := PluginPath(config)
	before, err := os.ReadFile(config)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	oldPlugin, _ := os.ReadFile(plugin)
	if err := writeFile(plugin, []byte(Source)); err != nil {
		return Result{}, err
	}
	next := WithBlock(string(before), Block(plugin, bin, profile))
	if err := writeFile(config, []byte(next)); err != nil {
		return Result{}, err
	}
	if err := rex(ctx, "config", "check", config); err != nil {
		restore(config, before)
		restore(plugin, oldPlugin)
		return Result{}, fmt.Errorf("Rex rejected the config, so nothing was changed: %w", err)
	}
	res := Result{Config: config, Plugin: plugin}
	res.ReloadErr = rex(ctx, "config", "reload")
	res.Reloaded = res.ReloadErr == nil
	return res, nil
}

// Uninstall removes the block and the plugin file.
func Uninstall(ctx context.Context, rex Rex) (Result, error) {
	config, err := ConfigPath()
	if err != nil {
		return Result{}, err
	}
	plugin := PluginPath(config)
	res := Result{Config: config, Plugin: plugin}
	before, err := os.ReadFile(config)
	if err == nil {
		next := WithBlock(string(before), "")
		if next != string(before) {
			if err := writeFile(config, []byte(next)); err != nil {
				return res, err
			}
			if err := rex(ctx, "config", "check", config); err != nil {
				restore(config, before)
				return res, fmt.Errorf("Rex rejected the config without asiri, so nothing was changed: %w", err)
			}
			res.ReloadErr = rex(ctx, "config", "reload")
			res.Reloaded = res.ReloadErr == nil
		}
	}
	os.Remove(plugin)
	os.Remove(filepath.Dir(plugin)) // only if empty
	return res, nil
}

// Installed reports whether init.lua has asiri's block.
func Installed() (bool, string, error) {
	config, err := ConfigPath()
	if err != nil {
		return false, "", err
	}
	b, err := os.ReadFile(config)
	if errors.Is(err, fs.ErrNotExist) {
		return false, config, nil
	}
	return strings.Contains(string(b), begin), config, err
}

// Block is the managed block. Its version line is a hash of the plugin, so
// init.lua changes when the plugin does and Rex refetches the actions.
func Block(plugin, bin, profile string) string {
	h := fnv.New64a()
	h.Write([]byte(Source))
	return fmt.Sprintf("%s\n-- Managed by `asiri rex install`; `asiri rex uninstall` removes it.\n%s%016x\n"+
		"dofile(%s).setup({ bin = %s, profile = %s })\n%s\n",
		begin, version, h.Sum64(), luaString(plugin), luaString(bin), luaString(profile), end)
}

// WithBlock puts block where asiri's block was, or at the end. An empty
// block removes it.
func WithBlock(content, block string) string {
	if i := strings.Index(content, begin); i >= 0 {
		if j := strings.Index(content[i:], end); j >= 0 {
			after := strings.TrimPrefix(content[i+j+len(end):], "\n")
			out := content[:i] + block + after
			if block == "" {
				out = strings.TrimRight(content[:i], "\n") + "\n" + after
				if strings.TrimSpace(out) == "" {
					return ""
				}
			}
			return out
		}
	}
	if block == "" {
		return content
	}
	if strings.TrimSpace(content) == "" {
		return block
	}
	return strings.TrimRight(content, "\n") + "\n\n" + block
}

func luaString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

func writeFile(path string, b []byte) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(b) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func restore(path string, before []byte) {
	if before == nil {
		os.Remove(path)
		return
	}
	os.WriteFile(path, before, 0o644)
}
