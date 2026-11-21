package rexplug

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithBlock(t *testing.T) {
	user := "rex.bind(\"cmd+b\", \"client.sidebar.toggle\")\n"
	b1 := Block("/p/asiri/init.lua", "/bin/asiri", "owner")
	added := WithBlock(user, b1)
	if !strings.HasPrefix(added, user) || !strings.HasSuffix(added, b1) {
		t.Fatalf("added:\n%s", added)
	}
	b2 := Block("/p/asiri/init.lua", "/opt/asiri", "owner")
	replaced := WithBlock(added+"-- after\n", b2)
	if strings.Contains(replaced, "/bin/asiri") || !strings.Contains(replaced, "/opt/asiri") || !strings.HasSuffix(replaced, "-- after\n") {
		t.Fatalf("replaced:\n%s", replaced)
	}
	if removed := WithBlock(added, ""); removed != user {
		t.Fatalf("removed = %q, want %q", removed, user)
	}
	if WithBlock("", b1) != b1 || WithBlock(b1, "") != "" || WithBlock(user, "") != user {
		t.Fatal("edge cases")
	}
}

func TestBlockQuotesPaths(t *testing.T) {
	b := Block(`/Users/a "b"/init.lua`, `C:\asiri`, "owner")
	if !strings.Contains(b, `dofile("/Users/a \"b\"/init.lua")`) || !strings.Contains(b, `bin = "C:\\asiri"`) {
		t.Fatalf("block:\n%s", b)
	}
	if !strings.Contains(b, version) {
		t.Fatal("no version line")
	}
}

func TestInstallRollsBackWhenRexRejects(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "rex", "init.lua")
	t.Setenv("REX_CONFIG", config)
	os.MkdirAll(filepath.Dir(config), 0o755)
	user := "-- my config\n"
	os.WriteFile(config, []byte(user), 0o644)

	var calls []string
	ok := func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	res, err := Install(context.Background(), ok, "/bin/asiri", "owner")
	if err != nil || !res.Reloaded {
		t.Fatalf("install: %+v %v", res, err)
	}
	got, _ := os.ReadFile(config)
	if !strings.HasPrefix(string(got), user) || !strings.Contains(string(got), begin) {
		t.Fatalf("config:\n%s", got)
	}
	if p, _ := os.ReadFile(PluginPath(config)); string(p) != Source {
		t.Fatal("plugin not written")
	}
	if strings.Join(calls, "|") != "config check "+config+"|config reload" {
		t.Fatalf("rex calls %v", calls)
	}
	if inst, _, _ := Installed(); !inst {
		t.Fatal("Installed = false")
	}

	// Rex rejects a reinstall: the previous state comes back.
	before, _ := os.ReadFile(config)
	reject := func(_ context.Context, args ...string) error {
		if args[1] == "check" {
			return errors.New("syntax error")
		}
		return nil
	}
	if _, err := Install(context.Background(), reject, "/other/asiri", "owner"); err == nil {
		t.Fatal("rejected install succeeded")
	}
	if after, _ := os.ReadFile(config); string(after) != string(before) {
		t.Fatalf("not rolled back:\n%s", after)
	}

	if _, err := Uninstall(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(config); string(after) != user {
		t.Fatalf("after uninstall %q", after)
	}
	if _, err := os.Stat(PluginPath(config)); !os.IsNotExist(err) {
		t.Fatal("plugin left behind")
	}
}

// A fresh machine has no init.lua: install creates it, a rejected install
// removes it again.
func TestInstallWithoutConfig(t *testing.T) {
	config := filepath.Join(t.TempDir(), "rex", "init.lua")
	t.Setenv("REX_CONFIG", config)
	reject := func(_ context.Context, args ...string) error { return errors.New("no") }
	Install(context.Background(), reject, "/bin/asiri", "owner")
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("config left behind after rejected install")
	}
}

func TestInstalledWith(t *testing.T) {
	config := filepath.Join(t.TempDir(), "rex", "init.lua")
	t.Setenv("REX_CONFIG", config)
	if _, _, ok := InstalledWith(); ok {
		t.Fatal("reported installed with no config")
	}
	os.MkdirAll(filepath.Dir(config), 0o755)
	os.WriteFile(config, []byte("-- mine\n\n"+Block("/p/init.lua", `/Users/a "b"/asiri`, "personal")), 0o644)
	bin, profile, ok := InstalledWith()
	if !ok || bin != `/Users/a "b"/asiri` || profile != "personal" {
		t.Fatalf("got %q %q %v", bin, profile, ok)
	}
}
