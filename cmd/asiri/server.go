package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/client"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/pki"
	"github.com/gingered-cat/asiri/internal/server"
	"github.com/gingered-cat/asiri/internal/service"
	"github.com/gingered-cat/asiri/internal/vault"
)

const containerKeyFile = "/run/secrets/asiri_master"

func serverCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{"missing subcommand"}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return serverInit(ctx, rest)
	case "run":
		return serverRun(ctx, rest)
	case "keygen":
		return serverKeygen(rest)
	case "pair-code":
		return serverPairCode(ctx, rest)
	case "health":
		return serverHealth(ctx, rest)
	case "reset-approval-keys":
		return serverResetApprovalKeys(ctx, rest)
	}
	return usageError{fmt.Sprintf("unknown server subcommand %q", sub)}
}

func defaultDataDir() string {
	if v := os.Getenv("ASIRI_DATA"); v != "" {
		return v
	}
	if fi, err := os.Stat("/data"); err == nil && fi.IsDir() {
		return "/data"
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", "asiri")
	}
	return "asiri-data"
}

func defaultKeyFile() string {
	if v := os.Getenv("ASIRI_KEY_FILE"); v != "" {
		return v
	}
	if _, err := os.Stat(containerKeyFile); err == nil {
		return containerKeyFile
	}
	return ""
}

type serverFlags struct {
	data, keyFile, san string
}

func (f *serverFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.data, "data", defaultDataDir(), "data directory")
	fs.StringVar(&f.keyFile, "key-file", defaultKeyFile(), "master key file (key-file mode)")
	fs.StringVar(&f.san, "san", os.Getenv("ASIRI_SAN"), "extra comma-separated host names or IPs for the server certificate")
}

func (f *serverFlags) hosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	return append(hosts, splitList(f.san)...)
}

type opened struct {
	dd      server.DataDir
	store   *vault.Store
	svc     *service.Service
	ca      *pki.CA
	certPEM []byte
	keyPEM  []byte
}

func openServer(f *serverFlags) (*opened, error) {
	if err := os.MkdirAll(f.data, 0o700); err != nil {
		return nil, err
	}
	dd := server.DataDir(f.data)
	ca, certPEM, keyPEM, err := dd.EnsureTLS(f.hosts(), time.Now())
	if err != nil {
		return nil, err
	}
	store, err := vault.Open(dd.DB())
	if err != nil {
		return nil, err
	}
	svc := service.New(service.Config{Store: store, Vault: vault.New(store), CA: ca, KeyFile: f.keyFile})
	return &opened{dd: dd, store: store, svc: svc, ca: ca, certPEM: certPEM, keyPEM: keyPEM}, nil
}

func serverInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server init", flag.ContinueOnError)
	var f serverFlags
	f.register(fs)
	pass := fs.Bool("passphrase", false, "protect the vault with a passphrase instead of a key file")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	o, err := openServer(&f)
	if err != nil {
		return err
	}
	defer o.store.Close()
	if err := initVault(ctx, o.svc, f.keyFile, *pass); err != nil {
		return err
	}
	fmt.Printf("initialized %s\nnext: asiri server run, then asiri server pair-code\n", o.dd.DB())
	return nil
}

func initVault(ctx context.Context, svc *service.Service, keyFile string, passphrase bool) error {
	if passphrase {
		p1, err := readHidden("new vault passphrase: ")
		if err != nil {
			return err
		}
		defer clear(p1)
		if len(p1) < 12 {
			return errors.New("use at least 12 characters (a few random words is good)")
		}
		p2, err := readHidden("again: ")
		if err != nil {
			return err
		}
		defer clear(p2)
		if !bytes.Equal(p1, p2) {
			return errors.New("the passphrases don't match")
		}
		return svc.Init(ctx, vault.NewKDF(vault.ModePassphrase), p1)
	}
	if keyFile == "" {
		return usageError{"pass --key-file PATH (make one with `asiri server keygen -o PATH`) or --passphrase"}
	}
	k, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		return err
	}
	defer clear(k)
	return svc.Init(ctx, vault.NewKDF(vault.ModeKeyFile), k)
}

func serverRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server run", flag.ContinueOnError)
	var f serverFlags
	f.register(fs)
	listen := fs.String("listen", envOr("ASIRI_LISTEN", "127.0.0.1:"+api.DefaultPort), "address to listen on")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	o, err := openServer(&f)
	if err != nil {
		return err
	}
	defer o.store.Close()

	initialized, err := o.svc.Initialized(ctx)
	if err != nil {
		return err
	}
	switch {
	case !initialized && f.keyFile != "":
		log.Info("first start: initializing the vault with the key file", "key_file", f.keyFile)
		if err := initVault(ctx, o.svc, f.keyFile, false); err != nil {
			return err
		}
	case !initialized:
		return errors.New("the vault is not initialized: run `asiri server init --key-file PATH` or `asiri server init --passphrase`")
	case f.keyFile != "":
		if err := o.svc.Unlock(ctx, "", nil); err != nil && domain.CodeOf(err) != domain.CodeInvalid {
			return fmt.Errorf("unlock with %s: %w", f.keyFile, err)
		} else if err != nil {
			log.Warn("starting locked", "reason", err)
		}
	}
	if o.svc.Sealed() {
		log.Info("the vault is locked; run `asiri unlock` on the host")
	}

	tc, err := server.TLSConfig(o.certPEM, o.keyPEM, o.ca)
	if err != nil {
		return err
	}
	o.svc.Start(ctx) // expires requests nobody answered
	hs := server.New(o.svc, log).HTTPServer(*listen, tc)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Info("asiri server listening", "addr", ln.Addr().String(), "version", server.Version, "data", f.data)
	errc := make(chan error, 1)
	go func() { errc <- hs.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}
	o.svc.Lock(context.Background(), "")
	return nil
}

func serverKeygen(args []string) error {
	fset := flag.NewFlagSet("server keygen", flag.ContinueOnError)
	out := fset.String("o", "", "write the key file here (0600); default stdout")
	if _, err := parse(fset, args); err != nil {
		return err
	}
	key := vault.NewKeyFile()
	defer clear(key)
	if *out == "" {
		_, err := os.Stdout.Write(key)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; asiri won't overwrite a key file", *out)
	}
	if err != nil {
		return err
	}
	if _, err := fh.Write(key); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\nback it up somewhere safe: without it the vault can't be opened\n", *out)
	return nil
}

func serverPairCode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server pair-code", flag.ContinueOnError)
	var f serverFlags
	f.register(fs)
	name := fs.String("name", "owner", "client name")
	role := fs.String("role", "owner", "owner or agent")
	replace := fs.Bool("replace", false, "pair again even if the client exists (e.g. a lost laptop)")
	serverURL := fs.String("server", "https://127.0.0.1:"+api.DefaultPort, "server URL to print in the pair command")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	o, err := openServer(&f)
	if err != nil {
		return err
	}
	defer o.store.Close()
	pc, err := o.svc.CreatePairCode(ctx, "", *name, domain.Role(*role), *replace)
	if err != nil {
		return err
	}
	printPairCode(pc, *serverURL)
	return nil
}

func printPairCode(pc api.PairCode, serverURL string) {
	profile := ""
	if pc.Name != client.DefaultProfile {
		profile = " --profile " + pc.Name
	}
	fmt.Printf("pairing code for %q (%s), valid until %s:\n\n  %s\n\non the machine to pair, run:\n\n  asiri pair --server %s%s --code %s\n",
		pc.Name, pc.Role, pc.ExpiresAt.Local().Format("15:04"), pc.Code, serverURL, profile, pc.Code)
}

func serverHealth(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server health", flag.ContinueOnError)
	u := fs.String("url", "https://127.0.0.1:"+api.DefaultPort, "server URL")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	h, err := client.HealthInsecure(ctx, *u)
	if err != nil {
		return err
	}
	fmt.Printf("ok %s initialized=%t sealed=%t\n", h.Version, h.Initialized, h.Sealed)
	return nil
}

// serverResetApprovalKeys revokes every approval key, for a lost or replaced
// Mac. It works on the data directory directly, like pair-code, so it needs
// access to where the server runs (docker compose exec asiri asiri server
// reset-approval-keys), not just an owner profile.
func serverResetApprovalKeys(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server reset-approval-keys", flag.ContinueOnError)
	var f serverFlags
	f.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	o, err := openServer(&f)
	if err != nil {
		return err
	}
	defer o.store.Close()
	n, err := o.svc.ResetApprovalKeys(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("revoked %d approval key(s); an owner profile can approve without Touch ID until you run `asiri touchid enroll` again\n", n)
	return nil
}
