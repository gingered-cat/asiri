package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/pki"
)

// Client calls the server as one profile, over mTLS with the CA pinned.
type Client struct {
	base string
	http *http.Client
}

func New(p *Profile) (*Client, error) {
	caPEM, err := os.ReadFile(p.file("ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s: bad CA certificate", p.file("ca.crt"))
	}
	pair, err := tls.LoadX509KeyPair(p.file("client.crt"), p.file("client.key"))
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}
	return &Client{base: strings.TrimRight(p.Server, "/"), http: newHTTP(tc)}, nil
}

func newHTTP(tc *tls.Config) *http.Client {
	return &http.Client{Timeout: 70 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	return call(ctx, c.http, method, c.base+path, in, out)
}

func call(ctx context.Context, hc *http.Client, method, u string, in, out any) error {
	var body io.Reader
	var raw []byte
	if in != nil {
		var err error
		if raw, err = json.Marshal(in); err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	clear(raw) // the body may have held a secret
	if err != nil {
		return unreachable(u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var eb api.ErrorBody
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&eb) == nil && eb.Error.Code != "" {
			return &domain.Error{Code: eb.Error.Code, Msg: eb.Error.Message}
		}
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func unreachable(u string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	host := u
	if p, perr := url.Parse(u); perr == nil {
		host = p.Host
	}
	return fmt.Errorf("asiri server not reachable at %s: %w", host, err)
}

func (c *Client) Health(ctx context.Context) (api.Health, error) {
	var h api.Health
	return h, c.do(ctx, "GET", "/v1/health", nil, &h)
}

func (c *Client) WhoAmI(ctx context.Context) (api.WhoAmI, error) {
	var w api.WhoAmI
	return w, c.do(ctx, "GET", "/v1/whoami", nil, &w)
}

func (c *Client) ListItems(ctx context.Context, query string) ([]domain.Item, error) {
	var r api.ItemsResponse
	return r.Items, c.do(ctx, "GET", "/v1/items?q="+url.QueryEscape(query), nil, &r)
}

// PutItem sends value; the caller should zero it afterwards.
func (c *Client) PutItem(ctx context.Context, ref domain.Ref, kind domain.Kind, value domain.Secret) (domain.Item, error) {
	var r api.ItemResponse
	path := "/v1/items/" + url.PathEscape(ref.Vault) + "/" + url.PathEscape(ref.Name)
	return r.Item, c.do(ctx, "PUT", path, api.PutItemRequest{Field: ref.Field, Kind: kind, Value: value.Reveal()}, &r)
}

func (c *Client) Unlock(ctx context.Context, passphrase []byte) (api.Health, error) {
	var h api.Health
	return h, c.do(ctx, "POST", "/v1/unlock", api.UnlockRequest{Passphrase: passphrase}, &h)
}

func (c *Client) Lock(ctx context.Context) (api.Health, error) {
	var h api.Health
	return h, c.do(ctx, "POST", "/v1/lock", struct{}{}, &h)
}

func (c *Client) CreateClient(ctx context.Context, name string, role domain.Role, replace bool) (api.PairCode, error) {
	var pc api.PairCode
	return pc, c.do(ctx, "POST", "/v1/clients", api.CreateClientRequest{Name: name, Role: role, Replace: replace}, &pc)
}

func (c *Client) ListClients(ctx context.Context) ([]domain.Client, error) {
	var r api.ClientsResponse
	return r.Clients, c.do(ctx, "GET", "/v1/clients", nil, &r)
}

func (c *Client) RevokeClient(ctx context.Context, name string) error {
	return c.do(ctx, "POST", "/v1/clients/"+url.PathEscape(name)+"/revoke", struct{}{}, nil)
}

func (c *Client) Audit(ctx context.Context, since int64, limit int) ([]domain.AuditEvent, error) {
	var r api.AuditResponse
	q := "?since=" + strconv.FormatInt(since, 10) + "&limit=" + strconv.Itoa(limit)
	return r.Events, c.do(ctx, "GET", "/v1/audit"+q, nil, &r)
}

func (c *Client) VerifyAudit(ctx context.Context) (int64, error) {
	var r api.VerifyResponse
	return r.Rows, c.do(ctx, "GET", "/v1/audit/verify", nil, &r)
}

// Pair spends a pairing code and saves a new profile. The code's prefix pins
// the server's CA fingerprint, so a different server is refused before the
// code is sent.
func Pair(ctx context.Context, server, code, profile string, force bool) (*Profile, api.PairResponse, error) {
	dir, err := profileDir(profile)
	if err != nil {
		return nil, api.PairResponse{}, err
	}
	if _, err := os.Stat(dir); err == nil && !force {
		return nil, api.PairResponse{}, fmt.Errorf("profile %q already exists at %s; pass --force to replace it", profile, dir)
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, api.PairResponse{}, fmt.Errorf("server %q: want https://host:port", server)
	}
	fp, _, ok := strings.Cut(strings.TrimSpace(code), "-")
	fp = strings.ToLower(fp)
	if !ok || len(fp) != pki.CodePrefixLen {
		return nil, api.PairResponse{}, fmt.Errorf("that doesn't look like an asiri pairing code")
	}
	var pinned *x509.Certificate
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyConnection: pin the CA from the code
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if c.IsCA && strings.HasPrefix(pki.Fingerprint(c), fp) {
					pinned = c
				}
			}
			if pinned == nil || len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("the server's CA does not match this code; is %s the right server?", u.Host)
			}
			pool := x509.NewCertPool()
			pool.AddCert(pinned)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: u.Hostname()})
			return err
		},
	}
	keyPEM, csrPEM, err := pki.NewClientKey()
	if err != nil {
		return nil, api.PairResponse{}, err
	}
	var resp api.PairResponse
	if err := call(ctx, newHTTP(tc), "POST", u.String()+"/v1/pair", api.PairRequest{Code: code, CSR: string(csrPEM)}, &resp); err != nil {
		return nil, api.PairResponse{}, err
	}
	gotCA, err := pki.ParseCert([]byte(resp.CA))
	if err != nil || pki.Fingerprint(gotCA) != pki.Fingerprint(pinned) {
		return nil, api.PairResponse{}, errors.New("the server returned a different CA than it presented")
	}
	p := &Profile{Name: profile, Dir: dir, Server: u.String()}
	if err := p.save([]byte(resp.CA), []byte(resp.Cert), keyPEM); err != nil {
		return nil, api.PairResponse{}, err
	}
	return p, resp, nil
}

// HealthInsecure checks a server without a profile. It is only used for the
// container health check; it reads no secrets.
func HealthInsecure(ctx context.Context, server string) (api.Health, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	var h api.Health
	return h, call(ctx, newHTTP(tc), "GET", strings.TrimRight(server, "/")+"/v1/health", nil, &h)
}

// SetPolicy replaces ref's policy.
func (c *Client) SetPolicy(ctx context.Context, ref domain.Ref, p domain.Policy) (domain.Item, error) {
	var r api.ItemResponse
	path := "/v1/items/" + url.PathEscape(ref.Vault) + "/" + url.PathEscape(ref.Name) + "/policy"
	return r.Item, c.do(ctx, "PUT", path, api.PolicyRequest{Field: ref.Field, Bins: p.Bins, SSHHosts: p.SSHHosts, MaxGrant: p.MaxGrant}, &r)
}

// GenerateSSHKey makes an Ed25519 key inside the server.
func (c *Client) GenerateSSHKey(ctx context.Context, ref domain.Ref) (domain.Item, error) {
	var r api.ItemResponse
	path := "/v1/items/" + url.PathEscape(ref.Vault) + "/" + url.PathEscape(ref.Name) + "/ssh-key"
	return r.Item, c.do(ctx, "POST", path, api.GenerateSSHKey{Field: ref.Field}, &r)
}

func (c *Client) SSHKeys(ctx context.Context) ([]domain.Item, error) {
	var r api.ItemsResponse
	return r.Items, c.do(ctx, "GET", "/v1/ssh/keys", nil, &r)
}

func (c *Client) SSHSign(ctx context.Context, gid domain.GrantID, data []byte, flags uint32) (api.SSHSignature, error) {
	var r api.SSHSignature
	return r, c.do(ctx, "POST", "/v1/ssh/sign", api.SSHSignRequest{GrantID: gid, Data: data, Flags: flags}, &r)
}

func (c *Client) CreateRequest(ctx context.Context, req api.CreateRequest) (api.RequestResponse, error) {
	var r api.RequestResponse
	return r, c.do(ctx, "POST", "/v1/requests", req, &r)
}

// Request returns a request, waiting up to wait for it to stop being pending.
func (c *Client) Request(ctx context.Context, id domain.RequestID, wait time.Duration) (domain.Request, error) {
	var r api.RequestResponse
	q := ""
	if wait > 0 {
		q = "?wait=" + wait.String()
	}
	return r.Request, c.do(ctx, "GET", "/v1/requests/"+url.PathEscape(string(id))+q, nil, &r)
}

func (c *Client) PendingRequests(ctx context.Context) ([]domain.Request, error) {
	var r api.RequestsResponse
	return r.Requests, c.do(ctx, "GET", "/v1/requests", nil, &r)
}

// Decide records a decision. On a conflict it returns the request as it now
// stands along with the error.
func (c *Client) Decide(ctx context.Context, id domain.RequestID, d domain.Decision, m domain.Method) (domain.Request, error) {
	var r api.RequestResponse
	err := c.do(ctx, "POST", "/v1/requests/"+url.PathEscape(string(id))+"/decision", api.DecisionRequest{Decision: d, Method: m}, &r)
	if domain.CodeOf(err) == domain.CodeConflict {
		cur, gerr := c.Request(ctx, id, 0)
		if gerr == nil {
			return cur, err
		}
	}
	return r.Request, err
}

// Redeem spends a grant. The caller must Zero the returned secret.
func (c *Client) Redeem(ctx context.Context, id domain.GrantID) (domain.Grant, domain.Secret, error) {
	var r api.RedeemResponse
	err := c.do(ctx, "POST", "/v1/grants/"+url.PathEscape(string(id))+"/redeem", struct{}{}, &r)
	return r.Grant, domain.NewSecret(r.Value), err
}

func (c *Client) ReportScrub(ctx context.Context, id domain.GrantID, hits int) error {
	return c.do(ctx, "POST", "/v1/grants/"+url.PathEscape(string(id))+"/scrub", api.ScrubReport{Hits: hits}, nil)
}

func (c *Client) Grants(ctx context.Context) ([]domain.Grant, error) {
	var r api.GrantsResponse
	return r.Grants, c.do(ctx, "GET", "/v1/grants", nil, &r)
}

func (c *Client) RevokeGrant(ctx context.Context, id domain.GrantID) error {
	return c.do(ctx, "POST", "/v1/grants/"+url.PathEscape(string(id))+"/revoke", struct{}{}, nil)
}

func (c *Client) RevokeAll(ctx context.Context) (int, error) {
	var r api.RevokeAllResponse
	return r.Revoked, c.do(ctx, "POST", "/v1/revoke-all", struct{}{}, &r)
}
