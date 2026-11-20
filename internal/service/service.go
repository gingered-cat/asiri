// Package service is Asiri's server-side logic: items, clients, pairing and
// sealing. It owns transactions, so every state change and its audit row
// commit together.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/pki"
	"github.com/gingered-cat/asiri/internal/vault"
)

// PairCodeTTL is how long a pairing code works.
const PairCodeTTL = 10 * time.Minute

type Config struct {
	Store   *vault.Store
	Vault   *vault.Vault
	CA      *pki.CA
	KeyFile string           // key-file mode: where to re-read the key on unlock
	Now     func() time.Time // defaults to time.Now
	// FailDelay slows down wrong passphrases and pairing codes. Defaults to 1s.
	FailDelay time.Duration
}

type Service struct {
	store     *vault.Store
	vault     *vault.Vault
	ca        *pki.CA
	keyFile   string
	now       func() time.Time
	failDelay time.Duration
}

func New(c Config) *Service {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.FailDelay == 0 {
		c.FailDelay = time.Second
	}
	return &Service{store: c.Store, vault: c.Vault, ca: c.CA, keyFile: c.KeyFile, now: c.Now, failDelay: c.FailDelay}
}

func (s *Service) fail() { time.Sleep(s.failDelay) }

func (s *Service) record(ctx context.Context, by domain.ClientID, event string, detail map[string]string) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by, Event: event, Detail: detail})
	})
}

// ---- sealing ----

func (s *Service) Initialized(ctx context.Context) (bool, error) { return s.vault.Initialized(ctx) }
func (s *Service) Sealed() bool                                  { return s.vault.Sealed() }

// Init creates the vault and leaves it unsealed.
func (s *Service) Init(ctx context.Context, kdf vault.KDF, secret []byte) error {
	var vk []byte
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if vk, err = s.vault.InitTx(ctx, tx, kdf, secret); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{Event: audit.Init,
			Detail: map[string]string{"mode": kdf.Mode}})
	})
	if err != nil {
		return err
	}
	s.vault.Unseal(vk)
	return nil
}

// Unlock unseals the vault. In key-file mode the passphrase is ignored and
// the configured key file is read again.
func (s *Service) Unlock(ctx context.Context, by domain.ClientID, passphrase []byte) error {
	mode, err := s.vault.Mode(ctx)
	if err != nil {
		return err
	}
	secret := passphrase
	if mode == vault.ModeKeyFile {
		if s.keyFile == "" {
			return domain.Errorf(domain.CodeInvalid, "this vault uses a key file, and the server was started without --key-file")
		}
		if secret, err = vault.ReadKeyFile(s.keyFile); err != nil {
			return domain.Errorf(domain.CodeInvalid, "%v", err)
		}
		defer clear(secret)
	}
	if err := s.vault.Unlock(ctx, secret); err != nil {
		s.record(ctx, by, audit.UnlockFailed, nil)
		s.fail()
		return err
	}
	return s.record(ctx, by, audit.Unlock, map[string]string{"mode": mode})
}

func (s *Service) Lock(ctx context.Context, by domain.ClientID) error {
	s.vault.Seal()
	return s.record(ctx, by, audit.Lock, nil)
}

// ---- items ----

func (s *Service) PutItem(ctx context.Context, by domain.Client, ref domain.Ref, kind domain.Kind, sec domain.Secret) (domain.Item, error) {
	if sec.Len() == 0 {
		return domain.Item{}, domain.Errorf(domain.CodeInvalid, "empty value")
	}
	if sec.Len() > 64<<10 {
		return domain.Item{}, domain.Errorf(domain.CodeInvalid, "value is larger than 64 KiB")
	}
	var it domain.Item
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if it, err = s.vault.PutTx(ctx, tx, ref, kind, sec, s.now()); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by.ID, Event: audit.ItemPut, ItemID: it.ID,
			Detail: map[string]string{"ref": ref.String(), "version": strconv.Itoa(it.Version), "kind": string(it.Kind)}})
	})
	return it, err
}

func (s *Service) ListItems(ctx context.Context, query string) ([]domain.Item, error) {
	if s.vault.Sealed() {
		return nil, vault.ErrSealed
	}
	return s.vault.List(ctx, query)
}

// ---- clients and pairing ----

var clientName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

var errBadCode = domain.Errorf(domain.CodeNotAllowed, "pairing code is wrong, used or expired")

// CreatePairCode makes a one-time code that pairs a CLI profile as name with
// role. by is empty when the code is made from inside the server container.
func (s *Service) CreatePairCode(ctx context.Context, by domain.ClientID, name string, role domain.Role, replace bool) (api.PairCode, error) {
	if !clientName.MatchString(name) {
		return api.PairCode{}, domain.Errorf(domain.CodeInvalid, "client name %q: use 1-32 lowercase letters, digits, '.', '_' or '-'", name)
	}
	if !role.Valid() {
		return api.PairCode{}, domain.Errorf(domain.CodeInvalid, "role %q: want owner or agent", role)
	}
	secret := newCodeSecret()
	exp := s.now().Add(PairCodeTTL)
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		if !replace {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE name = ? AND revoked_at IS NULL`, name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return domain.Errorf(domain.CodeConflict, "client %q already exists; pass --replace to pair it again", name)
			}
		}
		h := codeHash(secret)
		if _, err := tx.ExecContext(ctx, `INSERT INTO pair_codes (hash, name, role, expires_at) VALUES (?, ?, ?, ?)`,
			h[:], name, role, exp.UnixMilli()); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by, Event: audit.PairCode,
			Detail: map[string]string{"name": name, "role": string(role)}})
	})
	if err != nil {
		return api.PairCode{}, err
	}
	code := s.ca.Fingerprint()[:pki.CodePrefixLen] + "-" + secret[0:4] + "-" + secret[4:8] + "-" + secret[8:12] + "-" + secret[12:16]
	return api.PairCode{Code: code, Name: name, Role: role, ExpiresAt: exp.UTC()}, nil
}

// Pair spends a code and signs csrPEM as that code's client.
func (s *Service) Pair(ctx context.Context, code, csrPEM string) (api.PairResponse, error) {
	fp, secret, ok := strings.Cut(strings.TrimSpace(code), "-")
	if !ok || subtle.ConstantTimeCompare([]byte(strings.ToLower(fp)), []byte(s.ca.Fingerprint()[:pki.CodePrefixLen])) != 1 {
		s.fail()
		return api.PairResponse{}, domain.Errorf(domain.CodeInvalid, "this code is for a different asiri server")
	}
	h := codeHash(normalizeCode(secret))
	var resp api.PairResponse
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		var (
			name, role string
			exp        int64
			used       sql.NullInt64
		)
		err := tx.QueryRowContext(ctx, `SELECT name, role, expires_at, used_at FROM pair_codes WHERE hash = ?`, h[:]).
			Scan(&name, &role, &exp, &used)
		if errors.Is(err, sql.ErrNoRows) || used.Valid || s.now().UnixMilli() > exp {
			return errBadCode
		}
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE pair_codes SET used_at = ? WHERE hash = ?`, now.UnixMilli(), h[:]); err != nil {
			return err
		}
		certPEM, err := s.ca.IssueClient([]byte(csrPEM), name, now)
		if err != nil {
			return domain.Errorf(domain.CodeInvalid, "%v", err)
		}
		cert, err := pki.ParseCert(certPEM)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO clients (id, name, role, cert_fp, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET role = excluded.role, cert_fp = excluded.cert_fp,
			  created_at = excluded.created_at, revoked_at = NULL`,
			domain.NewID(), name, role, pki.Fingerprint(cert), now.UnixMilli()); err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM clients WHERE name = ?`, name).Scan(&id); err != nil {
			return err
		}
		resp = api.PairResponse{Name: name, Role: domain.Role(role), Cert: string(certPEM), CA: string(s.ca.CertPEM)}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: domain.ClientID(id), Event: audit.Pair,
			Detail: map[string]string{"name": name, "role": role}})
	})
	if errors.Is(err, errBadCode) {
		s.fail()
	}
	return resp, err
}

// ClientByFingerprint finds the active client for a certificate.
func (s *Service) ClientByFingerprint(ctx context.Context, fp string) (domain.Client, error) {
	var (
		c       domain.Client
		created int64
		revoked sql.NullInt64
	)
	err := s.store.R().QueryRowContext(ctx,
		`SELECT id, name, role, created_at, revoked_at FROM clients WHERE cert_fp = ?`, fp).
		Scan(&c.ID, &c.Name, &c.Role, &created, &revoked)
	if errors.Is(err, sql.ErrNoRows) || revoked.Valid {
		return domain.Client{}, domain.Errorf(domain.CodeUnauthenticated, "this client is not paired or was revoked; run `asiri pair`")
	}
	if err != nil {
		return domain.Client{}, err
	}
	c.CertFP = fp
	c.CreatedAt = time.UnixMilli(created).UTC()
	return c, nil
}

func (s *Service) ListClients(ctx context.Context) ([]domain.Client, error) {
	rows, err := s.store.R().QueryContext(ctx,
		`SELECT id, name, role, created_at, revoked_at FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Client{}
	for rows.Next() {
		var (
			c       domain.Client
			created int64
			revoked sql.NullInt64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Role, &created, &revoked); err != nil {
			return nil, err
		}
		c.CreatedAt = time.UnixMilli(created).UTC()
		if revoked.Valid {
			t := time.UnixMilli(revoked.Int64).UTC()
			c.RevokedAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeClient stops name's certificate from working. The last owner can't
// be revoked from the API; use `asiri server pair-code` in the container.
func (s *Service) RevokeClient(ctx context.Context, by domain.ClientID, name string) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		var role string
		err := tx.QueryRowContext(ctx, `SELECT role FROM clients WHERE name = ? AND revoked_at IS NULL`, name).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Errorf(domain.CodeNotFound, "no active client named %q", name)
		}
		if err != nil {
			return err
		}
		if role == string(domain.RoleOwner) {
			var owners int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE role = 'owner' AND revoked_at IS NULL`).Scan(&owners); err != nil {
				return err
			}
			if owners == 1 {
				return domain.Errorf(domain.CodeNotAllowed, "%q is the last owner; pair another owner first", name)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE clients SET revoked_at = ? WHERE name = ?`, s.now().UnixMilli(), name); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by, Event: audit.ClientRevoke,
			Detail: map[string]string{"name": name}})
	})
}

// ---- audit ----

func (s *Service) Audit(ctx context.Context, since int64, limit int) ([]domain.AuditEvent, error) {
	return audit.List(ctx, s.store.R(), since, limit)
}

func (s *Service) VerifyAudit(ctx context.Context) (int64, error) {
	n, err := audit.Verify(ctx, s.store.R())
	if err != nil && !errors.Is(err, context.Canceled) {
		return n, domain.Errorf(domain.CodeConflict, "%v", err)
	}
	return n, err
}

// ---- codes ----

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newCodeSecret returns 16 Crockford base32 characters (80 random bits).
func newCodeSecret() string {
	var b [16]byte
	rand.Read(b[:])
	out := make([]byte, 16)
	for i := range out {
		out[i] = crockford[b[i]&31]
	}
	return string(out)
}

// normalizeCode accepts lowercase, dashes, spaces and the usual look-alikes.
func normalizeCode(s string) string {
	r := strings.NewReplacer("-", "", " ", "", "I", "1", "L", "1", "O", "0")
	return r.Replace(strings.ToUpper(s))
}

func codeHash(secret string) [32]byte { return sha256.Sum256([]byte("asiri pair v1|" + secret)) }
