package service

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/vault"
)

// PendingTTL is how long a request waits for a decision.
const PendingTTL = 120 * time.Second

// RequestInput is what the CLI sends when it wants to use a secret.
type RequestInput struct {
	Ref       domain.Ref
	BinPath   string
	BinSHA256 string
	Argv      []string
	Cwd       string
	Reason    string
}

// CreateRequest checks the rules and either reuses a live timed grant for
// the same client, item and binary, or opens a pending request.
func (s *Service) CreateRequest(ctx context.Context, by domain.Client, in RequestInput) (domain.Request, bool, error) {
	if s.vault.Sealed() {
		return domain.Request{}, false, vault.ErrSealed
	}
	now := s.now()
	if ok, report := s.limit.allow(by.ID, now); !ok {
		if report {
			s.record(ctx, by.ID, audit.Anomaly, map[string]string{"reason": "request rate limit", "ref": in.Ref.String()})
		}
		return domain.Request{}, false, domain.Errorf(domain.CodeRateLimited, "too many requests from %q; slow down", by.Name)
	}
	item, err := s.vault.Lookup(ctx, in.Ref)
	if err != nil {
		return domain.Request{}, false, err
	}
	for _, rule := range s.rules {
		if err := rule(RuleInput{Client: by, Item: item, In: in}); err != nil {
			s.record(ctx, by.ID, audit.Rejected, map[string]string{
				"ref": in.Ref.String(), "bin": filepath.Base(in.BinPath), "code": string(domain.CodeOf(err))})
			return domain.Request{}, false, err
		}
	}

	var gid, rid string
	err = s.store.R().QueryRowContext(ctx, `SELECT id, request_id FROM grants
		WHERE client_id = ? AND item_id = ? AND bin_sha256 = ? AND revoked_at IS NULL
		  AND expires_at > ? AND uses_left IS NULL ORDER BY expires_at DESC LIMIT 1`,
		by.ID, item.ID, in.BinSHA256, now.UnixMilli()).Scan(&gid, &rid)
	if err == nil {
		r, err := s.GetRequest(ctx, by, domain.RequestID(rid))
		return r, true, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Request{}, false, err
	}

	argv := s.argvPreview(ctx, item, in.BinPath, in.Argv)
	id := domain.RequestID(domain.NewID())
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO requests
			(id, client_id, item_id, ref, bin_path, bin_sha256, argv, cwd, reason, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
			id, by.ID, item.ID, item.Ref.String(), in.BinPath, in.BinSHA256, argv, clip(in.Cwd, 200),
			clip(in.Reason, 200), now.UnixMilli()); err != nil {
			return err
		}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by.ID, Event: audit.Request, ItemID: item.ID,
			Detail: map[string]string{"request": string(id), "ref": item.Ref.String(), "bin": filepath.Base(in.BinPath)}})
	})
	if err != nil {
		return domain.Request{}, false, err
	}
	r, err := s.GetRequest(ctx, by, id)
	return r, false, err
}

// argvPreview renders the command for the approval prompt, at most 200
// characters, with the item's value scrubbed if the caller put it in argv.
func (s *Service) argvPreview(ctx context.Context, item domain.Item, bin string, args []string) string {
	parts := []string{filepath.Base(bin)}
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$`") {
			a = strconv.Quote(a)
		}
		parts = append(parts, a)
	}
	out := []byte(strings.Join(parts, " "))
	if _, sec, err := s.vault.GetByID(ctx, item.ID); err == nil {
		if v := sec.Reveal(); len(v) >= 4 {
			out = bytes.ReplaceAll(out, v, []byte("[asiri:"+item.Ref.String()+"]"))
		}
		sec.Zero()
	}
	return clip(string(out), 200)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

const requestCols = `r.id, r.client_id, COALESCE(c.name, ''), r.ref, r.item_id, r.bin_path, r.argv, r.cwd, r.reason,
	r.status, r.decision, r.method, COALESCE(g.id, ''), r.created_at
	FROM requests r LEFT JOIN clients c ON c.id = r.client_id LEFT JOIN grants g ON g.request_id = r.id`

type scanner interface{ Scan(...any) error }

func scanRequest(row scanner) (domain.Request, error) {
	var (
		r       domain.Request
		ref     string
		created int64
	)
	if err := row.Scan(&r.ID, &r.ClientID, &r.ClientName, &ref, &r.ItemID, &r.BinPath, &r.Argv, &r.Cwd, &r.Reason,
		&r.Status, &r.Decision, &r.Method, &r.GrantID, &created); err != nil {
		return domain.Request{}, err
	}
	r.Ref, _ = domain.ParseRef(ref)
	r.CreatedAt = time.UnixMilli(created).UTC()
	r.ExpiresAt = r.CreatedAt.Add(PendingTTL)
	r.Title = fmt.Sprintf("%s wants %s", r.ClientName, r.Ref)
	r.Detail = r.Argv
	if r.Cwd != "" {
		r.Detail += " · " + r.Cwd
	}
	if r.Reason != "" {
		r.Detail += " · " + strconv.Quote(r.Reason)
	}
	return r, nil
}

// GetRequest returns a request to the client that made it, or to an owner.
func (s *Service) GetRequest(ctx context.Context, by domain.Client, id domain.RequestID) (domain.Request, error) {
	r, err := scanRequest(s.store.R().QueryRowContext(ctx, `SELECT `+requestCols+` WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && by.Role != domain.RoleOwner && r.ClientID != by.ID) {
		return domain.Request{}, domain.Errorf(domain.CodeNotFound, "no request %s", id)
	}
	return r, err
}

// WaitRequest returns the request once it is no longer pending, or after
// timeout, whichever comes first.
func (s *Service) WaitRequest(ctx context.Context, by domain.Client, id domain.RequestID, timeout time.Duration) (domain.Request, error) {
	ch, unsubscribe := s.broker.subscribe(id)
	defer unsubscribe()
	r, err := s.GetRequest(ctx, by, id)
	if err != nil || r.Status != domain.StatusPending || timeout <= 0 {
		return r, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
		return r, ctx.Err()
	}
	return s.GetRequest(ctx, by, id)
}

// PendingRequests lists requests waiting for a decision, oldest first.
func (s *Service) PendingRequests(ctx context.Context) ([]domain.Request, error) {
	rows, err := s.store.R().QueryContext(ctx, `SELECT `+requestCols+` WHERE r.status = 'pending' ORDER BY r.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Request{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Decide records the first decision for a pending request. Later decisions
// get a conflict error and the request as it now stands. Only owners decide:
// an agent can never approve its own request, so approvals come from the
// person's own profile (the Rex plugin or `asiri approve`).
func (s *Service) Decide(ctx context.Context, by domain.Client, id domain.RequestID, d domain.Decision, m domain.Method) (domain.Request, error) {
	if !d.Valid() || !m.Valid() {
		return domain.Request{}, domain.Errorf(domain.CodeInvalid, "decision %q / method %q", d, m)
	}
	if by.Role != domain.RoleOwner {
		return domain.Request{}, domain.Errorf(domain.CodeNotAllowed,
			"%q is an agent and can't approve requests; approve as the owner (Rex, or `asiri approve`)", by.Name)
	}
	cur, err := s.GetRequest(ctx, by, id)
	if err != nil {
		return domain.Request{}, err
	}
	now := s.now()
	if cur.Status == domain.StatusPending && now.After(cur.ExpiresAt) {
		s.ExpireRequests(ctx)
		cur, _ = s.GetRequest(ctx, by, id)
	}
	if cur.Status != domain.StatusPending {
		return cur, domain.Errorf(domain.CodeConflict, "request was already %s", cur.Status)
	}
	item, err := s.vault.Lookup(ctx, cur.Ref)
	if err != nil {
		return domain.Request{}, err
	}
	eff := d.Clamp(item.Policy.MaxGrant)
	status := domain.StatusApproved
	if d == domain.DecideDeny {
		status = domain.StatusDenied
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE requests SET status = ?, decision = ?, method = ?, decided_at = ?
			WHERE id = ? AND status = 'pending'`, status, eff, m, now.UnixMilli(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return domain.Errorf(domain.CodeConflict, "request was already decided")
		}
		detail := map[string]string{"request": string(id), "decision": string(eff), "method": string(m), "ref": cur.Ref.String()}
		if eff != d {
			detail["asked"] = string(d)
		}
		if status == domain.StatusApproved {
			var usesLeft any // NULL: timed grant
			if eff == domain.DecideOnce {
				usesLeft = 1
			}
			gid := domain.NewID()
			var sha string
			if err := tx.QueryRowContext(ctx, `SELECT bin_sha256 FROM requests WHERE id = ?`, id).Scan(&sha); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO grants (id, request_id, client_id, item_id, ref, bin_path,
				bin_sha256, decision, method, uses_left, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				gid, id, cur.ClientID, cur.ItemID, cur.Ref.String(), cur.BinPath, sha, eff, m, usesLeft,
				now.UnixMilli(), now.Add(eff.Duration()).UnixMilli()); err != nil {
				return err
			}
			detail["grant"] = gid
		}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by.ID, Event: audit.Decision, ItemID: cur.ItemID, Detail: detail})
	})
	if domain.CodeOf(err) == domain.CodeConflict {
		cur, _ = s.GetRequest(ctx, by, id)
		return cur, err
	}
	if err != nil {
		return domain.Request{}, err
	}
	s.broker.publish(id)
	return s.GetRequest(ctx, by, id)
}

// ExpireRequests expires pending requests older than PendingTTL.
func (s *Service) ExpireRequests(ctx context.Context) (int, error) {
	now := s.now()
	var ids []domain.RequestID
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `UPDATE requests SET status = 'expired', decided_at = ?
			WHERE status = 'pending' AND created_at < ? RETURNING id, client_id, item_id`,
			now.UnixMilli(), now.Add(-PendingTTL).UnixMilli())
		if err != nil {
			return err
		}
		type row struct{ id, client, item string }
		var expired []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.client, &r.item); err != nil {
				rows.Close()
				return err
			}
			expired = append(expired, r)
		}
		rows.Close()
		for _, r := range expired {
			ids = append(ids, domain.RequestID(r.id))
			if err := audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: domain.ClientID(r.client), Event: audit.Expired,
				ItemID: domain.ItemID(r.item), Detail: map[string]string{"request": r.id}}); err != nil {
				return err
			}
		}
		return nil
	})
	for _, id := range ids {
		s.broker.publish(id)
	}
	return len(ids), err
}

// Start runs background work (request expiry) until ctx ends.
func (s *Service) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.ExpireRequests(ctx)
			}
		}
	}()
}

// Redeem spends one use of a grant and returns the item's current value.
// Only the client the grant was made for may redeem it.
func (s *Service) Redeem(ctx context.Context, by domain.Client, gid domain.GrantID) (domain.Grant, domain.Secret, error) {
	if s.vault.Sealed() {
		return domain.Grant{}, domain.Secret{}, vault.ErrSealed
	}
	now := s.now()
	g, err := s.getGrant(ctx, gid)
	if err != nil || g.ClientID != by.ID {
		return domain.Grant{}, domain.Secret{}, domain.Errorf(domain.CodeNotFound, "no grant %s for %q", gid, by.Name)
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants
			SET uses_left = CASE WHEN uses_left IS NULL THEN NULL ELSE uses_left - 1 END
			WHERE id = ? AND revoked_at IS NULL AND expires_at > ? AND (uses_left IS NULL OR uses_left > 0)`,
			gid, now.UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			switch {
			case g.RevokedAt != nil:
				return domain.Errorf(domain.CodeRevoked, "grant %s was revoked", gid)
			case g.UsesLeft != nil && *g.UsesLeft <= 0:
				return domain.Errorf(domain.CodeSpent, "grant %s was already used", gid)
			default:
				return domain.Errorf(domain.CodeExpired, "grant %s expired", gid)
			}
		}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by.ID, Event: audit.Redeem, ItemID: g.ItemID,
			Detail: map[string]string{"grant": string(gid), "ref": g.Ref.String(), "bin": filepath.Base(g.BinPath)}})
	})
	if err != nil {
		return domain.Grant{}, domain.Secret{}, err
	}
	_, sec, err := s.vault.GetByID(ctx, g.ItemID)
	if err != nil {
		return domain.Grant{}, domain.Secret{}, err
	}
	g, _ = s.getGrant(ctx, gid)
	return g, sec, nil
}

const grantCols = `g.id, g.request_id, g.client_id, COALESCE(c.name, ''), g.item_id, g.ref, g.bin_path, g.decision,
	g.method, g.uses_left, g.created_at, g.expires_at, g.revoked_at
	FROM grants g LEFT JOIN clients c ON c.id = g.client_id`

func scanGrant(row scanner) (domain.Grant, error) {
	var (
		g                domain.Grant
		ref              string
		uses, revoked    sql.NullInt64
		created, expires int64
	)
	if err := row.Scan(&g.ID, &g.RequestID, &g.ClientID, &g.ClientName, &g.ItemID, &ref, &g.BinPath, &g.Decision,
		&g.Method, &uses, &created, &expires, &revoked); err != nil {
		return domain.Grant{}, err
	}
	g.Ref, _ = domain.ParseRef(ref)
	if uses.Valid {
		n := int(uses.Int64)
		g.UsesLeft = &n
	}
	g.CreatedAt, g.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64).UTC()
		g.RevokedAt = &t
	}
	return g, nil
}

func (s *Service) getGrant(ctx context.Context, id domain.GrantID) (domain.Grant, error) {
	g, err := scanGrant(s.store.R().QueryRowContext(ctx, `SELECT `+grantCols+` WHERE g.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Grant{}, domain.Errorf(domain.CodeNotFound, "no grant %s", id)
	}
	return g, err
}

// ActiveGrants lists grants that can still be redeemed.
func (s *Service) ActiveGrants(ctx context.Context) ([]domain.Grant, error) {
	rows, err := s.store.R().QueryContext(ctx, `SELECT `+grantCols+`
		WHERE g.revoked_at IS NULL AND g.expires_at > ? AND (g.uses_left IS NULL OR g.uses_left > 0)
		ORDER BY g.expires_at`, s.now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Grant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Service) RevokeGrant(ctx context.Context, by domain.ClientID, id domain.GrantID) error {
	now := s.now()
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now.UnixMilli(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return domain.Errorf(domain.CodeNotFound, "no active grant %s", id)
		}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by, Event: audit.GrantRevoke,
			Detail: map[string]string{"grant": string(id)}})
	})
}

// RevokeAll is the kill switch: every unexpired grant stops working, and
// every pending request is denied.
func (s *Service) RevokeAll(ctx context.Context, by domain.ClientID) (int, error) {
	now := s.now()
	var n int64
	var pending []domain.RequestID
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants SET revoked_at = ? WHERE revoked_at IS NULL AND expires_at > ?
			AND (uses_left IS NULL OR uses_left > 0)`,
			now.UnixMilli(), now.UnixMilli())
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		rows, err := tx.QueryContext(ctx, `UPDATE requests SET status = 'denied', decision = 'deny', method = 'cli',
			decided_at = ? WHERE status = 'pending' RETURNING id`, now.UnixMilli())
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			rows.Scan(&id)
			pending = append(pending, domain.RequestID(id))
		}
		rows.Close()
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by, Event: audit.RevokeAll,
			Detail: map[string]string{"grants": strconv.FormatInt(n, 10), "requests": strconv.Itoa(len(pending))}})
	})
	for _, id := range pending {
		s.broker.publish(id)
	}
	return int(n), err
}

// ReportScrub records that a command printed a secret it was given.
func (s *Service) ReportScrub(ctx context.Context, by domain.Client, id domain.GrantID, hits int) error {
	g, err := s.getGrant(ctx, id)
	if err != nil || g.ClientID != by.ID {
		return domain.Errorf(domain.CodeNotFound, "no grant %s for %q", id, by.Name)
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by.ID, Event: audit.ScrubHit, ItemID: g.ItemID,
			Detail: map[string]string{"grant": string(id), "ref": g.Ref.String(), "bin": filepath.Base(g.BinPath),
				"hits": strconv.Itoa(hits)}})
	})
}

var binName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// SetPolicy replaces the policy of ref.
func (s *Service) SetPolicy(ctx context.Context, by domain.Client, ref domain.Ref, p domain.Policy) (domain.Item, error) {
	for _, b := range p.Bins {
		if !filepath.IsAbs(b) && !binName.MatchString(b) {
			return domain.Item{}, domain.Errorf(domain.CodeInvalid, "bins entry %q: want a program name like gh, or an absolute path", b)
		}
	}
	switch p.MaxGrant {
	case "":
		p.MaxGrant = string(domain.Decide1h)
	case string(domain.DecideOnce), string(domain.Decide15m), string(domain.Decide1h):
	default:
		return domain.Item{}, domain.Errorf(domain.CodeInvalid, "max grant %q: want once, 15m or 1h", p.MaxGrant)
	}
	item, err := s.vault.Lookup(ctx, ref)
	if err != nil {
		return domain.Item{}, err
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.vault.SetPolicyTx(ctx, tx, item.ID, p); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by.ID, Event: audit.PolicySet, ItemID: item.ID,
			Detail: map[string]string{"ref": ref.String(), "bins": strings.Join(p.Bins, ","), "max_grant": p.MaxGrant}})
	})
	if err != nil {
		return domain.Item{}, err
	}
	return s.vault.Lookup(ctx, ref)
}
