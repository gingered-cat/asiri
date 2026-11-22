package service

import (
	"context"
	"database/sql"
	"regexp"
	"strconv"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/approvalkey"
	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/domain"
)

// Approval keys: once one is enrolled, an "allow" decision needs a signature
// by a live key over the server's statement of the request. A deny never
// does, since refusing can't leak a secret.

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// liveApprovalKeys returns the keys that are not revoked, oldest first.
func liveApprovalKeys(ctx context.Context, q querier) ([]domain.ApprovalKey, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name, client_id, public_key, created_at FROM approval_keys
		WHERE revoked_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ApprovalKey{}
	for rows.Next() {
		var k domain.ApprovalKey
		var created int64
		if err := rows.Scan(&k.ID, &k.Name, &k.ClientID, &k.PublicKey, &created); err != nil {
			return nil, err
		}
		k.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, k)
	}
	return out, rows.Err()
}

// ApprovalKeys lists the live approval keys.
func (s *Service) ApprovalKeys(ctx context.Context) ([]domain.ApprovalKey, error) {
	return liveApprovalKeys(ctx, s.store.R())
}

func (s *Service) serverID() string { return s.ca.Fingerprint() }

// approvalStatement is what a key signs to allow request cur with decision d.
func (s *Service) approvalStatement(ctx context.Context, cur domain.Request, d domain.Decision) ([]byte, error) {
	var sha string
	if err := s.store.R().QueryRowContext(ctx, `SELECT bin_sha256 FROM requests WHERE id = ?`, cur.ID).Scan(&sha); err != nil {
		return nil, err
	}
	action := approvalkey.ActionUse
	if cur.HostFP != "" {
		action = approvalkey.ActionSSH
	}
	return approvalkey.Statement(approvalkey.Request{
		Action: action, Server: s.serverID(), ID: string(cur.ID), Client: cur.ClientName, ClientID: string(cur.ClientID), Ref: cur.Ref.String(),
		Program: cur.BinPath, SHA256: sha, HostFP: cur.HostFP, Decision: string(d), ExpiresAt: cur.ExpiresAt,
	}), nil
}

// ApprovalChallenge returns the statement to sign to allow request id with
// decision d, and whether this server needs it signed.
func (s *Service) ApprovalChallenge(ctx context.Context, by domain.Client, id domain.RequestID, d domain.Decision) (api.ApprovalChallenge, error) {
	if by.Role != domain.RoleOwner {
		return api.ApprovalChallenge{}, domain.Errorf(domain.CodeNotAllowed, "only an owner can approve requests")
	}
	if !d.Valid() || d == domain.DecideDeny {
		return api.ApprovalChallenge{}, domain.Errorf(domain.CodeInvalid, "decision %q: want once, 15m or 1h", d)
	}
	cur, err := s.GetRequest(ctx, by, id)
	if err != nil {
		return api.ApprovalChallenge{}, err
	}
	keys, err := s.ApprovalKeys(ctx)
	if err != nil {
		return api.ApprovalChallenge{}, err
	}
	msg, err := s.approvalStatement(ctx, cur, d)
	if err != nil {
		return api.ApprovalChallenge{}, err
	}
	return api.ApprovalChallenge{Statement: msg, Required: len(keys) > 0, KeyIDs: keyIDs(keys)}, nil
}

func keyIDs(keys []domain.ApprovalKey) []string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	return ids
}

// checkSigned verifies a signature over statement by a live key.
func checkSigned(keys []domain.ApprovalKey, keyID string, statement, sig []byte) error {
	for _, k := range keys {
		if k.ID == keyID {
			if err := approvalkey.Verify(k.PublicKey, statement, sig); err != nil {
				return domain.Errorf(domain.CodeNotAllowed, "the approval signature by key %s doesn't match this request", keyID)
			}
			return nil
		}
	}
	return domain.Errorf(domain.CodeNotAllowed, "approval key %q is not enrolled on this server", keyID)
}

// requireSigned enforces signed approvals for an allow decision on cur. It
// returns the key that signed, or "" when no key is enrolled.
func (s *Service) requireSigned(ctx context.Context, cur domain.Request, req api.DecisionRequest) (string, error) {
	if req.Decision == domain.DecideDeny {
		return "", nil
	}
	keys, err := s.ApprovalKeys(ctx)
	if err != nil || len(keys) == 0 {
		return "", err
	}
	if len(req.Signature) == 0 {
		return "", domain.Errorf(domain.CodeNotAllowed,
			"approvals on this server need Touch ID: approve with `asiri approve` or Rex on the Mac with the enrolled key")
	}
	msg, err := s.approvalStatement(ctx, cur, req.Decision)
	if err != nil {
		return "", err
	}
	return req.KeyID, checkSigned(keys, req.KeyID, msg, req.Signature)
}

var keyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._'-]{0,63}$`)

// EnrollChallenge returns the statement a new key signs to prove itself (and
// an existing key signs to endorse it). Required means an endorsement by a
// live key is needed, because one is already enrolled.
func (s *Service) EnrollChallenge(ctx context.Context, by domain.Client, publicKey []byte) (api.ApprovalChallenge, error) {
	if by.Role != domain.RoleOwner {
		return api.ApprovalChallenge{}, domain.Errorf(domain.CodeNotAllowed, "only an owner can enroll approval keys")
	}
	if _, err := approvalkey.ParsePublicKey(publicKey); err != nil {
		return api.ApprovalChallenge{}, domain.Errorf(domain.CodeInvalid, "%v", err)
	}
	keys, err := s.ApprovalKeys(ctx)
	if err != nil {
		return api.ApprovalChallenge{}, err
	}
	return api.ApprovalChallenge{Statement: approvalkey.EnrollStatement(s.serverID(), publicKey),
		Required: len(keys) > 0, KeyIDs: keyIDs(keys)}, nil
}

// EnrollApprovalKey adds an approval key. The new key must sign the enroll
// statement (so it exists and the person touched it). If keys are already
// enrolled, one of them must sign it too: otherwise anyone holding the owner
// profile could add a key of their own and approve with it.
func (s *Service) EnrollApprovalKey(ctx context.Context, by domain.Client, req api.EnrollApprovalKeyRequest) (domain.ApprovalKey, error) {
	ch, err := s.EnrollChallenge(ctx, by, req.PublicKey)
	if err != nil {
		return domain.ApprovalKey{}, err
	}
	if !keyName.MatchString(req.Name) {
		return domain.ApprovalKey{}, domain.Errorf(domain.CodeInvalid, "key name %q: 1-64 letters, digits, spaces or ._'-", req.Name)
	}
	if err := approvalkey.Verify(req.PublicKey, ch.Statement, req.Proof); err != nil {
		return domain.ApprovalKey{}, domain.Errorf(domain.CodeNotAllowed, "the new key's proof doesn't match: %v", err)
	}
	k := domain.ApprovalKey{ID: approvalkey.ID(req.PublicKey), Name: req.Name, ClientID: by.ID,
		PublicKey: req.PublicKey, CreatedAt: s.now().UTC()}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		keys, err := liveApprovalKeys(ctx, tx)
		if err != nil {
			return err
		}
		for _, l := range keys {
			if l.ID == k.ID {
				return domain.Errorf(domain.CodeConflict, "key %s is already enrolled", k.ID)
			}
		}
		detail := map[string]string{"key": k.ID, "name": k.Name}
		if len(keys) > 0 {
			if len(req.Endorsement) == 0 {
				return domain.Errorf(domain.CodeNotAllowed,
					"an approval key is already enrolled: endorse the new key with it, or reset with `asiri server reset-approval-keys` on the server")
			}
			if err := checkSigned(keys, req.EndorsedBy, ch.Statement, req.Endorsement); err != nil {
				return err
			}
			detail["endorsed_by"] = req.EndorsedBy
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO approval_keys (id, name, client_id, public_key, created_at) VALUES (?, ?, ?, ?, ?)`,
			k.ID, k.Name, k.ClientID, k.PublicKey, k.CreatedAt.UnixMilli()); err != nil {
			return err
		}
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{ClientID: by.ID, Event: audit.KeyEnroll, Detail: detail})
	})
	return k, err
}

// ResetApprovalKeys revokes every approval key, so allow decisions no longer
// need a signature. It has no API route: only someone who can run the server
// binary against its data directory (`asiri server reset-approval-keys`) can
// do it, which is the recovery path for a lost or replaced Mac.
func (s *Service) ResetApprovalKeys(ctx context.Context) (int, error) {
	n := 0
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE approval_keys SET revoked_at = ? WHERE revoked_at IS NULL`, s.now().UnixMilli())
		if err != nil {
			return err
		}
		m, _ := res.RowsAffected()
		n = int(m)
		return audit.Append(ctx, tx, s.now(), domain.AuditEvent{Event: audit.KeysReset,
			Detail: map[string]string{"revoked": strconv.Itoa(n)}})
	})
	return n, err
}
