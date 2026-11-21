// Package audit keeps a hash-chained, append-only log. Each row's hash covers
// the previous row's hash, so editing or deleting a row breaks the chain from
// that point on. Rows are appended inside the caller's transaction, so the log
// and the change it records commit together or not at all.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

// Event names.
const (
	Init         = "init"
	Unlock       = "unlock"
	UnlockFailed = "unlock_failed"
	Lock         = "lock"
	PairCode     = "pair_code"
	Pair         = "pair"
	ClientRevoke = "client_revoke"
	ItemPut      = "item_put"
	PolicySet    = "policy_set"
	Request      = "request"
	Rejected     = "request_rejected"
	Decision     = "decision"
	Expired      = "request_expired"
	Redeem       = "redeem"
	SSHSign      = "ssh_sign"
	Import       = "import"
	GrantRevoke  = "grant_revoke"
	RevokeAll    = "revoke_all"
	ScrubHit     = "scrub_hit"
	Anomaly      = "anomaly"
)

var genesis = make([]byte, sha256.Size)

type row struct {
	Seq      int64             `json:"seq"`
	TS       int64             `json:"ts"`
	ClientID string            `json:"client_id"`
	Event    string            `json:"event"`
	ItemID   string            `json:"item_id"`
	Detail   map[string]string `json:"detail"`
}

func (r row) hash(prev []byte) ([]byte, error) {
	if r.Detail == nil {
		r.Detail = map[string]string{}
	}
	b, err := json.Marshal(r) // map keys are sorted, so this is canonical
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil), nil
}

// Append adds e to the log inside tx. Seq, TS and Hash are filled in.
func Append(ctx context.Context, tx *sql.Tx, now time.Time, e domain.AuditEvent) error {
	var seq int64
	prev := genesis
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	r := row{Seq: seq + 1, TS: now.UnixMilli(), ClientID: string(e.ClientID), Event: e.Event,
		ItemID: string(e.ItemID), Detail: e.Detail}
	h, err := r.hash(prev)
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(nonNil(e.Detail))
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit (seq, ts, client_id, event, item_id, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Seq, r.TS, r.ClientID, r.Event, r.ItemID, string(detail), prev, h)
	return err
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// List returns up to limit events with seq > since, oldest first.
func List(ctx context.Context, db querier, since int64, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx,
		`SELECT seq, ts, client_id, event, item_id, detail, hash FROM audit WHERE seq > ? ORDER BY seq LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AuditEvent{}
	for rows.Next() {
		var (
			e      domain.AuditEvent
			ts     int64
			detail string
			h      []byte
		)
		if err := rows.Scan(&e.Seq, &ts, &e.ClientID, &e.Event, &e.ItemID, &detail, &h); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ts).UTC()
		e.Hash = hex.EncodeToString(h)
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Verify walks the whole chain. It returns the number of rows checked, and an
// error naming the first row that doesn't match.
func Verify(ctx context.Context, db querier) (int64, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT seq, ts, client_id, event, item_id, detail, prev_hash, hash FROM audit ORDER BY seq`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := genesis
	var n int64
	for rows.Next() {
		var (
			r          row
			detail     string
			prevH, got []byte
		)
		if err := rows.Scan(&r.Seq, &r.TS, &r.ClientID, &r.Event, &r.ItemID, &detail, &prevH, &got); err != nil {
			return n, err
		}
		if r.Seq != n+1 {
			return n, fmt.Errorf("audit: row %d is missing", n+1)
		}
		if err := json.Unmarshal([]byte(detail), &r.Detail); err != nil {
			return n, fmt.Errorf("audit: row %d: %w", r.Seq, err)
		}
		want, err := r.hash(prev)
		if err != nil {
			return n, err
		}
		if string(prevH) != string(prev) || string(got) != string(want) {
			return n, fmt.Errorf("audit: row %d was altered", r.Seq)
		}
		prev = got
		n++
	}
	return n, rows.Err()
}
