// Package vault stores encrypted items in SQLite and holds the vault key.
package vault

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the SQLite database. Writes go through one connection so they
// never contend; reads use a small pool.
type Store struct {
	w, r *sql.DB
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	base := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path != ":memory:" {
		base += "&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	}
	w, err := sql.Open("sqlite", base+"&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r := w
	if path != ":memory:" {
		if r, err = sql.Open("sqlite", base); err != nil {
			w.Close()
			return nil, err
		}
		r.SetMaxOpenConns(4)
	}
	s := &Store{w: w, r: r}
	if err := s.migrate(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error {
	err := s.w.Close()
	if s.r != s.w {
		s.r.Close()
	}
	return err
}

// R is the read pool.
func (s *Store) R() *sql.DB { return s.r }

// Tx runs fn in a write transaction, committing if fn returns nil.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var cur int
	if err := s.w.QueryRowContext(ctx, `SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&cur); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for i, name := range names {
		v := i + 1
		if !strings.HasPrefix(name, fmt.Sprintf("migrations/%03d_", v)) {
			return fmt.Errorf("migration %s is out of sequence", name)
		}
		if v <= cur {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = s.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_version (v) VALUES (?)`, v)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}
