package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/vault"
)

func TestChain(t *testing.T) {
	ctx := context.Background()
	s, err := vault.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 5 {
		err := s.Tx(ctx, func(tx *sql.Tx) error {
			return Append(ctx, tx, time.Now(), domain.AuditEvent{Event: ItemPut, ClientID: "c1",
				Detail: map[string]string{"ref": "asiri://dev/x", "n": string(rune('0' + i))}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(ctx, s.R())
	if err != nil || n != 5 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	evs, err := List(ctx, s.R(), 2, 10)
	if err != nil || len(evs) != 3 || evs[0].Seq != 3 || evs[0].Detail["ref"] != "asiri://dev/x" {
		t.Fatalf("List = %+v, %v", evs, err)
	}

	tamper := func(q string) {
		t.Helper()
		if err := s.Tx(ctx, func(tx *sql.Tx) error { _, err := tx.Exec(q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	tamper(`UPDATE audit SET event = 'unlock' WHERE seq = 3`)
	if _, err := Verify(ctx, s.R()); err == nil || !strings.Contains(err.Error(), "row 3") {
		t.Fatalf("edit not detected: %v", err)
	}
	tamper(`UPDATE audit SET event = 'item_put' WHERE seq = 3`)
	tamper(`DELETE FROM audit WHERE seq = 2`)
	if _, err := Verify(ctx, s.R()); err == nil || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("delete not detected: %v", err)
	}
}
