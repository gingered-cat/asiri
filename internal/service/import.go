package service

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/importer"
	"github.com/gingered-cat/asiri/internal/vault"
)

// importFields maps each login to items: vault/name/password and friends.
// Only password and totp are secret-kinds; the rest are notes, stored
// encrypted all the same.
func importFields(vaultName string, e importer.Entry) ([]importField, error) {
	var out []importField
	for _, f := range []struct {
		field, value string
		kind         domain.Kind
	}{
		{"password", e.Password, domain.KindLogin},
		{"username", e.Username, domain.KindNote},
		{"url", e.URL, domain.KindNote},
		{"totp", e.TOTP, domain.KindToken},
		{"notes", e.Notes, domain.KindNote},
	} {
		if f.value == "" {
			continue
		}
		ref, err := domain.ParseRef(vaultName + "/" + e.Name + "/" + f.field)
		if err != nil {
			return nil, err
		}
		out = append(out, importField{ref: ref, kind: f.kind, value: []byte(f.value)})
	}
	return out, nil
}

type importField struct {
	ref   domain.Ref
	kind  domain.Kind
	value []byte
}

// Import stores logins from a password-manager export in one transaction.
// A login whose fields are all unchanged is left alone, so importing the
// same file twice changes nothing. Imported items get the default policy:
// no program may use them until the person says so.
func (s *Service) Import(ctx context.Context, by domain.Client, vaultName, source string, entries []importer.Entry) (api.ImportResult, error) {
	if s.vault.Sealed() {
		return api.ImportResult{}, vault.ErrSealed
	}
	if len(entries) > importer.MaxEntries {
		return api.ImportResult{}, domain.Errorf(domain.CodeInvalid, "more than %d logins", importer.MaxEntries)
	}
	res := api.ImportResult{Logins: len(entries)}
	type change struct {
		f   importField
		new bool
	}
	var changes []change
	for _, e := range entries {
		fields, err := importFields(vaultName, e)
		if err != nil {
			return api.ImportResult{}, err
		}
		created, changed := true, false
		for _, f := range fields {
			_, cur, err := s.vault.Get(ctx, f.ref)
			switch {
			case err == nil:
				created = false
				same := bytes.Equal(cur.Reveal(), f.value)
				cur.Zero()
				if same {
					continue
				}
			case domain.CodeOf(err) != domain.CodeNotFound:
				return api.ImportResult{}, err
			}
			changed = true
			changes = append(changes, change{f: f})
		}
		switch {
		case created:
			res.Created++
		case changed:
			res.Updated++
		default:
			res.Unchanged++
		}
	}
	now := s.now()
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		for _, c := range changes {
			sec := domain.NewSecret(c.f.value)
			_, err := s.vault.PutTx(ctx, tx, c.f.ref, c.f.kind, sec, "", now)
			sec.Zero()
			if err != nil {
				return err
			}
		}
		return audit.Append(ctx, tx, now, domain.AuditEvent{ClientID: by.ID, Event: audit.Import, Detail: map[string]string{
			"source": source, "vault": vaultName, "logins": strconv.Itoa(res.Logins),
			"created": strconv.Itoa(res.Created), "updated": strconv.Itoa(res.Updated), "unchanged": strconv.Itoa(res.Unchanged),
		}})
	})
	if err != nil {
		return api.ImportResult{}, err
	}
	return res, nil
}
