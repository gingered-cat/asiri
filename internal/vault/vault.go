package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

// Vault encrypts and decrypts items. Key hierarchy:
//
//	key file or passphrase → KEK → vault key (VK) → per-version DEK → value
//
// Values are sealed with AAD = item id, version and field, so a ciphertext
// can't be moved to another item or version.
type Vault struct {
	store *Store
	kr    keyring
}

func New(s *Store) *Vault { return &Vault{store: s} }

func (v *Vault) Sealed() bool { return v.kr.sealed() }
func (v *Vault) Seal()        { v.kr.seal() }

// Initialized reports whether a vault key exists.
func (v *Vault) Initialized(ctx context.Context) (bool, error) {
	var n int
	err := v.store.R().QueryRowContext(ctx, `SELECT COUNT(*) FROM meta WHERE k = 'vk'`).Scan(&n)
	return n == 1, err
}

// Mode returns the KDF mode the vault was created with.
func (v *Vault) Mode(ctx context.Context) (string, error) {
	k, err := v.kdf(ctx, v.store.R())
	return k.Mode, err
}

// InitTx creates the vault key inside tx and returns it. After the
// transaction commits, pass it to Unseal.
func (v *Vault) InitTx(ctx context.Context, tx *sql.Tx, kdf KDF, secret []byte) ([]byte, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM meta WHERE k = 'vk'`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, domain.Errorf(domain.CodeConflict, "the vault is already initialized")
	}
	kek, err := kdf.deriveKEK(secret)
	if err != nil {
		return nil, domain.Errorf(domain.CodeInvalid, "%v", err)
	}
	defer clear(kek)
	vk := randomKey()
	nonce, ct, err := sealAEAD(kek, vk, vkAAD)
	if err != nil {
		return nil, err
	}
	kj, err := json.Marshal(kdf)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES ('kdf', ?), ('vk', ?)`,
		kj, append(nonce, ct...)); err != nil {
		return nil, err
	}
	return vk, nil
}

// Unseal installs a vault key returned by InitTx.
func (v *Vault) Unseal(vk []byte) { v.kr.unseal(vk) }

// Unlock derives the KEK from secret, unwraps the vault key and unseals.
func (v *Vault) Unlock(ctx context.Context, secret []byte) error {
	k, err := v.kdf(ctx, v.store.R())
	if err != nil {
		return err
	}
	var wrapped []byte
	if err := v.store.R().QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'vk'`).Scan(&wrapped); err != nil {
		return err
	}
	kek, err := k.deriveKEK(secret)
	if err != nil {
		return domain.Errorf(domain.CodeInvalid, "%v", err)
	}
	defer clear(kek)
	const n = 24 // XChaCha20 nonce
	if len(wrapped) < n {
		return errors.New("corrupt vault key")
	}
	vk, err := openAEAD(kek, wrapped[:n], wrapped[n:], vkAAD)
	if err != nil {
		if k.Mode == ModePassphrase {
			return domain.Errorf(domain.CodeNotAllowed, "wrong passphrase")
		}
		return domain.Errorf(domain.CodeNotAllowed, "wrong key file")
	}
	v.kr.unseal(vk)
	return nil
}

func (v *Vault) kdf(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (KDF, error) {
	var b []byte
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'kdf'`).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return KDF{}, domain.Errorf(domain.CodeNotFound, "the vault is not initialized; run `asiri server init`")
	}
	if err != nil {
		return KDF{}, err
	}
	var k KDF
	return k, json.Unmarshal(b, &k)
}

// PutTx stores a new version of ref. An empty kind keeps the previous
// version's kind (token for a new item).
func (v *Vault) PutTx(ctx context.Context, tx *sql.Tx, ref domain.Ref, kind domain.Kind, s domain.Secret, publicKey string, now time.Time) (domain.Item, error) {
	var item domain.Item
	err := v.kr.with(func(vk []byte) error {
		var id, oldKind string
		var ver int
		err := tx.QueryRowContext(ctx,
			`SELECT id, version, kind FROM items WHERE vault = ? AND name = ? AND field = ?
			 ORDER BY version DESC LIMIT 1`, ref.Vault, ref.Name, ref.Field).Scan(&id, &ver, &oldKind)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id, oldKind = domain.NewID(), string(domain.KindToken)
		case err != nil:
			return err
		}
		ver++
		if kind == "" {
			kind = domain.Kind(oldKind)
		}
		if !kind.Valid() {
			return domain.Errorf(domain.CodeInvalid, "unknown kind %q", kind)
		}
		dek := randomKey()
		defer clear(dek)
		nonce, ct, err := sealAEAD(dek, s.Reveal(), itemAAD(id, ver, ref.Field))
		if err != nil {
			return err
		}
		dn, wd, err := sealAEAD(vk, dek, dekAAD(id, ver))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO items (id, version, vault, name, field, kind, ciphertext, nonce, wrapped_dek, dek_nonce, public_key, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ver, ref.Vault, ref.Name, ref.Field, kind, ct, nonce, wd, dn, publicKey, now.UnixMilli()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO policies (item_id) VALUES (?)`, id); err != nil {
			return err
		}
		item = domain.Item{ID: domain.ItemID(id), Ref: ref, Kind: kind, Version: ver, UpdatedAt: now.UTC(), PublicKey: publicKey,
			Policy: domain.Policy{Bins: []string{}, SSHHosts: []string{}, MaxGrant: "1h"}}
		return nil
	})
	return item, err
}

// Get returns the latest version of ref and its value.
func (v *Vault) Get(ctx context.Context, ref domain.Ref) (domain.Item, domain.Secret, error) {
	return v.get(ctx, `vault = ? AND name = ? AND field = ?`, ref.Vault, ref.Name, ref.Field)
}

// GetByID returns the latest version of the item with id and its value.
func (v *Vault) GetByID(ctx context.Context, id domain.ItemID) (domain.Item, domain.Secret, error) {
	return v.get(ctx, `id = ?`, string(id))
}

func (v *Vault) get(ctx context.Context, where string, args ...any) (domain.Item, domain.Secret, error) {
	var (
		it                      domain.Item
		created                 int64
		ct, nonce, wdek, dnonce []byte
	)
	err := v.store.R().QueryRowContext(ctx,
		`SELECT id, version, vault, name, field, kind, created_at, ciphertext, nonce, wrapped_dek, dek_nonce FROM items
		 WHERE `+where+` AND deleted_at IS NULL ORDER BY version DESC LIMIT 1`, args...).
		Scan(&it.ID, &it.Version, &it.Ref.Vault, &it.Ref.Name, &it.Ref.Field, &it.Kind, &created, &ct, &nonce, &wdek, &dnonce)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Item{}, domain.Secret{}, domain.Errorf(domain.CodeNotFound, "that secret does not exist")
	}
	if err != nil {
		return domain.Item{}, domain.Secret{}, err
	}
	it.UpdatedAt = time.UnixMilli(created).UTC()
	id := string(it.ID)
	var value []byte
	err = v.kr.with(func(vk []byte) error {
		dek, err := openAEAD(vk, dnonce, wdek, dekAAD(id, it.Version))
		if err != nil {
			return errors.New("item key failed to decrypt: the database was altered or is corrupt")
		}
		defer clear(dek)
		value, err = openAEAD(dek, nonce, ct, itemAAD(id, it.Version, it.Ref.Field))
		if err != nil {
			return errors.New("item failed to decrypt: the database was altered or is corrupt")
		}
		return nil
	})
	if err != nil {
		return domain.Item{}, domain.Secret{}, err
	}
	return it, domain.NewSecret(value), nil
}

// Lookup returns the latest version of ref with its policy, without decrypting.
func (v *Vault) Lookup(ctx context.Context, ref domain.Ref) (domain.Item, error) {
	items, err := v.list(ctx, `i.vault = ? AND i.name = ? AND i.field = ?`, ref.Vault, ref.Name, ref.Field)
	if err != nil {
		return domain.Item{}, err
	}
	if len(items) == 0 {
		return domain.Item{}, domain.Errorf(domain.CodeNotFound, "%s does not exist; add it with: asiri add %s", ref, ref)
	}
	return items[0], nil
}

// SetPolicyTx replaces an item's policy.
func (v *Vault) SetPolicyTx(ctx context.Context, tx *sql.Tx, id domain.ItemID, p domain.Policy) error {
	bins, _ := json.Marshal(nonNil(p.Bins))
	hosts, _ := json.Marshal(nonNil(p.SSHHosts))
	reveal := 0
	if p.RevealToAgent {
		reveal = 1
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO policies (item_id, bins, ssh_hosts, max_grant, reveal_to_agent)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT (item_id) DO UPDATE SET bins = excluded.bins,
		ssh_hosts = excluded.ssh_hosts, max_grant = excluded.max_grant, reveal_to_agent = excluded.reveal_to_agent`,
		id, string(bins), string(hosts), p.MaxGrant, reveal)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// List returns the latest version of every item whose ref contains query.
func (v *Vault) List(ctx context.Context, query string) ([]domain.Item, error) {
	return v.list(ctx, `(?1 = '' OR instr(lower(i.vault || '/' || i.name || '/' || i.field), lower(?1)) > 0)`, query)
}

func (v *Vault) list(ctx context.Context, where string, args ...any) ([]domain.Item, error) {
	rows, err := v.store.R().QueryContext(ctx, `
		SELECT i.id, i.vault, i.name, i.field, i.kind, i.version, i.created_at, i.public_key,
		       COALESCE(p.bins, '[]'), COALESCE(p.ssh_hosts, '[]'), COALESCE(p.max_grant, '1h'),
		       COALESCE(p.reveal_to_agent, 0)
		FROM items i
		JOIN (SELECT id, MAX(version) AS v FROM items GROUP BY id) l ON l.id = i.id AND l.v = i.version
		LEFT JOIN policies p ON p.item_id = i.id
		WHERE i.deleted_at IS NULL AND `+where+`
		ORDER BY i.vault, i.name, i.field`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.Item{}
	for rows.Next() {
		var (
			it          domain.Item
			created     int64
			bins, hosts string
			reveal      int
		)
		if err := rows.Scan(&it.ID, &it.Ref.Vault, &it.Ref.Name, &it.Ref.Field, &it.Kind, &it.Version,
			&created, &it.PublicKey, &bins, &hosts, &it.Policy.MaxGrant, &reveal); err != nil {
			return nil, err
		}
		it.UpdatedAt = time.UnixMilli(created).UTC()
		it.Policy.RevealToAgent = reveal != 0
		if err := json.Unmarshal([]byte(bins), &it.Policy.Bins); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(hosts), &it.Policy.SSHHosts); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}
