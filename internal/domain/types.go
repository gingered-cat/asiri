// Package domain holds Asiri's value types, entities and errors. It imports
// nothing else from Asiri.
package domain

import "time"

// Kind says what a secret is, which decides how it may be delivered.
type Kind string

const (
	KindToken    Kind = "token"
	KindPassword Kind = "password"
	KindSSHKey   Kind = "ssh_key"
	KindLogin    Kind = "login"
	KindNote     Kind = "note"
)

func (k Kind) Valid() bool {
	switch k {
	case KindToken, KindPassword, KindSSHKey, KindLogin, KindNote:
		return true
	}
	return false
}

// Role is what a paired client may do.
type Role string

const (
	// RoleOwner manages secrets, clients and policy, and approves.
	RoleOwner Role = "owner"
	// RoleAgent lists metadata and asks to use secrets.
	RoleAgent Role = "agent"
)

func (r Role) Valid() bool { return r == RoleOwner || r == RoleAgent }

// Policy limits where an item's value may go.
type Policy struct {
	Bins          []string `json:"bins"`
	SSHHosts      []string `json:"ssh_hosts"`
	MaxGrant      string   `json:"max_grant"`
	RevealToAgent bool     `json:"reveal_to_agent"`
}

// Item is a secret's metadata. It never carries the value.
type Item struct {
	ID        ItemID    `json:"id"`
	Ref       Ref       `json:"ref"`
	Kind      Kind      `json:"kind"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Policy    Policy    `json:"policy"`
}

// Client is a paired CLI profile, identified by its certificate.
type Client struct {
	ID        ClientID   `json:"id"`
	Name      string     `json:"name"`
	Role      Role       `json:"role"`
	CertFP    string     `json:"cert_fp,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AuditEvent is one row of the hash-chained audit log. Detail never holds
// secret values.
type AuditEvent struct {
	Seq      int64             `json:"seq"`
	TS       time.Time         `json:"ts"`
	ClientID ClientID          `json:"client_id,omitempty"`
	Event    string            `json:"event"`
	ItemID   ItemID            `json:"item_id,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
	Hash     string            `json:"hash"`
}
