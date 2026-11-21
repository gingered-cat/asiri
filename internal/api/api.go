// Package api holds the JSON types sent between the asiri CLI and server.
package api

import (
	"net/http"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/importer"
)

// DefaultPort is where the server listens.
const DefaultPort = "7420"

type Health struct {
	Version     string `json:"version"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
}

type WhoAmI struct {
	Name string      `json:"name"`
	Role domain.Role `json:"role"`
}

type PairRequest struct {
	Code string `json:"code"`
	CSR  string `json:"csr"`
}

type PairResponse struct {
	Name string      `json:"name"`
	Role domain.Role `json:"role"`
	Cert string      `json:"cert"`
	CA   string      `json:"ca"`
}

// PutItemRequest carries a value. Value is base64 in JSON.
type PutItemRequest struct {
	Field string      `json:"field,omitempty"`
	Kind  domain.Kind `json:"kind,omitempty"`
	Value []byte      `json:"value"`
}

type ItemResponse struct {
	Item domain.Item `json:"item"`
}

type ItemsResponse struct {
	Items []domain.Item `json:"items"`
}

type UnlockRequest struct {
	Passphrase []byte `json:"passphrase,omitempty"`
}

type CreateClientRequest struct {
	Name    string      `json:"name"`
	Role    domain.Role `json:"role"`
	Replace bool        `json:"replace,omitempty"`
}

type PairCode struct {
	Code      string      `json:"code"`
	Name      string      `json:"name"`
	Role      domain.Role `json:"role"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type ClientsResponse struct {
	Clients []domain.Client `json:"clients"`
}

type AuditResponse struct {
	Events []domain.AuditEvent `json:"events"`
}

type VerifyResponse struct {
	Rows int64 `json:"rows"`
}

type CreateRequest struct {
	Ref       domain.Ref `json:"ref"`
	BinPath   string     `json:"bin_path"`
	BinSHA256 string     `json:"bin_sha256"`
	HostFP    string     `json:"host_fp,omitempty"`
	Argv      []string   `json:"argv"`
	Cwd       string     `json:"cwd"`
	Reason    string     `json:"reason"`
}

// RequestResponse is a request's state. Reused means a live grant for the
// same client, item and binary already covered it.
type RequestResponse struct {
	Request domain.Request `json:"request"`
	Reused  bool           `json:"reused,omitempty"`
}

type RequestsResponse struct {
	Requests []domain.Request `json:"requests"`
}

type DecisionRequest struct {
	Decision domain.Decision `json:"decision"`
	Method   domain.Method   `json:"method"`
}

// RedeemResponse carries a value. Value is base64 in JSON.
type RedeemResponse struct {
	Grant domain.Grant `json:"grant"`
	Value []byte       `json:"value"`
}

type GrantsResponse struct {
	Grants []domain.Grant `json:"grants"`
}

type RevokeAllResponse struct {
	Revoked int `json:"revoked"`
}

type ScrubReport struct {
	Hits int `json:"hits"`
}

type PolicyRequest struct {
	Field    string   `json:"field,omitempty"`
	Bins     []string `json:"bins"`
	SSHHosts []string `json:"ssh_hosts,omitempty"`
	MaxGrant string   `json:"max_grant,omitempty"`
}

type GenerateSSHKey struct {
	Field string `json:"field,omitempty"`
}

type SSHSignRequest struct {
	GrantID domain.GrantID `json:"grant_id"`
	Data    []byte         `json:"data"`
	Flags   uint32         `json:"flags"`
}

// SSHSignature is an ssh.Signature on the wire.
type SSHSignature struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// ImportRequest carries logins parsed from an export.
type ImportRequest struct {
	Vault   string           `json:"vault"`
	Source  string           `json:"source"`
	Entries []importer.Entry `json:"entries"`
}

type ImportResult struct {
	Logins    int `json:"logins"`
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

type ErrorBody struct {
	Error struct {
		Code    domain.Code `json:"code"`
		Message string      `json:"message"`
	} `json:"error"`
}

// Status maps an error code to its HTTP status.
func Status(c domain.Code) int {
	switch c {
	case domain.CodeInvalid:
		return http.StatusBadRequest
	case domain.CodeUnauthenticated:
		return http.StatusUnauthorized
	case domain.CodeNotAllowed, domain.CodeInterpreter, domain.CodeDenied:
		return http.StatusForbidden
	case domain.CodeExpired, domain.CodeSpent, domain.CodeRevoked:
		return http.StatusGone
	case domain.CodeNotFound:
		return http.StatusNotFound
	case domain.CodeConflict:
		return http.StatusConflict
	case domain.CodeRateLimited:
		return http.StatusTooManyRequests
	case domain.CodeSealed:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}
