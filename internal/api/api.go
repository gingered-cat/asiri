// Package api holds the JSON types sent between the asiri CLI and server.
package api

import (
	"net/http"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
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
	case domain.CodeNotAllowed:
		return http.StatusForbidden
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
