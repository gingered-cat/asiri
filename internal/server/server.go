// Package server is the HTTPS API. Handlers decode, call the service and
// encode; they hold no business logic.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gingered-cat/asiri/internal/api"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/pki"
	"github.com/gingered-cat/asiri/internal/service"
)

// Version is set at build time.
var Version = "dev"

type Server struct {
	svc *service.Service
	log *slog.Logger
	mux *http.ServeMux
}

func New(svc *service.Service, log *slog.Logger) *Server {
	s := &Server{svc: svc, log: log, mux: http.NewServeMux()}
	anyone := []domain.Role{domain.RoleOwner, domain.RoleAgent}
	owner := []domain.Role{domain.RoleOwner}

	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/pair", s.pair)
	s.handle("GET /v1/whoami", anyone, s.whoami)
	s.handle("GET /v1/items", anyone, s.listItems)
	s.handle("PUT /v1/items/{vault}/{name}", owner, s.putItem)
	s.handle("POST /v1/unlock", owner, s.unlock)
	s.handle("POST /v1/lock", owner, s.lock)
	s.handle("GET /v1/clients", owner, s.listClients)
	s.handle("POST /v1/clients", owner, s.createClient)
	s.handle("POST /v1/clients/{name}/revoke", owner, s.revokeClient)
	s.handle("GET /v1/audit", owner, s.listAudit)
	s.handle("GET /v1/audit/verify", owner, s.verifyAudit)
	return s
}

// Handler wraps the routes in logging and panic recovery.
func (s *Server) Handler() http.Handler { return s.logged(s.recovered(s.mux)) }

// TLSConfig requires TLS 1.3 and verifies client certificates when given.
// Routes other than /v1/health and /v1/pair reject requests without one.
func TLSConfig(serverCertPEM, serverKeyPEM []byte, ca *pki.CA) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(append(append([]byte{}, serverCertPEM...), ca.CertPEM...), serverKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}, nil
}

// HTTPServer returns an http.Server with sane timeouts.
func (s *Server) HTTPServer(addr string, tc *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// ---- middleware ----

type ctxKey struct{}

func clientFrom(ctx context.Context) domain.Client {
	c, _ := ctx.Value(ctxKey{}).(domain.Client)
	return c
}

// handle registers a route that needs a paired client with one of roles.
func (s *Server) handle(pattern string, roles []domain.Role, h http.HandlerFunc) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeErr(w, domain.Errorf(domain.CodeUnauthenticated, "a client certificate is required; run `asiri pair`"))
			return
		}
		c, err := s.svc.ClientByFingerprint(r.Context(), pki.Fingerprint(r.TLS.PeerCertificates[0]))
		if err != nil {
			writeErr(w, err)
			return
		}
		allowed := false
		for _, role := range roles {
			allowed = allowed || c.Role == role
		}
		if !allowed {
			writeErr(w, domain.Errorf(domain.CodeNotAllowed, "%s needs the %s role; %q is %s", r.URL.Path, roles[0], c.Name, c.Role))
			return
		}
		if rec, ok := w.(*recorder); ok {
			rec.client = c.Name
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}

type recorder struct {
	http.ResponseWriter
	status int
	client string
}

func (r *recorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// logged logs method, path, status, client and duration. Never bodies.
func (s *Server) logged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"client", rec.client, "ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) recovered(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic", "path", r.URL.Path, "panic", v)
				writeErr(w, errors.New("internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var body api.ErrorBody
	var e *domain.Error
	if errors.As(err, &e) {
		body.Error.Code, body.Error.Message = e.Code, e.Msg
	} else {
		body.Error.Code, body.Error.Message = domain.CodeInternal, "internal error"
	}
	writeJSON(w, api.Status(body.Error.Code), body)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return domain.Errorf(domain.CodeInvalid, "bad request body: %v", err)
	}
	return nil
}

// ---- handlers ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	init, err := s.svc.Initialized(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.Health{Version: Version, Initialized: init, Sealed: s.svc.Sealed()})
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	var req api.PairRequest
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, err)
		return
	}
	resp, err := s.svc.Pair(r.Context(), req.Code, req.CSR)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	c := clientFrom(r.Context())
	writeJSON(w, http.StatusOK, api.WhoAmI{Name: c.Name, Role: c.Role})
}

func (s *Server) listItems(w http.ResponseWriter, r *http.Request) {
	items, err := s.svc.ListItems(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ItemsResponse{Items: items})
}

func (s *Server) putItem(w http.ResponseWriter, r *http.Request) {
	var req api.PutItemRequest
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, err)
		return
	}
	sec := domain.NewSecret(req.Value)
	defer sec.Zero()
	field := req.Field
	if field == "" {
		field = domain.DefaultField
	}
	ref, err := domain.ParseRef(r.PathValue("vault") + "/" + r.PathValue("name") + "/" + field)
	if err != nil {
		writeErr(w, err)
		return
	}
	it, err := s.svc.PutItem(r.Context(), clientFrom(r.Context()), ref, req.Kind, sec)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ItemResponse{Item: it})
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var req api.UnlockRequest
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, err)
		return
	}
	defer clear(req.Passphrase)
	if err := s.svc.Unlock(r.Context(), clientFrom(r.Context()).ID, req.Passphrase); err != nil {
		writeErr(w, err)
		return
	}
	s.health(w, r)
}

func (s *Server) lock(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Lock(r.Context(), clientFrom(r.Context()).ID); err != nil {
		writeErr(w, err)
		return
	}
	s.health(w, r)
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	cs, err := s.svc.ListClients(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ClientsResponse{Clients: cs})
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var req api.CreateClientRequest
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, err)
		return
	}
	code, err := s.svc.CreatePairCode(r.Context(), clientFrom(r.Context()).ID, req.Name, req.Role, req.Replace)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, code)
}

func (s *Server) revokeClient(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RevokeClient(r.Context(), clientFrom(r.Context()).ID, r.PathValue("name")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evs, err := s.svc.Audit(r.Context(), since, limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.AuditResponse{Events: evs})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	n, err := s.svc.VerifyAudit(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.VerifyResponse{Rows: n})
}
