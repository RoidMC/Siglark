package nxs

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// AdminHandler exposes the provider's minimal operator surface. It is
// separate from the NXS wire protocol and protected by a single operator
// token.
type AdminHandler struct {
	service *Service
	token   string
}

// NewAdminHandler builds the operator API. An empty token disables mounting.
func NewAdminHandler(service *Service, token string) *AdminHandler {
	return &AdminHandler{service: service, token: token}
}

// Mount registers the admin routes. It does nothing when no token is
// configured, so an unconfigured deployment exposes no operator surface.
func (h *AdminHandler) Mount(r chi.Router) {
	if h.token == "" {
		return
	}
	r.Route("/v1/admin", func(r chi.Router) {
		r.Use(h.requireAdmin)
		r.Get("/registrations", h.listRegistrations)
		r.Get("/registrations/{registrationID}", h.getRegistration)
		r.Get("/tokens", h.listTokens)
		r.Post("/tokens", h.issueToken)
		r.Delete("/tokens/{reference}", h.revokeToken)
	})
}

func (h *AdminHandler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		raw := r.Header.Get("Authorization")
		if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) ||
			subtle.ConstantTimeCompare([]byte(raw[len(prefix):]), []byte(h.token)) != 1 {
			writeError(w, NewError(http.StatusUnauthorized, "invalid_admin_token", "The admin token is missing or invalid."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *AdminHandler) listRegistrations(w http.ResponseWriter, r *http.Request) {
	views, err := h.service.ListRegistrations(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, map[string]any{"registrations": views})
}

func (h *AdminHandler) getRegistration(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "registrationID")
	view, err := h.service.GetRegistrationView(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, NewError(http.StatusNotFound, "not_found", "No such registration."))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, view)
}

func (h *AdminHandler) listTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"tokens": h.service.ListBearerTokens()})
}

func (h *AdminHandler) issueToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, errInvalidRequest("The request body is not valid JSON."))
			return
		}
	}
	token, err := h.service.IssueBearerToken(req.Label)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, token)
}

func (h *AdminHandler) revokeToken(w http.ResponseWriter, r *http.Request) {
	reference := chi.URLParam(r, "reference")
	if err := h.service.RevokeBearerToken(reference); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, NewError(http.StatusNotFound, "not_found", "No such authorization."))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, EmptyResponse{})
}
