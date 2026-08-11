package auth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"goleanauth/internal/apperror"
	"goleanauth/internal/response"
	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
)

// RegisterClientRequest is the body of POST /v1/admin/clients.
type RegisterClientRequest struct {
	Name         string   `json:"name" validate:"required,min=1,max=100"`
	Scope        string   `json:"scope" validate:"max=200"`
	RedirectURIs []string `json:"redirect_uris" validate:"max=10,dive,absolute_uri"`
}

// AdminHandler serves operations protected by the static ADMIN_API_KEY.
type AdminHandler struct {
	Clients *ClientService
	cfg     *config.Config
}

func NewAdminHandler(clients *ClientService, cfg *config.Config) *AdminHandler {
	return &AdminHandler{Clients: clients, cfg: cfg}
}

// CreateClient registers a new OAuth client and returns its credentials. The
// client secret is returned only once.
func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.NotFound(w, r)
		return
	}

	var req RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.HandleError(w, apperror.ErrInvalidRequestBody)
		return
	}

	if fields := validation.ValidateStruct(req); len(fields) > 0 {
		response.ValidationError(w, fields)
		return
	}

	clientID, clientSecret, err := h.Clients.RegisterClient(r.Context(), req.Name, req.Scope, req.RedirectURIs...)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, http.StatusCreated, "client registered", map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
	})
}

// ListClients returns all registered clients without secret material.
func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.NotFound(w, r)
		return
	}

	clients, err := h.Clients.ListClients(r.Context())
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, http.StatusOK, "clients fetched", clients)
}

// authorized verifies the static admin API key. The endpoint is hidden (404)
// when no key is configured.
func (h *AdminHandler) authorized(r *http.Request) bool {
	key := h.cfg.AdminAPIKey
	if key == "" {
		return false
	}

	provided := r.Header.Get("X-Admin-Key")
	if provided == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(provided), []byte(key)) == 1
}
