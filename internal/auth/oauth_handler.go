package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"goleanauth/internal/apperror"
	"goleanauth/internal/requestctx"
	"goleanauth/pkg/config"
)

type OAuthHandler struct {
	Service *OAuthService
	cfg     *config.Config
}

func NewOAuthHandler(service *OAuthService, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{Service: service, cfg: cfg}
}

// Token issues tokens for the client_credentials and refresh_token grants.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret := clientCredentials(r)

	tokens, err := h.Service.Token(r.Context(), TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
	})
	if err != nil {
		h.tokenError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, tokens)
}

// Revoke invalidates a refresh token (RFC 7009).
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret := clientCredentials(r)

	err := h.Service.Revoke(r.Context(), clientID, clientSecret, r.FormValue("token"))
	if err != nil {
		h.tokenError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Introspect validates a token and returns its state and claims (RFC 7662).
func (h *OAuthHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret := clientCredentials(r)

	info, err := h.Service.Introspect(r.Context(), clientID, clientSecret, r.FormValue("token"))
	if err != nil {
		h.tokenError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, info)
}

// UserInfo returns standard claims for the authenticated user.
func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := requestctx.UserID(r.Context())
	if !ok || userID == "" {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	info, err := h.Service.UserInfo(r.Context(), userID)
	if err != nil {
		h.tokenError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, info)
}

// Discovery serves the OpenID Connect discovery document.
func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                h.Service.Issuer,
		"jwks_uri":                              h.Service.Issuer + "/.well-known/jwks.json",
		"token_endpoint":                        h.Service.Issuer + "/v1/oauth/token",
		"userinfo_endpoint":                     h.Service.Issuer + "/v1/userinfo",
		"introspection_endpoint":                h.Service.Issuer + "/v1/oauth/introspect",
		"revocation_endpoint":                   h.Service.Issuer + "/v1/oauth/revoke",
		"response_types_supported":              []string{"token"},
		"grant_types_supported":                 []string{"client_credentials", "refresh_token", "authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	})
}

// JWKS serves the public JSON Web Key Set for token verification.
func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	body, err := h.Service.Keys.JWKS()
	if err != nil {
		h.oauthError(w, http.StatusInternalServerError, "server_error", "unable to build key set")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *OAuthHandler) tokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apperror.ErrInvalidClientCredentials), errors.Is(err, apperror.ErrClientInactive):
		h.oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
	case errors.Is(err, apperror.ErrUnsupportedGrantType):
		h.oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	case errors.Is(err, apperror.ErrInvalidRequest):
		h.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid request")
	case errors.Is(err, apperror.ErrInvalidScope):
		h.oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed")
	case errors.Is(err, apperror.ErrInvalidToken):
		h.oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
	case errors.Is(err, apperror.ErrUserNotFound):
		h.oauthError(w, http.StatusNotFound, "user_not_found", "user not found")
	default:
		h.oauthError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

func (h *OAuthHandler) oauthError(w http.ResponseWriter, status int, code, description string) {
	h.writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (h *OAuthHandler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// clientCredentials returns the client id/secret from the Authorization
// header (preferred) or the form body.
func clientCredentials(r *http.Request) (clientID, clientSecret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}
