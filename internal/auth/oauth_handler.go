package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"goleanauth/internal/apperror"
	"goleanauth/internal/auth/pages"
	"goleanauth/internal/normalize"
	"goleanauth/internal/requestctx"
	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
)

type OAuthHandler struct {
	Service *OAuthService
	Auth    *AuthService
	cfg     *config.Config
}

func NewOAuthHandler(service *OAuthService, authService *AuthService, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{Service: service, Auth: authService, cfg: cfg}
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
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
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
		"authorization_endpoint":                h.Service.Issuer + "/v1/oauth/authorize",
		"token_endpoint":                        h.Service.Issuer + "/v1/oauth/token",
		"userinfo_endpoint":                     h.Service.Issuer + "/v1/userinfo",
		"introspection_endpoint":                h.Service.Issuer + "/v1/oauth/introspect",
		"revocation_endpoint":                   h.Service.Issuer + "/v1/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"client_credentials", "refresh_token", "authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
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

// Authorize is the interactive OAuth 2.0 authorization endpoint. It validates
// the request, and either shows the consent screen or bounces the browser to
// the login page when no valid session is present.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	requestedScope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	client, scope, err := h.Service.ValidateAuthorize(r.Context(), clientID, redirectURI, requestedScope, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.authorizeError(w, r, err, clientID, redirectURI, state)
		return
	}

	if q.Get("response_type") != "code" {
		h.redirectOAuthError(w, r, redirectURI, "unsupported_response_type", "response_type must be 'code'", state)
		return
	}

	userID, ok := h.loggedInUser(r)
	if !ok {
		next := "/v1/oauth/authorize?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	h.renderConsent(w, client, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod)
}

// ConsentApprove handles the consent form submission. It re-validates every
// value (the form is attacker-controllable) before issuing an authorization
// code, then redirects the browser back to the client.
func (h *OAuthHandler) ConsentApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		pages.OAuthError(w, pages.OAuthErrorData{Code: "invalid_request", Description: "invalid form body"})
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	requestedScope := r.FormValue("scope")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	_, scope, err := h.Service.ValidateAuthorize(r.Context(), clientID, redirectURI, requestedScope, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.authorizeError(w, r, err, clientID, redirectURI, state)
		return
	}

	userID, ok := h.loggedInUser(r)
	if !ok {
		next := "/v1/oauth/authorize?" + url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {requestedScope}, "state": {state}, "code_challenge": {codeChallenge}, "code_challenge_method": {codeChallengeMethod}}.Encode()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	if r.FormValue("decision") != "approve" {
		h.redirectOAuthError(w, r, redirectURI, "access_denied", "the user denied the request", state)
		return
	}

	code, err := h.Service.IssueAuthorizationCode(r.Context(), clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.authorizeError(w, r, err, clientID, redirectURI, state)
		return
	}

	http.Redirect(w, r, buildAuthorizeRedirect(redirectURI, url.Values{"code": {code}, "state": {state}}), http.StatusFound)
}

// LoginForm renders the interactive login page used by the authorize flow.
func (h *OAuthHandler) LoginForm(w http.ResponseWriter, r *http.Request) {
	pages.Login(w, pages.LoginData{Next: r.URL.Query().Get("next")})
}

// LoginSubmit validates credentials and, on success, sets the refresh-token
// cookie and redirects back to the authorize flow.
func (h *OAuthHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		pages.Login(w, pages.LoginData{Next: r.FormValue("next"), Error: "invalid form body"})
		return
	}

	next := safeNext(r.FormValue("next"))

	loginReq, err := authLoginFormRequest(r)
	if err != nil {
		pages.Login(w, pages.LoginData{Next: next, Error: "invalid email, phone, or password"})
		return
	}

	_, refreshToken, err := h.Auth.Login(r.Context(), loginReq)
	if err != nil {
		pages.Login(w, pages.LoginData{Next: next, Error: "invalid email, phone, or password"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   h.cfg.AppEnv == "production",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.cfg.RefreshTokenTTLHours * 3600,
	})

	http.Redirect(w, r, next, http.StatusFound)
}

// loggedInUser resolves the browser's login from the refresh-token cookie.
func (h *OAuthHandler) loggedInUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", false
	}
	userID, err := h.Auth.LookupSessionUser(r.Context(), cookie.Value)
	if err != nil {
		return "", false
	}
	return userID, true
}

// authorizeError renders an error page for requests that cannot be safely
// redirected (unknown/inactive client or unregistered redirect URI), and
// redirects with an OAuth error otherwise.
func (h *OAuthHandler) authorizeError(w http.ResponseWriter, r *http.Request, err error, clientID, redirectURI, state string) {
	var code, desc string
	switch {
	case errors.Is(err, apperror.ErrInvalidClientCredentials), errors.Is(err, apperror.ErrClientInactive):
		code, desc = "invalid_client", "unknown or inactive client"
	case errors.Is(err, apperror.ErrInvalidRedirectURI):
		code, desc = "invalid_request", "redirect_uri is not registered for this client"
	case errors.Is(err, apperror.ErrInvalidScope):
		code, desc = "invalid_scope", "requested scope is not allowed"
	default:
		code, desc = "server_error", "internal server error"
	}

	// A registered redirect URI is trustworthy, so surface the error to the
	// client via redirect; otherwise show a plain error page.
	if clientID != "" && redirectURI != "" {
		if _, cErr := h.Service.Clients.Get(r.Context(), clientID); cErr == nil {
			h.redirectOAuthError(w, r, redirectURI, code, desc, state)
			return
		}
	}

	pages.OAuthError(w, pages.OAuthErrorData{Code: code, Description: desc})
}

func (h *OAuthHandler) redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	values := url.Values{"error": {code}, "error_description": {desc}}
	if state != "" {
		values.Set("state", state)
	}
	http.Redirect(w, r, buildAuthorizeRedirect(redirectURI, values), http.StatusFound)
}

func (h *OAuthHandler) renderConsent(w http.ResponseWriter, client Client, userID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string) {
	pages.Consent(w, pages.ConsentData{
		ClientName:          client.Name,
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              pages.ScopeDescriptions(scopeFields(scope)),
	})
}

// authLoginFormRequest builds and validates a login request from the form.
func authLoginFormRequest(r *http.Request) (LoginRequest, error) {
	req := LoginRequest{
		Identifier: normalize.Identifier(r.FormValue("identifier"), ""),
		Password:   r.FormValue("password"),
	}
	if fields := validation.ValidateStruct(req); len(fields) > 0 {
		return LoginRequest{}, apperror.ErrInvalidRequest
	}
	return req, nil
}

// buildAuthorizeRedirect appends query values to a redirect URI.
func buildAuthorizeRedirect(redirectURI string, values url.Values) string {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + values.Encode()
}

// safeNext restricts post-login redirects to same-origin relative paths.
func safeNext(next string) string {
	if next == "" || strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	return "/"
}

func scopeFields(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}
