package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/pkg/config"
	"goleanauth/pkg/db"
	"goleanauth/pkg/jwks"
)

// OAuthService implements the token/introspection/revocation flows for
// registered clients.
type OAuthService struct {
	DB              *sql.DB
	Keys            *jwks.KeySet
	Issuer          string
	Clients         *ClientService
	AuditService    *audit.AuditService
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func NewOAuthService(db *sql.DB, keys *jwks.KeySet, clients *ClientService, auditService *audit.AuditService, cfg *config.Config) *OAuthService {
	return &OAuthService{
		DB:              db,
		Keys:            keys,
		Issuer:          cfg.Issuer,
		Clients:         clients,
		AuditService:    auditService,
		AccessTokenTTL:  time.Duration(cfg.AccessTokenTTLMinutes) * time.Minute,
		RefreshTokenTTL: time.Duration(cfg.RefreshTokenTTLHours) * time.Hour,
	}
}

// TokenRequest is a parsed token endpoint request.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Code         string
	RedirectURI  string
	CodeVerifier string
	Scope        string
}

// TokenSet is the OAuth 2.0 token response.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles the client_credentials and refresh_token grants.
func (s *OAuthService) Token(ctx context.Context, req TokenRequest) (TokenSet, error) {
	client, err := s.Clients.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return TokenSet{}, err
	}

	switch req.GrantType {
	case "client_credentials":
		return s.tokenClientCredentials(ctx, client, req.Scope)
	case "refresh_token":
		return s.tokenRefresh(ctx, client, req.RefreshToken)
	case "authorization_code":
		return s.tokenAuthorizationCode(ctx, client, req.Code, req.RedirectURI, req.CodeVerifier)
	default:
		return TokenSet{}, apperror.ErrUnsupportedGrantType
	}
}

func (s *OAuthService) tokenClientCredentials(ctx context.Context, client Client, requestedScope string) (TokenSet, error) {
	scope, err := intersectScope(client.Scope, requestedScope)
	if err != nil {
		return TokenSet{}, err
	}

	var tokens TokenSet

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err = db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		var accessToken, refreshToken string
		_, accessToken, refreshToken, err = createSession(dbCtx, tx, "", &client.ClientID, scope, s.Keys, s.Issuer, s.AccessTokenTTL, s.RefreshTokenTTL)
		if err != nil {
			return err
		}

		tokens = TokenSet{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(s.AccessTokenTTL.Seconds()),
			RefreshToken: refreshToken,
			Scope:        scope,
		}

		return s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			Action:     "client.token_issued",
			EntityType: "client",
			EntityID:   &client.ClientID,
			Metadata:   map[string]any{"grant_type": "client_credentials", "scope": scope},
		})
	})
	if err != nil {
		return TokenSet{}, err
	}

	return tokens, nil
}

func (s *OAuthService) tokenRefresh(ctx context.Context, client Client, refreshToken string) (TokenSet, error) {
	if refreshToken == "" {
		return TokenSet{}, apperror.ErrInvalidRequest
	}

	var tokens TokenSet

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		var sessionID, scope string
		var userID sql.NullString
		hash := hashRefreshToken(refreshToken)

		err := tx.QueryRowContext(dbCtx, `
			SELECT s.id, s.user_id, s.scope
			FROM sessions s
			JOIN clients c ON c.client_id = s.client_id
			WHERE s.refresh_token_hash = $1
			  AND s.client_id = $2
			  AND s.revoked = false
			  AND s.expires_at > NOW()
			  AND c.active = true
		`, hash, client.ClientID).Scan(&sessionID, &userID, &scope)
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrInvalidToken
		}
		if err != nil {
			return apperror.ErrDatabase
		}

		_, err = tx.ExecContext(dbCtx, `
			UPDATE sessions
			SET revoked = true,
			    revoked_at = NOW()
			WHERE id = $1
		`, sessionID)
		if err != nil {
			return apperror.ErrDatabase
		}

		var accessToken, newRefreshToken string
		_, accessToken, newRefreshToken, err = createSession(dbCtx, tx, userID.String, &client.ClientID, scope, s.Keys, s.Issuer, s.AccessTokenTTL, s.RefreshTokenTTL)
		if err != nil {
			return err
		}

		tokens = TokenSet{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(s.AccessTokenTTL.Seconds()),
			RefreshToken: newRefreshToken,
			Scope:        scope,
		}

		return s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     nullableString(userID.String),
			Action:     "client.token_refreshed",
			EntityType: "client",
			EntityID:   &client.ClientID,
			Metadata:   map[string]any{"grant_type": "refresh_token"},
		})
	})
	if err != nil {
		return TokenSet{}, err
	}

	return tokens, nil
}

// tokenAuthorizationCode exchanges an authorization code for tokens. Codes are
// single-use and bound to the client, user, redirect URI, scope, and (when
// present) PKCE challenge recorded at issuance time.
func (s *OAuthService) tokenAuthorizationCode(ctx context.Context, client Client, code, redirectURI, codeVerifier string) (TokenSet, error) {
	if code == "" || redirectURI == "" {
		return TokenSet{}, apperror.ErrInvalidRequest
	}

	var tokens TokenSet

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		var userID, codeRedirectURI, scope string
		var codeChallenge, codeChallengeMethod sql.NullString

		err := tx.QueryRowContext(dbCtx, `
			SELECT ac.user_id, ac.redirect_uri, ac.scope, ac.code_challenge, ac.code_challenge_method
			FROM authorization_codes ac
			JOIN users u ON u.id = ac.user_id
			WHERE ac.code_hash = $1
			  AND ac.client_id = $2
			  AND ac.used = false
			  AND ac.expires_at > NOW()
			  AND u.status = 'active'
		`, hashAuthorizationCode(code), client.ClientID).Scan(&userID, &codeRedirectURI, &scope, &codeChallenge, &codeChallengeMethod)
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrInvalidToken
		}
		if err != nil {
			return apperror.ErrDatabase
		}

		if codeRedirectURI != redirectURI {
			return apperror.ErrInvalidToken
		}

		// PKCE verification (RFC 7636). Completed when the code was issued
		// with a challenge.
		if codeChallenge.Valid && codeChallenge.String != "" {
			if codeChallengeMethod.String != "S256" || codeVerifier == "" {
				return apperror.ErrInvalidToken
			}
			if subtle.ConstantTimeCompare([]byte(s256Challenge(codeVerifier)), []byte(codeChallenge.String)) != 1 {
				return apperror.ErrInvalidToken
			}
		}

		// Single-use: mark consumed before issuing tokens so a replayed code
		// (even in a concurrent request) is rejected.
		_, err = tx.ExecContext(dbCtx, `
			UPDATE authorization_codes
			SET used = true
			WHERE code_hash = $1
		`, hashAuthorizationCode(code))
		if err != nil {
			return apperror.ErrDatabase
		}

		var accessToken, refreshToken string
		_, accessToken, refreshToken, err = createSession(dbCtx, tx, userID, &client.ClientID, scope, s.Keys, s.Issuer, s.AccessTokenTTL, s.RefreshTokenTTL)
		if err != nil {
			return err
		}

		tokens = TokenSet{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(s.AccessTokenTTL.Seconds()),
			RefreshToken: refreshToken,
			Scope:        scope,
		}

		return s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "client.token_issued",
			EntityType: "client",
			EntityID:   &client.ClientID,
			Metadata:   map[string]any{"grant_type": "authorization_code", "scope": scope},
		})
	})
	if err != nil {
		return TokenSet{}, err
	}

	return tokens, nil
}

// authorizationCodeTTL is how long an issued code remains redeemable.
const authorizationCodeTTL = 10 * time.Minute

// ValidateAuthorize validates an authorization request against the registered
// client and returns the client and the granted scope. The caller renders a
// consent page or an error from the result.
func (s *OAuthService) ValidateAuthorize(ctx context.Context, clientID, redirectURI, requestedScope, codeChallenge, codeChallengeMethod string) (Client, string, error) {
	if err := validateCodeChallenge(codeChallenge, codeChallengeMethod); err != nil {
		return Client{}, "", err
	}

	client, err := s.Clients.Get(ctx, clientID)
	if errors.Is(err, apperror.ErrClientNotFound) {
		return Client{}, "", apperror.ErrInvalidClientCredentials
	}
	if err != nil {
		return Client{}, "", err
	}
	if !client.Active {
		return Client{}, "", apperror.ErrClientInactive
	}

	if !s.redirectURIRegistered(client.RedirectURIs, redirectURI) {
		return Client{}, "", apperror.ErrInvalidRedirectURI
	}

	scope, err := intersectScope(client.Scope, requestedScope)
	if err != nil {
		return Client{}, "", err
	}

	return client, scope, nil
}

// validateCodeChallenge enforces RFC 7636 S256 challenges. An absent
// challenge is allowed; when present, the method must be S256 and the value a
// URL-safe base64 string of 43–128 characters.
func validateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return nil
	}
	if method != "S256" {
		return apperror.ErrInvalidRequest
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		return apperror.ErrInvalidRequest
	}
	for _, r := range challenge {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return apperror.ErrInvalidRequest
		}
	}
	return nil
}

// s256Challenge derives the PKCE S256 code challenge for a verifier.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// redirectURIRegistered reports whether the presented redirect URI exactly
// matches one of the client's registered redirect URIs.
func (s *OAuthService) redirectURIRegistered(registered []string, redirectURI string) bool {
	for _, u := range registered {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// IssueAuthorizationCode creates a single-use, short-lived authorization code
// bound to the client, user, redirect URI, and granted scope. A PKCE S256
// challenge is recorded when supplied.
func (s *OAuthService) IssueAuthorizationCode(ctx context.Context, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", apperror.ErrInternalServer
	}
	code := hex.EncodeToString(codeBytes)

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	_, err := s.DB.ExecContext(dbCtx, `
		INSERT INTO authorization_codes (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, hashAuthorizationCode(code), clientID, userID, redirectURI, scope, nullableString(codeChallenge), nullableString(codeChallengeMethod), time.Now().Add(authorizationCodeTTL))
	if err != nil {
		return "", apperror.ErrDatabase
	}

	return code, nil
}

// hashAuthorizationCode hashes an authorization code with SHA-256 so only the
// digest is persisted, mirroring refresh-token handling.
func hashAuthorizationCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Introspect validates an access token (JWT) or refresh token and returns its
// active state and principal claims. The caller must be an authenticated client.
func (s *OAuthService) Introspect(ctx context.Context, clientID, clientSecret, token string) (map[string]any, error) {
	if _, err := s.Clients.Authenticate(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	if token == "" {
		return nil, apperror.ErrInvalidRequest
	}

	// Access tokens are JWTs; check the signature and session state.
	if claims, err := s.Keys.Parse(token); err == nil && claims.SessionID != "" {
		return s.introspectAccess(ctx, claims)
	}

	// Otherwise treat it as a refresh token.
	return s.introspectRefresh(ctx, clientID, token)
}

func (s *OAuthService) introspectAccess(ctx context.Context, claims *jwks.Claims) (map[string]any, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var revoked, expired bool
	err := s.DB.QueryRowContext(dbCtx, `
		SELECT revoked, expires_at < NOW()
		FROM sessions
		WHERE id = $1
	`, claims.SessionID).Scan(&revoked, &expired)
	if errors.Is(err, sql.ErrNoRows) || revoked || expired {
		return map[string]any{"active": false}, nil
	}
	if err != nil {
		return nil, apperror.ErrDatabase
	}

	return map[string]any{
		"active":     true,
		"sub":        claims.Subject,
		"session_id": claims.SessionID,
		"client_id":  claims.ClientID,
		"scope":      claims.Scope,
		"iss":        claims.Issuer,
		"aud":        []string(claims.Audience),
		"exp":        claims.ExpiresAt,
		"iat":        claims.IssuedAt,
	}, nil
}

func (s *OAuthService) introspectRefresh(ctx context.Context, clientID, token string) (map[string]any, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var sessionID, scope string
	var userID sql.NullString
	var expiresAt time.Time

	err := s.DB.QueryRowContext(dbCtx, `
		SELECT s.id, s.user_id, s.scope, s.expires_at
		FROM sessions s
		JOIN clients c ON c.client_id = s.client_id
		WHERE s.refresh_token_hash = $1
		  AND s.client_id = $2
		  AND s.revoked = false
		  AND c.active = true
	`, hashRefreshToken(token), clientID).Scan(&sessionID, &userID, &scope, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]any{"active": false}, nil
	}
	if err != nil {
		return nil, apperror.ErrDatabase
	}

	active := expiresAt.After(time.Now())

	result := map[string]any{
		"active":     active,
		"session_id": sessionID,
		"client_id":  clientID,
		"scope":      scope,
		"exp":        expiresAt.Unix(),
	}
	if userID.Valid {
		result["sub"] = userID.String
	}

	return result, nil
}

// Revoke invalidates a refresh token. Per RFC 7009 it always succeeds.
func (s *OAuthService) Revoke(ctx context.Context, clientID, clientSecret, token string) error {
	if _, err := s.Clients.Authenticate(ctx, clientID, clientSecret); err != nil {
		return err
	}
	if token == "" {
		return apperror.ErrInvalidRequest
	}

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	_, err := s.DB.ExecContext(dbCtx, `
		UPDATE sessions
		SET revoked = true,
		    revoked_at = NOW()
		WHERE refresh_token_hash = $1
	`, hashRefreshToken(token))
	if err != nil {
		return apperror.ErrDatabase
	}

	return nil
}

// UserInfo returns the standard claims for an authenticated user.
func (s *OAuthService) UserInfo(ctx context.Context, userID string) (map[string]any, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var email, firstName, lastName string
	var emailVerified bool
	var emailValid bool

	err := s.DB.QueryRowContext(dbCtx, `
		SELECT COALESCE(email, ''), first_name, last_name, email_verified, email IS NOT NULL
		FROM users
		WHERE id = $1
	`, userID).Scan(&email, &firstName, &lastName, &emailVerified, &emailValid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperror.ErrUserNotFound
	}
	if err != nil {
		return nil, apperror.ErrDatabase
	}

	info := map[string]any{
		"sub": userID,
	}
	if emailValid {
		info["email"] = email
		info["email_verified"] = emailVerified
	}
	if firstName != "" {
		info["given_name"] = firstName
	}
	if lastName != "" {
		info["family_name"] = lastName
	}
	if firstName != "" || lastName != "" {
		info["name"] = strings.TrimSpace(firstName + " " + lastName)
	}

	return info, nil
}

// intersectScope returns the intersection of the requested scope with the
// client's allowed scope. An empty requested scope grants the full allowed
// scope; any out-of-allowed scope is rejected.
func intersectScope(allowed, requested string) (string, error) {
	allowedSet := scopeSet(allowed)

	if requested == "" {
		return allowed, nil
	}

	var granted []string
	for _, s := range strings.Fields(requested) {
		if !allowedSet[s] {
			return "", apperror.ErrInvalidScope
		}
		granted = append(granted, s)
	}

	return strings.Join(granted, " "), nil
}

func scopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}
