package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/pkg/config"
	"goleanauth/pkg/jwks"
)

func newTestOAuth(t *testing.T) (*OAuthService, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}

	cfg := &config.Config{
		AccessTokenTTLMinutes: 15,
		RefreshTokenTTLHours:  24,
		Issuer:                "http://auth.test",
	}
	svc := NewOAuthService(db, keys, NewClientService(db), audit.NewAuditService(db), cfg)
	return svc, mock
}

func mockClientAuth(mock sqlmock.Sqlmock, secret, scope string) {
	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}).
		AddRow("client-1", "Test App", scope, true, hashClientSecret(secret), `{"http://app.test/cb"}`)
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)
}

func mockNoClient(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("FROM clients").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}))
}

// mockClientGet returns a client via the public lookup with the given
// redirect URIs (as a Postgres array literal) and allowed scope.
func mockClientGet(mock sqlmock.Sqlmock, scope, redirectURIs string) {
	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "redirect_uris"}).
		AddRow("client-1", "Test App", scope, true, redirectURIs)
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)
}

func mockLoggedInSession(mock sqlmock.Sqlmock, userID string) {
	rows := sqlmock.NewRows([]string{"user_id"}).AddRow(userID)
	mock.ExpectQuery("FROM sessions").WillReturnRows(rows)
}

func TestOAuthTokenClientCredentials(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	tokens, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("Token() returned empty tokens")
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", tokens.TokenType)
	}
	if tokens.Scope != "read" {
		t.Errorf("Scope = %q, want read", tokens.Scope)
	}
	if tokens.ExpiresIn <= 0 {
		t.Error("ExpiresIn must be positive")
	}
}

func TestOAuthTokenScopeNotAllowed(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Scope:        "admin",
	})
	if !errors.Is(err, apperror.ErrInvalidScope) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidScope)
	}
}

func TestOAuthTokenUnsupportedGrant(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "password",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
	})
	if !errors.Is(err, apperror.ErrUnsupportedGrantType) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrUnsupportedGrantType)
	}
}

func TestOAuthTokenInvalidClient(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockNoClient(mock)

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "client-1",
		ClientSecret: "wrong",
	})
	if !errors.Is(err, apperror.ErrInvalidClientCredentials) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidClientCredentials)
	}
}

func TestOAuthTokenRefresh(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope"}).AddRow("session-1", "read"))
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-2"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	tokens, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		RefreshToken: "some-refresh-token",
	})
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("Token() returned empty tokens")
	}
}

func TestOAuthTokenRefreshInvalid(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope"}))
	mock.ExpectRollback()

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		RefreshToken: "unknown-token",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestOAuthIntrospectRefreshActive(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "scope", "expires_at"}).
			AddRow("session-1", nil, "read", time.Now().Add(time.Hour)))

	info, err := svc.Introspect(context.Background(), "client-1", "topsecret", "refresh-token-value")
	if err != nil {
		t.Fatalf("Introspect() unexpected error: %v", err)
	}
	active, _ := info["active"].(bool)
	if !active {
		t.Error("Introspect() expected active=true for valid refresh token")
	}
}

func TestOAuthIssueAuthorizationCode(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mock.ExpectExec("INSERT INTO authorization_codes").WillReturnResult(sqlmock.NewResult(1, 1))

	code, err := svc.IssueAuthorizationCode(context.Background(), "client-1", "user-1", "http://app.test/cb", "read", "", "")
	if err != nil {
		t.Fatalf("IssueAuthorizationCode() unexpected error: %v", err)
	}
	if len(code) < 32 {
		t.Errorf("code too short: %d chars", len(code))
	}
}

func TestOAuthTokenAuthorizationCode(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}).
			AddRow("user-1", "http://app.test/cb", "read", "", ""))
	mock.ExpectExec("UPDATE authorization_codes").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	tokens, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "some-auth-code",
		RedirectURI:  "http://app.test/cb",
	})
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Error("Token() returned empty tokens")
	}
	if tokens.Scope != "read" {
		t.Errorf("Scope = %q, want read", tokens.Scope)
	}
}

func TestOAuthTokenAuthorizationCodePKCE(t *testing.T) {
	svc, mock := newTestOAuth(t)
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}).
			AddRow("user-1", "http://app.test/cb", "read", challenge, "S256"))
	mock.ExpectExec("UPDATE authorization_codes").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	tokens, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "some-auth-code",
		RedirectURI:  "http://app.test/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("Token() returned empty access token")
	}
}

func TestOAuthTokenAuthorizationCodeWrongVerifier(t *testing.T) {
	svc, mock := newTestOAuth(t)
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}).
			AddRow("user-1", "http://app.test/cb", "read", challenge, "S256"))
	mock.ExpectRollback()

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "some-auth-code",
		RedirectURI:  "http://app.test/cb",
		CodeVerifier: "this-is-the-wrong-verifier-value-with-enough-length",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestOAuthTokenAuthorizationCodeMissingVerifier(t *testing.T) {
	svc, mock := newTestOAuth(t)
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}).
			AddRow("user-1", "http://app.test/cb", "read", challenge, "S256"))
	mock.ExpectRollback()

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "some-auth-code",
		RedirectURI:  "http://app.test/cb",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestOAuthTokenAuthorizationCodeReplay(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}))
	mock.ExpectRollback()

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "used-or-expired-code",
		RedirectURI:  "http://app.test/cb",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestOAuthTokenAuthorizationCodeRedirectMismatch(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("FROM authorization_codes").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method"}).
			AddRow("user-1", "http://app.test/cb", "read", "", ""))
	mock.ExpectRollback()

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "client-1",
		ClientSecret: "topsecret",
		Code:         "some-auth-code",
		RedirectURI:  "http://evil.test/cb",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestOAuthValidateAuthorize(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientGet(mock, "read write", `{"http://app.test/cb"}`)

	client, scope, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://app.test/cb", "read", "", "")
	if err != nil {
		t.Fatalf("ValidateAuthorize() unexpected error: %v", err)
	}
	if client.ClientID != "client-1" {
		t.Errorf("client id = %q", client.ClientID)
	}
	if scope != "read" {
		t.Errorf("scope = %q, want read", scope)
	}
}

func TestOAuthValidateAuthorizeUnregisteredRedirect(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientGet(mock, "read write", `{"http://app.test/cb"}`)

	_, _, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://evil.test/cb", "read", "", "")
	if !errors.Is(err, apperror.ErrInvalidRedirectURI) {
		t.Fatalf("ValidateAuthorize() error = %v, want %v", err, apperror.ErrInvalidRedirectURI)
	}
}

func TestOAuthValidateAuthorizeScopeDenied(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientGet(mock, "read write", `{"http://app.test/cb"}`)

	_, _, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://app.test/cb", "admin", "", "")
	if !errors.Is(err, apperror.ErrInvalidScope) {
		t.Fatalf("ValidateAuthorize() error = %v, want %v", err, apperror.ErrInvalidScope)
	}
}

func TestOAuthValidateAuthorizePKCEUnsupportedMethod(t *testing.T) {
	svc, _ := newTestOAuth(t)
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	_, _, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://app.test/cb", "read", challenge, "plain")
	if !errors.Is(err, apperror.ErrInvalidRequest) {
		t.Fatalf("ValidateAuthorize() error = %v, want %v", err, apperror.ErrInvalidRequest)
	}
}

func TestOAuthValidateAuthorizePKCEMalformedChallenge(t *testing.T) {
	svc, _ := newTestOAuth(t)

	_, _, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://app.test/cb", "read", "short", "S256")
	if !errors.Is(err, apperror.ErrInvalidRequest) {
		t.Fatalf("ValidateAuthorize() error = %v, want %v", err, apperror.ErrInvalidRequest)
	}
}

func TestOAuthValidateAuthorizePKCEValid(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientGet(mock, "read write", `{"http://app.test/cb"}`)
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	_, scope, err := svc.ValidateAuthorize(context.Background(), "client-1", "http://app.test/cb", "read", challenge, "S256")
	if err != nil {
		t.Fatalf("ValidateAuthorize() unexpected error: %v", err)
	}
	if scope != "read" {
		t.Errorf("scope = %q, want read", scope)
	}
}

func TestS256Challenge(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := s256Challenge(verifier); got != want {
		t.Errorf("s256Challenge() = %q, want %q", got, want)
	}
}

func TestOAuthRevoke(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(1, 1))

	err := svc.Revoke(context.Background(), "client-1", "topsecret", "refresh-token-value")
	if err != nil {
		t.Fatalf("Revoke() unexpected error: %v", err)
	}
}
