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
	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash"}).
		AddRow("client-1", "Test App", scope, true, hashClientSecret(secret))
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)
}

func mockNoClient(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("FROM clients").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash"}))
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

func TestOAuthRevoke(t *testing.T) {
	svc, mock := newTestOAuth(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(1, 1))

	err := svc.Revoke(context.Background(), "client-1", "topsecret", "refresh-token-value")
	if err != nil {
		t.Fatalf("Revoke() unexpected error: %v", err)
	}
}
