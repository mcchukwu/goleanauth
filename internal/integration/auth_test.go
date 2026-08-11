//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/internal/auth"
	"goleanauth/pkg/config"
	"goleanauth/pkg/jwks"
)

func testConfig() *config.Config {
	return &config.Config{
		Issuer:                "http://integration.test",
		AccessTokenTTLMinutes: 15,
		RefreshTokenTTLHours:  24,
	}
}

func newKeySet(t *testing.T) *jwks.KeySet {
	t.Helper()
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate(): %v", err)
	}
	return keys
}

func newAuthService(t *testing.T) *auth.AuthService {
	t.Helper()
	return auth.NewAuthService(db, newKeySet(t), audit.NewAuditService(db), testConfig())
}

func parseAccess(t *testing.T, keys *jwks.KeySet, token string) *jwks.Claims {
	t.Helper()
	claims, err := keys.Parse(token)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}
	return claims
}

func uniqueEmail() string {
	return fmt.Sprintf("int%d@example.com", time.Now().UnixNano())
}

func registerAndLogin(t *testing.T, svc *auth.AuthService, email string) (userID string, refresh string) {
	t.Helper()
	if err := svc.Register(context.Background(), auth.RegisterRequest{
		Email:     email,
		FirstName: "Integ",
		LastName:  "Tester",
		Password:  "integration-pass-7",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	access, refresh, err := svc.Login(context.Background(), auth.LoginRequest{
		Identifier: email,
		Password:   "integration-pass-7",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	claims := parseAccess(t, svc.Keys, access)
	return claims.Subject, refresh
}

func TestRegisterDuplicateAndLogin(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	email := uniqueEmail()

	if err := svc.Register(ctx, auth.RegisterRequest{
		Email:     email,
		FirstName: "Integ",
		LastName:  "Tester",
		Password:  "integration-pass-7",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := svc.Register(ctx, auth.RegisterRequest{
		Email:     email,
		FirstName: "Integ",
		LastName:  "Tester",
		Password:  "integration-pass-7",
	})
	if !errors.Is(err, apperror.ErrEmailAlreadyExists) {
		t.Fatalf("duplicate Register = %v, want ErrEmailAlreadyExists", err)
	}

	if _, _, err := svc.Login(ctx, auth.LoginRequest{Identifier: email, Password: "wrong-password-9"}); !errors.Is(err, apperror.ErrInvalidPassword) {
		t.Fatalf("Login with wrong password = %v, want ErrInvalidPassword", err)
	}
}

func TestRefreshRotationAndLogout(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	email := uniqueEmail()

	userID, refresh1 := registerAndLogin(t, svc, email)
	if userID == "" {
		t.Fatal("expected a user subject in access token")
	}

	// First refresh rotates: the presented token is revoked.
	access2, refresh2, err := svc.RefreshToken(ctx, refresh1)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	claims := parseAccess(t, svc.Keys, access2)
	if claims.Subject != userID {
		t.Fatalf("refreshed subject = %q, want %q", claims.Subject, userID)
	}

	// Reusing the old refresh token must fail after rotation.
	if _, _, err := svc.RefreshToken(ctx, refresh1); !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("reused refresh token = %v, want ErrInvalidToken", err)
	}

	// Logout revokes the current session.
	if err := svc.Logout(ctx, claims.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, _, err := svc.RefreshToken(ctx, refresh2); !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("refresh after logout = %v, want ErrInvalidToken", err)
	}
}
