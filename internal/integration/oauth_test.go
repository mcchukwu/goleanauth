//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/internal/auth"
	"goleanauth/pkg/jwks"
)

// s256Challenge mirrors the service's RFC 7636 challenge derivation.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newOAuth(t *testing.T) (*auth.OAuthService, *auth.ClientService, *jwks.KeySet) {
	t.Helper()
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate(): %v", err)
	}
	clients := auth.NewClientService(db)
	oauth := auth.NewOAuthService(db, keys, clients, audit.NewAuditService(db), testConfig())
	return oauth, clients, keys
}

const integrationRedirectURI = "http://localhost:9999/integration/cb"

func TestClientCredentialsIntrospectRevoke(t *testing.T) {
	oauth, clients, keys := newOAuth(t)
	ctx := context.Background()

	clientID, clientSecret, err := clients.RegisterClient(ctx, "Integration Machine", "openid profile email read write", integrationRedirectURI)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	ts, err := oauth.Token(ctx, auth.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        "read",
	})
	if err != nil {
		t.Fatalf("client_credentials Token: %v", err)
	}
	claims := parseAccess(t, keys, ts.AccessToken)
	if claims.ClientID != clientID {
		t.Fatalf("access token cid = %q, want %q", claims.ClientID, clientID)
	}
	if claims.Subject != "" {
		t.Fatalf("machine token sub = %q, want empty", claims.Subject)
	}

	active, err := oauth.Introspect(ctx, clientID, clientSecret, ts.AccessToken)
	if err != nil {
		t.Fatalf("Introspect access token: %v", err)
	}
	if active["active"] != true {
		t.Fatalf("Introspect active = %v, want true", active["active"])
	}

	// Refresh_token grant rotates the machine session; the old refresh fails.
	ts2, err := oauth.Token(ctx, auth.TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: ts.RefreshToken,
	})
	if err != nil {
		t.Fatalf("refresh_token Token: %v", err)
	}
	if _, err := oauth.Token(ctx, auth.TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: ts.RefreshToken,
	}); !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("reused refresh token = %v, want ErrInvalidToken", err)
	}

	if err := oauth.Revoke(ctx, clientID, clientSecret, ts2.RefreshToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := oauth.Token(ctx, auth.TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: ts2.RefreshToken,
	}); !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("refresh after revoke = %v, want ErrInvalidToken", err)
	}
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	oauth, clients, keys := newOAuth(t)
	svc := newAuthService(t)
	ctx := context.Background()

	userID, _ := registerAndLogin(t, svc, uniqueEmail())

	clientID, clientSecret, err := clients.RegisterClient(ctx, "Integration Web", "openid profile email", integrationRedirectURI)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 vector
	challenge := s256Challenge(verifier)

	// A malformed challenge must be rejected before any consent.
	if _, _, err := oauth.ValidateAuthorize(ctx, clientID, integrationRedirectURI, "openid profile email", "tooshort", "S256"); !errors.Is(err, apperror.ErrInvalidRequest) {
		t.Fatalf("ValidateAuthorize with short challenge = %v, want ErrInvalidRequest", err)
	}

	_, scope, err := oauth.ValidateAuthorize(ctx, clientID, integrationRedirectURI, "openid profile email", challenge, "S256")
	if err != nil {
		t.Fatalf("ValidateAuthorize: %v", err)
	}
	if scope != "openid profile email" {
		t.Fatalf("granted scope = %q, want %q", scope, "openid profile email")
	}

	code, err := oauth.IssueAuthorizationCode(ctx, clientID, userID, integrationRedirectURI, scope, challenge, "S256")
	if err != nil {
		t.Fatalf("IssueAuthorizationCode: %v", err)
	}

	codeReq := auth.TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  integrationRedirectURI,
		CodeVerifier: verifier,
	}

	ts, err := oauth.Token(ctx, codeReq)
	if err != nil {
		t.Fatalf("authorization_code Token: %v", err)
	}
	claims := parseAccess(t, keys, ts.AccessToken)
	if claims.Subject != userID {
		t.Fatalf("authorization_code sub = %q, want %q", claims.Subject, userID)
	}

	info, err := oauth.UserInfo(ctx, userID)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info["sub"] != userID {
		t.Fatalf("UserInfo sub = %v, want %q", info["sub"], userID)
	}

	// Single-use: replaying the code must fail.
	if _, err := oauth.Token(ctx, codeReq); !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("replayed authorization code = %v, want ErrInvalidToken", err)
	}
}

func TestAuthorizationCodePKCEMismatch(t *testing.T) {
	oauth, clients, _ := newOAuth(t)
	svc := newAuthService(t)
	ctx := context.Background()

	userID, _ := registerAndLogin(t, svc, uniqueEmail())

	clientID, clientSecret, err := clients.RegisterClient(ctx, "Integration Web 2", "openid profile email", integrationRedirectURI)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := s256Challenge(verifier)

	_, scope, err := oauth.ValidateAuthorize(ctx, clientID, integrationRedirectURI, "openid profile email", challenge, "S256")
	if err != nil {
		t.Fatalf("ValidateAuthorize: %v", err)
	}
	code, err := oauth.IssueAuthorizationCode(ctx, clientID, userID, integrationRedirectURI, scope, challenge, "S256")
	if err != nil {
		t.Fatalf("IssueAuthorizationCode: %v", err)
	}

	_, err = oauth.Token(ctx, auth.TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  integrationRedirectURI,
		CodeVerifier: "a-different-verifier-that-is-also-plenty-long-enough-XYZ",
	})
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("Token with wrong verifier = %v, want ErrInvalidToken", err)
	}
}
