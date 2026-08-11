package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"goleanauth/pkg/config"
)

// testAppleConfig wires a throwaway EC key into the package Apple config.
func testAppleConfig(t *testing.T) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	cfg := &config.Config{
		AppleClientID:    "com.example.services",
		AppleTeamID:      "TEAM1234",
		AppleKeyID:       "KEYID5678",
		ApplePrivateKey:  pemData,
		AppleRedirectURL: "http://localhost:8080/v1/auth/apple/callback",
	}
	if err := initApple(cfg); err != nil {
		t.Fatalf("initApple() error: %v", err)
	}
}

func TestAppleClientSecretClaims(t *testing.T) {
	testAppleConfig(t)

	secret, err := buildAppleClientSecret()
	if err != nil {
		t.Fatalf("buildAppleClientSecret() unexpected error: %v", err)
	}

	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(secret, claims)
	if err != nil {
		t.Fatalf("ParseUnverified() error: %v", err)
	}

	if alg := parsed.Method.Alg(); alg != "ES256" {
		t.Errorf("alg = %q, want ES256", alg)
	}
	if parsed.Header["kid"] != "KEYID5678" {
		t.Errorf("kid = %v, want KEYID5678", parsed.Header["kid"])
	}
	if claims["iss"] != "TEAM1234" {
		t.Errorf("iss = %v, want TEAM1234", claims["iss"])
	}
	if claims["sub"] != "com.example.services" {
		t.Errorf("sub = %v, want com.example.services", claims["sub"])
	}
	if claims["aud"] != "https://appleid.apple.com" {
		t.Errorf("aud = %v, want https://appleid.apple.com", claims["aud"])
	}
}

func TestAppleClientSecretUnconfigured(t *testing.T) {
	if err := initApple(&config.Config{}); err != nil {
		t.Fatalf("initApple() unexpected error: %v", err)
	}

	if _, err := buildAppleClientSecret(); err == nil {
		t.Error("buildAppleClientSecret() expected error when unconfigured")
	}
}

func TestAppleAuthorizeURL(t *testing.T) {
	testAppleConfig(t)

	raw := appleAuthorizeURL("state-123")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}

	q := u.Query()
	for key, want := range map[string]string{
		"client_id":     "com.example.services",
		"redirect_uri":  "http://localhost:8080/v1/auth/apple/callback",
		"response_type": "code",
		"scope":         "name email",
		"state":         "state-123",
	} {
		if q.Get(key) != want {
			t.Errorf("query %q = %q, want %q", key, q.Get(key), want)
		}
	}
}

func TestParseAppleUserParam(t *testing.T) {
	payload := parseAppleUserParam(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}`)
	if payload.Name.FirstName != "Ada" || payload.Name.LastName != "Lovelace" {
		t.Errorf("name = %+v", payload.Name)
	}
	if payload.Email != "ada@example.com" {
		t.Errorf("email = %q", payload.Email)
	}

	empty := parseAppleUserParam("")
	if empty.Name.FirstName != "" || empty.Email != "" {
		t.Errorf("expected empty payload, got %+v", empty)
	}
}

func TestParseApplePrivateKeyPKCS8AndSEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if _, err := parseApplePrivateKey(pkcs8PEM); err != nil {
		t.Errorf("PKCS8 parse error: %v", err)
	}

	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error: %v", err)
	}
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if _, err := parseApplePrivateKey(sec1PEM); err != nil {
		t.Errorf("SEC1 parse error: %v", err)
	}

	if _, err := parseApplePrivateKey("not pem"); err == nil {
		t.Error("parseApplePrivateKey() expected error for garbage input")
	}
}
