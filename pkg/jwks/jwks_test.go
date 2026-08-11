package jwks

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndVerify(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "http://localhost:8080",
			Audience:  jwt.ClaimStrings{"http://localhost:8080"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		SessionID: "session-1",
	}

	token, err := ks.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	parsed, err := ks.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if parsed.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", parsed.Subject)
	}
	if parsed.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want session-1", parsed.SessionID)
	}
	if len(parsed.Audience) == 0 || parsed.Audience[0] != "http://localhost:8080" {
		t.Errorf("Audience = %v, want issuer", parsed.Audience)
	}
}

func TestParseRejectsTamperedToken(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	token, err := ks.Sign(Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	})
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if _, err := ks.Parse(token + "tampered"); err == nil {
		t.Error("Parse() expected error for tampered token")
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	other, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	token, err := other.Sign(Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if _, err := ks.Parse(token); err == nil {
		t.Error("Parse() expected error for token signed by other key")
	}
}

func TestLoadFromPEM(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))

	ks, err := Load(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	token, err := ks.Sign(Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	parsed, err := ks.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error after Load: %v", err)
	}
	if parsed.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", parsed.Subject)
	}
}

func TestJWKS(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	body, err := ks.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error: %v", err)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Alg != "EdDSA" || key.Use != "sig" {
		t.Errorf("unexpected jwk: %+v", key)
	}
	if key.Kid != ks.KeyID() {
		t.Errorf("kid = %q, want %q", key.Kid, ks.KeyID())
	}
}
