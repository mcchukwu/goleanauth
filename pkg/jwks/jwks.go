// Package jwks provides Ed25519 signing key management, JWT issuance and
// verification, and a JWKS endpoint for downstream services.
//
// Tokens are signed with EdDSA (Ed25519) and carry a key ID (kid) so keys can
// be rotated without invalidating existing tokens. Verification accepts any
// key in the set, while only the active private key signs.
package jwks

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the claims set issued and consumed by goleanauth. It embeds the
// standard registered claims (sub, iss, aud, exp, iat, jti) plus the
// goleanauth-specific session and client identifiers.
type Claims struct {
	jwt.RegisteredClaims

	SessionID string   `json:"sid,omitempty"`
	ClientID  string   `json:"cid,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// KeySet holds the active signing key and every public key accepted for
// verification. Retired public keys can be added to keep old tokens valid
// across rotation.
type KeySet struct {
	signingPrivate ed25519.PrivateKey
	signingKeyID   string
	verifiers      map[string]ed25519.PublicKey
}

// Generate creates a fresh ephemeral signing key. Use for development only;
// persisted keys come from Load.
func Generate() (*KeySet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}

	ks := &KeySet{
		signingPrivate: priv,
		signingKeyID:   keyID(pub),
		verifiers:      make(map[string]ed25519.PublicKey),
	}
	ks.verifiers[ks.signingKeyID] = pub

	return ks, nil
}

// Load parses a signing private key (PKCS#8 PEM) and optionally additional
// public keys (PKIX PEM), any of which can be set with other trusted keys used
// for verification only.
func Load(privatePEM string, extraPublicPEMs ...string) (*KeySet, error) {
	priv, err := privateKeyFromPEM(privatePEM)
	if err != nil {
		return nil, err
	}

	ks, err := Generate()
	if err != nil {
		return nil, err
	}

	ks.signingPrivate = priv
	pub := priv.Public().(ed25519.PublicKey)
	ks.signingKeyID = keyID(pub)
	ks.verifiers = map[string]ed25519.PublicKey{ks.signingKeyID: pub}

	for _, pemData := range extraPublicPEMs {
		pubs, err := publicKeysFromPEM(pemData)
		if err != nil {
			return nil, err
		}
		for _, p := range pubs {
			ks.verifiers[keyID(p)] = p
		}
	}

	return ks, nil
}

// AddVerificationKey adds a public key used for verification only (rotation).
func (ks *KeySet) AddVerificationKey(pub ed25519.PublicKey) {
	ks.verifiers[keyID(pub)] = pub
}

// KeyID returns the identifier of the active signing key.
func (ks *KeySet) KeyID() string {
	return ks.signingKeyID
}

// Sign issues an EdDSA-signed JWT carrying the active key ID.
func (ks *KeySet) Sign(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = ks.signingKeyID

	signed, err := token.SignedString(ks.signingPrivate)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signed, nil
}

// Parse verifies a token against the known public keys and returns its claims.
func (ks *KeySet) Parse(tokenString string) (*Claims, error) {
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}

		kid, _ := token.Header["kid"].(string)
		pub, ok := ks.verifiers[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}

		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// JWKS builds the RFC 7517 JSON Web Key Set for the public endpoint.
func (ks *KeySet) JWKS() ([]byte, error) {
	keys := make([]map[string]string, 0, len(ks.verifiers))
	for kid, pub := range ks.verifiers {
		keys = append(keys, map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": kid,
			"use": "sig",
			"alg": "EdDSA",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		})
	}

	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, fmt.Errorf("marshaling jwks: %w", err)
	}

	return body, nil
}

// keyID derives a stable key identifier from the public key bytes.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func privateKeyFromPEM(pemData string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid PEM: no private key block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an Ed25519 key")
	}

	return priv, nil
}

func publicKeysFromPEM(pemData string) ([]ed25519.PublicKey, error) {
	var pubs []ed25519.PublicKey

	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}

		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not an Ed25519 key")
		}

		pubs = append(pubs, pub)
	}

	if len(pubs) == 0 {
		return nil, errors.New("invalid PEM: no public key block found")
	}

	return pubs, nil
}
