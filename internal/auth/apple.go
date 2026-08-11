package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"goleanauth/pkg/config"
)

// Sign in with Apple endpoints (see developer.apple.com).
const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleJWKSURL  = "https://appleid.apple.com/auth/keys"
)

// appleConfig holds the runtime Apple OAuth configuration. Apple requires a
// paid developer account to obtain real credentials; a placeholder setup is
// accepted so the flow can be wired up and tested before provisioning.
var appleConfig struct {
	clientID    string // Services ID / bundle identifier
	teamID      string
	keyID       string
	privateKey  *ecdsa.PrivateKey
	redirectURL string
	configured  bool
}

// initApple wires the Apple configuration. It is a no-op when APPLE_CLIENT_ID
// is unset so the server can run without Apple credentials.
func initApple(cfg *config.Config) error {
	appleConfig = struct {
		clientID    string
		teamID      string
		keyID       string
		privateKey  *ecdsa.PrivateKey
		redirectURL string
		configured  bool
	}{
		clientID:    cfg.AppleClientID,
		teamID:      cfg.AppleTeamID,
		keyID:       cfg.AppleKeyID,
		redirectURL: cfg.AppleRedirectURL,
	}

	if cfg.AppleClientID == "" {
		return nil
	}

	key, err := parseApplePrivateKey(cfg.ApplePrivateKey)
	if err != nil {
		return err
	}
	appleConfig.privateKey = key
	appleConfig.configured = true
	return nil
}

// appleAuthorizeURL builds the Sign in with Apple authorization URL.
func appleAuthorizeURL(state string) string {
	q := url.Values{
		"client_id":     {appleConfig.clientID},
		"redirect_uri":  {appleConfig.redirectURL},
		"response_type": {"code"},
		"scope":         {"name email"},
		"state":         {state},
		"response_mode": {"query"},
	}
	return appleAuthURL + "?" + q.Encode()
}

// appleTokenResponse is the Apple token endpoint response.
type appleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

// exchangeAppleCode exchanges the authorization code for tokens using a
// client secret JWT signed with the Apple private key.
func exchangeAppleCode(ctx context.Context, code string) (appleTokenResponse, error) {
	secret, err := buildAppleClientSecret()
	if err != nil {
		return appleTokenResponse{}, err
	}

	form := url.Values{
		"client_id":     {appleConfig.clientID},
		"client_secret": {secret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {appleConfig.redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return appleTokenResponse{}, fmt.Errorf("apple token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return appleTokenResponse{}, fmt.Errorf("apple token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return appleTokenResponse{}, fmt.Errorf("apple token read: %w", err)
	}

	var out appleTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return appleTokenResponse{}, fmt.Errorf("apple token parse: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		if out.Error == "" {
			out.Error = "token endpoint returned status " + resp.Status
		}
		return appleTokenResponse{}, fmt.Errorf("apple token error: %s", out.Error)
	}
	return out, nil
}

// buildAppleClientSecret signs the ES256 client secret JWT required by Apple.
func buildAppleClientSecret() (string, error) {
	if !appleConfig.configured {
		return "", errors.New("apple sign in is not configured")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": appleConfig.teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": appleConfig.clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = appleConfig.keyID
	return token.SignedString(appleConfig.privateKey)
}

// parseApplePrivateKey parses an Apple .p8 private key (PKCS#8 or SEC1 EC).
func parseApplePrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemData)))
	if block == nil {
		return nil, errors.New("apple private key: no PEM block found")
	}

	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("apple private key: parse pkcs8: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("apple private key: not an EC key")
		}
		return ecKey, nil
	case "EC PRIVATE KEY": // SEC1
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("apple private key: unsupported PEM type %q", block.Type)
	}
}

// appleIDTokenClaims is the subset of the Apple id_token claims we need.
type appleIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	jwt.RegisteredClaims
}

// parseAppleIDToken verifies the id_token signature against Apple's JWKS and
// returns the subject (Apple user id) and email.
func parseAppleIDToken(idToken string) (sub, email string, err error) {
	claims := &appleIDTokenClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))

	_, err = parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("apple id token: missing kid")
		}
		return applePublicKey(kid)
	})
	if err != nil {
		return "", "", fmt.Errorf("apple id token verify: %w", err)
	}
	if claims.Subject == "" {
		return "", "", errors.New("apple id token: missing sub")
	}
	return claims.Subject, claims.Email, nil
}

// appleJWKS is a cached copy of Apple's public signing keys.
var appleJWKSCache = struct {
	sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}{}

const appleJWKSTTL = time.Hour

func applePublicKey(kid string) (*ecdsa.PublicKey, error) {
	appleJWKSCache.Lock()
	defer appleJWKSCache.Unlock()

	if key, ok := appleJWKSCache.keys[kid]; ok && time.Since(appleJWKSCache.fetchedAt) < appleJWKSTTL {
		return key, nil
	}

	keys, err := fetchAppleJWKS()
	if err != nil {
		return nil, err
	}
	appleJWKSCache.keys = keys
	appleJWKSCache.fetchedAt = time.Now()

	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("apple jwks: no key for kid %q", kid)
}

type appleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func fetchAppleJWKS() (map[string]*ecdsa.PublicKey, error) {
	resp, err := http.Get(appleJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("apple jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("apple jwks read: %w", err)
	}

	var list struct {
		Keys []appleJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("apple jwks parse: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey)
	for _, j := range list.Keys {
		if j.Kty != "EC" || j.Crv != "P-256" || j.Use != "sig" {
			continue
		}
		xb, errX := base64.RawURLEncoding.DecodeString(j.X)
		yb, errY := base64.RawURLEncoding.DecodeString(j.Y)
		if errX != nil || errY != nil {
			continue
		}
		keys[j.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("apple jwks: no usable keys")
	}
	return keys, nil
}

// appleUserPayload is the JSON user object Apple returns on first sign-in.
type appleUserPayload struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
	Email string `json:"email"`
}

// parseAppleUserParam parses the `user` query parameter sent by Apple on the
// first authorization.
func parseAppleUserParam(raw string) appleUserPayload {
	var out appleUserPayload
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}
