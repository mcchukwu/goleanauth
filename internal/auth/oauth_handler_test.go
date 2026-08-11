package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"goleanauth/pkg/jwks"
)

func newTestOAuthHandler(t *testing.T) (*OAuthHandler, sqlmock.Sqlmock) {
	t.Helper()
	svc, mock := newTestOAuth(t)
	h := &OAuthHandler{Service: svc}
	return h, mock
}

func tokenFormRequest(t *testing.T, params map[string]string) *http.Request {
	t.Helper()
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestOAuthTokenHandler(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	rr := httptest.NewRecorder()
	h.Token(rr, tokenFormRequest(t, map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "topsecret",
		"scope":         "read",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["access_token"] == "" || body["refresh_token"] == "" {
		t.Error("handler response missing tokens")
	}
}

func TestOAuthTokenHandlerBasicAuth(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	req := tokenFormRequest(t, map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "topsecret",
	})
	req.SetBasicAuth("client-1", "topsecret")

	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestOAuthTokenHandlerUnsupportedGrant(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockClientAuth(mock, "topsecret", "read write")

	rr := httptest.NewRecorder()
	h.Token(rr, tokenFormRequest(t, map[string]string{
		"grant_type":    "password",
		"client_id":     "client-1",
		"client_secret": "topsecret",
	}))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %q, want unsupported_grant_type", body["error"])
	}
}

func TestOAuthTokenHandlerInvalidClient(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockNoClient(mock)

	rr := httptest.NewRecorder()
	h.Token(rr, tokenFormRequest(t, map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "wrong",
	}))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

func TestOAuthIntrospectHandler(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "scope", "expires_at"}).
			AddRow("session-1", nil, "read", time.Now().Add(time.Hour)))

	rr := httptest.NewRecorder()
	h.Introspect(rr, tokenFormRequest(t, map[string]string{
		"client_id":     "client-1",
		"client_secret": "topsecret",
		"token":         "refresh-token-value",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["active"] != true {
		t.Errorf("active = %v, want true", body["active"])
	}
}

func TestOAuthRevokeHandler(t *testing.T) {
	h, mock := newTestOAuthHandler(t)
	mockClientAuth(mock, "topsecret", "read write")
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(1, 1))

	rr := httptest.NewRecorder()
	h.Revoke(rr, tokenFormRequest(t, map[string]string{
		"client_id":     "client-1",
		"client_secret": "topsecret",
		"token":         "refresh-token-value",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.Len() != 0 {
		t.Errorf("expected empty body, got %q", rr.Body.String())
	}
}

func TestOAuthUserInfoHandlerUnauthorized(t *testing.T) {
	h, _ := newTestOAuthHandler(t)

	rr := httptest.NewRecorder()
	h.UserInfo(rr, httptest.NewRequest(http.MethodGet, "/v1/userinfo", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestOAuthDiscovery(t *testing.T) {
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}
	h := &OAuthHandler{Service: &OAuthService{
		Issuer: "http://auth.test",
		Keys:   keys,
	}}

	rr := httptest.NewRecorder()
	h.Discovery(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["issuer"] != "http://auth.test" {
		t.Errorf("issuer = %v, want http://auth.test", body["issuer"])
	}
}

func TestOAuthJWKS(t *testing.T) {
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}
	h := &OAuthHandler{Service: &OAuthService{Keys: keys}}

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := body["keys"]; !ok {
		t.Error("JWKS missing keys")
	}
}
