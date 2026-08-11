package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
)

func newTestHandler() *AuthHandler {
	cfg := &config.Config{AppEnv: "test", RefreshTokenTTLHours: 24}
	return NewAuthHandler(&AuthService{}, cfg)
}

type errorBody struct {
	Success bool `json:"success"`
	Error   struct {
		Code   string            `json:"code"`
		Fields map[string]string `json:"fields"`
	} `json:"error"`
}

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return body
}

func TestRegister_InvalidJSON(t *testing.T) {
	validation.Init()
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewBufferString("{"))
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if body := decodeError(t, rr); body.Error.Code != "invalid_request_body" {
		t.Errorf("error code = %q, want invalid_request_body", body.Error.Code)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	validation.Init()
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewBufferString(
		`{"email":"not-an-email","password":"12345678","first_name":"Miracle","last_name":"Chukwu"}`,
	))
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	body := decodeError(t, rr)
	if body.Error.Code != "validation_error" {
		t.Errorf("error code = %q, want validation_error", body.Error.Code)
	}
	if _, ok := body.Error.Fields["Email"]; !ok {
		t.Errorf("expected validation error on Email field, got %v", body.Error.Fields)
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	validation.Init()
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString("{"))
	rr := httptest.NewRecorder()

	h.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if body := decodeError(t, rr); body.Error.Code != "invalid_request_body" {
		t.Errorf("error code = %q, want invalid_request_body", body.Error.Code)
	}
}

func TestRefreshToken_NoCookie(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	rr := httptest.NewRecorder()

	h.RefreshToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if body := decodeError(t, rr); body.Error.Code != "invalid_token" {
		t.Errorf("error code = %q, want invalid_token", body.Error.Code)
	}
}

func TestGoogleLogin_NotConfigured(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/google/login", nil)
	rr := httptest.NewRecorder()

	h.GoogleLoginHandler(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if body := decodeError(t, rr); body.Error.Code != "provider_not_configured" {
		t.Errorf("error code = %q, want provider_not_configured", body.Error.Code)
	}
}
