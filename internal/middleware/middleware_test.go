package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"

	"goleanauth/internal/requestctx"
	"goleanauth/pkg/jwks"
)

func TestGetClientIP(t *testing.T) {
	cases := []struct {
		name       string
		trustProxy bool
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name:       "direct, ignores forwarded header",
			trustProxy: false,
			headers:    map[string]string{"X-Forwarded-For": "5.6.7.8"},
			remoteAddr: "1.2.3.4:5678",
			want:       "1.2.3.4",
		},
		{
			name:       "proxied, first forwarded entry",
			trustProxy: true,
			headers:    map[string]string{"X-Forwarded-For": "5.6.7.8, 9.9.9.9"},
			remoteAddr: "10.0.0.1:5678",
			want:       "5.6.7.8",
		},
		{
			name:       "proxied, real ip fallback",
			trustProxy: true,
			headers:    map[string]string{"X-Real-IP": "8.8.8.8"},
			remoteAddr: "10.0.0.1:5678",
			want:       "8.8.8.8",
		},
		{
			name:       "direct, no headers",
			trustProxy: false,
			remoteAddr: "1.2.3.4:5678",
			want:       "1.2.3.4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := getClientIP(req, tc.trustProxy); got != tc.want {
				t.Errorf("getClientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func userClaims(userID, sessionID string) jwks.Claims {
	return jwks.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		SessionID: sessionID,
	}
}

func TestRequireAuth_MissingHeader(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	defer db.Close()

	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}

	m := NewAuthMiddleware(db, keys)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_ValidUserToken(t *testing.T) {
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	defer db.Close()

	signed, err := keys.Sign(userClaims("user-1", "session-1"))
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"revoked", "expired", "user_id", "client_id", "status", "client_active"}).
			AddRow(false, false, "user-1", nil, "active", nil))

	m := NewAuthMiddleware(db, keys)

	var called bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if uid, ok := requestctx.UserID(r.Context()); !ok || uid != "user-1" {
			t.Errorf("UserID from context = %q, %v; want user-1", uid, ok)
		}
		if sid, ok := requestctx.SessionID(r.Context()); !ok || sid != "session-1" {
			t.Errorf("SessionID from context = %q, %v; want session-1", sid, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()

	m.RequireAuth(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if !called {
		t.Error("next handler was not called")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRequireAuth_ValidClientToken(t *testing.T) {
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	defer db.Close()

	claims := userClaims("", "session-1")
	claims.ClientID = "client-1"
	claims.Scope = "read write"
	signed, err := keys.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"revoked", "expired", "user_id", "client_id", "status", "client_active"}).
			AddRow(false, false, nil, "client-1", nil, true))

	m := NewAuthMiddleware(db, keys)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()

	var called bool
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if cid, ok := requestctx.ClientID(r.Context()); !ok || cid != "client-1" {
			t.Errorf("ClientID from context = %q, %v; want client-1", cid, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

func TestRequireAuth_SuspendedUser(t *testing.T) {
	keys, err := jwks.Generate()
	if err != nil {
		t.Fatalf("jwks.Generate() error: %v", err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	defer db.Close()

	signed, err := keys.Sign(userClaims("user-1", "session-1"))
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"revoked", "expired", "user_id", "client_id", "status", "client_active"}).
			AddRow(false, false, "user-1", nil, "suspended", nil))

	m := NewAuthMiddleware(db, keys)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
