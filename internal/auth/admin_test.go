package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
)

func TestMain(m *testing.M) {
	validation.Init()
	os.Exit(m.Run())
}

func newTestAdminHandler(adminKey string) (*AdminHandler, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		panic(err)
	}
	cfg := &config.Config{AdminAPIKey: adminKey}
	return NewAdminHandler(NewClientService(db), cfg), mock
}

func adminRequest(method, path, body string, key string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Admin-Key", key)
	}
	return req
}

func TestAdminCreateClient(t *testing.T) {
	h, mock := newTestAdminHandler("super-secret")
	mock.ExpectExec("INSERT INTO clients").WillReturnResult(sqlmock.NewResult(1, 1))

	rr := httptest.NewRecorder()
	h.CreateClient(rr, adminRequest(http.MethodPost, "/v1/admin/clients",
		`{"name":"My App","scope":"read write","redirect_uris":["http://app.test/cb"]}`, "super-secret"))

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	data, _ := body["data"].(map[string]any)
	if data["client_id"] == "" || data["client_secret"] == "" {
		t.Error("response missing client credentials")
	}
}

func TestAdminCreateClientWrongKey(t *testing.T) {
	h, _ := newTestAdminHandler("super-secret")

	rr := httptest.NewRecorder()
	h.CreateClient(rr, adminRequest(http.MethodPost, "/v1/admin/clients", `{"name":"My App"}`, "wrong-key"))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAdminCreateClientUnsetKey(t *testing.T) {
	h, _ := newTestAdminHandler("")

	rr := httptest.NewRecorder()
	h.CreateClient(rr, adminRequest(http.MethodPost, "/v1/admin/clients", `{"name":"My App"}`, ""))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAdminCreateClientInvalidBody(t *testing.T) {
	h, _ := newTestAdminHandler("super-secret")

	rr := httptest.NewRecorder()
	h.CreateClient(rr, adminRequest(http.MethodPost, "/v1/admin/clients", `{"name":""}`, "super-secret"))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminCreateClientBadRedirectURI(t *testing.T) {
	h, _ := newTestAdminHandler("super-secret")

	rr := httptest.NewRecorder()
	h.CreateClient(rr, adminRequest(http.MethodPost, "/v1/admin/clients",
		`{"name":"My App","redirect_uris":["not-a-url"]}`, "super-secret"))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminListClients(t *testing.T) {
	h, mock := newTestAdminHandler("super-secret")
	mock.ExpectQuery("FROM clients").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "redirect_uris"}).
			AddRow("client-1", "My App", "read", true, `{"http://app.test/cb"}`))

	rr := httptest.NewRecorder()
	h.ListClients(rr, adminRequest(http.MethodGet, "/v1/admin/clients", "", "super-secret"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "client-1") {
		t.Error("list response missing client")
	}
}
