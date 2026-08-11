package docs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func doRequest(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	switch path {
	case "/docs":
		h.Index(rec, req)
	case "/docs/openapi.yaml":
		h.Spec(rec, req)
	case "/docs/redoc.standalone.js":
		h.ReDocJS(rec, req)
	default:
		t.Fatalf("unhandled path %q", path)
	}
	return rec
}

func TestEnabledServesAllRoutes(t *testing.T) {
	h := NewHandler(true)

	spec := doRequest(t, h, "/docs/openapi.yaml")
	if spec.Code != http.StatusOK {
		t.Fatalf("spec status = %d, want 200", spec.Code)
	}
	if ct := spec.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Fatalf("spec content-type = %q, want application/yaml", ct)
	}
	if !strings.Contains(spec.Body.String(), "openapi: 3.1.0") {
		t.Error("spec body does not look like OpenAPI 3.1")
	}

	index := doRequest(t, h, "/docs")
	if index.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", index.Code)
	}
	body := index.Body.String()
	for _, want := range []string{`spec-url="openapi.yaml"`, `src="redoc.standalone.js"`, "<redoc", "GoleanAuth API Reference"} {
		if !strings.Contains(body, want) {
			t.Errorf("index body missing %q", want)
		}
	}

	js := doRequest(t, h, "/docs/redoc.standalone.js")
	if js.Code != http.StatusOK {
		t.Fatalf("js status = %d, want 200", js.Code)
	}
	if ct := js.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Fatalf("js content-type = %q, want application/javascript", ct)
	}
	if !strings.Contains(js.Body.String(), "Redoc") {
		t.Error("js body does not look like the ReDoc bundle")
	}
}

func TestDisabledReturnsNotFound(t *testing.T) {
	h := NewHandler(false)
	for _, path := range []string{"/docs", "/docs/openapi.yaml", "/docs/redoc.standalone.js"} {
		rec := doRequest(t, h, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}
}
