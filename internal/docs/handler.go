// Package docs serves the OpenAPI specification and a self-hosted ReDoc
// reference UI. The spec lives beside this file so it is compiled into the
// binary and always matches the build.
package docs

import (
	"embed"
	"net/http"
)

//go:embed openapi.yaml redoc.standalone.js redoc.standalone.js.LICENSE.txt
var files embed.FS

// Handler serves the API documentation routes. When constructed with
// serve=false every route returns 404, mirroring the admin-key gating used
// elsewhere.
type Handler struct {
	serve bool
}

// NewHandler returns a Handler. Set serve=false to disable documentation
// endpoints (recommended outside development unless explicitly enabled).
func NewHandler(serve bool) *Handler {
	return &Handler{serve: serve}
}

// redocIndex is the ReDoc shell. spec-url is relative so the page resolves
// /docs/openapi.yaml regardless of the path the app is mounted under.
const redocIndex = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GoleanAuth API Reference</title>
  <style>
    html, body { margin: 0; padding: 0; }
  </style>
</head>
<body>
  <redoc spec-url="openapi.yaml"></redoc>
  <script src="redoc.standalone.js"></script>
</body>
</html>`

// Index renders the ReDoc API reference.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	if !h.serve {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(redocIndex))
}

// Spec serves the raw OpenAPI specification for import into clients such as
// Postman, Stoplight, or Hoppscotch.
func (h *Handler) Spec(w http.ResponseWriter, r *http.Request) {
	if !h.serve {
		http.NotFound(w, r)
		return
	}
	serveEmbedded(w, "openapi.yaml", "application/yaml")
}

// ReDocJS serves the vendored ReDoc standalone bundle.
func (h *Handler) ReDocJS(w http.ResponseWriter, r *http.Request) {
	if !h.serve {
		http.NotFound(w, r)
		return
	}
	serveEmbedded(w, "redoc.standalone.js", "application/javascript")
}

func serveEmbedded(w http.ResponseWriter, name, contentType string) {
	data, err := files.ReadFile(name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}
