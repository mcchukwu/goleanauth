package health

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"goleanauth/internal/response"
)

type HealthHandler struct {
	DB *sql.DB
}

func NewHealthHandler(db *sql.DB) *HealthHandler {
	return &HealthHandler{
		DB: db,
	}
}

func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	response.Success(w, http.StatusOK, "Service is live", nil)
}

func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := h.DB.PingContext(ctx); err != nil {
		response.Error(w, http.StatusServiceUnavailable, "service_unavailable", "database unavailable")
		return
	}

	response.Success(w, http.StatusOK, "Service is ready", nil)
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	response.Success(w, http.StatusOK, "Service is healthy", map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}
