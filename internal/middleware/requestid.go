package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"goleanauth/internal/requestctx"
)

type RequestIDMiddleware struct{}

func NewRequestIDMiddleware() *RequestIDMiddleware {
	return &RequestIDMiddleware{}
}

// Assign assigns a request id to the request context
func (m *RequestIDMiddleware) Assign(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()

		ctx := requestctx.WithRequestID(r.Context(), requestID)

		w.Header().Set("X-Request-Id", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
