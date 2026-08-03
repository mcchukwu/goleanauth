package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"goleanauth/internal/apperror"
	"goleanauth/internal/requestctx"
	"goleanauth/internal/response"
	"goleanauth/pkg/logger"
)

type RecoveryMiddleware struct{}

func NewRecoveryMiddleware() *RecoveryMiddleware {
	return &RecoveryMiddleware{}
}

// Recover recovers from panics and logs the error
func (m *RecoveryMiddleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				requestID, ok := requestctx.RequestID(r.Context())
				if !ok {
					response.HandleError(w, apperror.ErrInternalServer)
					return
				}

				logger.Error(fmt.Sprintf("panic recovered request_id=%s panic=%v stack=%s", requestID, err, debug.Stack()))
				response.HandleError(w, apperror.ErrInternalServer)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
