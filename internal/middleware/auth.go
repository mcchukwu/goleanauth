package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"goleanauth/internal/apperror"
	"goleanauth/internal/requestctx"
	"goleanauth/internal/response"
	"goleanauth/pkg/jwks"
)

type AuthMiddleware struct {
	DB   *sql.DB
	Keys *jwks.KeySet
}

func NewAuthMiddleware(db *sql.DB, keys *jwks.KeySet) *AuthMiddleware {
	return &AuthMiddleware{
		DB:   db,
		Keys: keys,
	}
}

func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			response.HandleError(w, apperror.ErrUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")

		if len(parts) != 2 || parts[0] != "Bearer" {
			response.HandleError(w, apperror.ErrInvalidToken)
			return
		}

		claims, err := m.Keys.Parse(parts[1])
		if err != nil {
			response.HandleError(w, apperror.ErrUnauthorized)
			return
		}

		if claims.SessionID == "" || (claims.Subject == "" && claims.ClientID == "") {
			response.HandleError(w, apperror.ErrUnauthorized)
			return
		}

		// Validate the session is still active and its principal is allowed.
		var revoked, expired bool
		var userID, clientID sql.NullString
		var userStatus sql.NullString
		var clientActive sql.NullBool

		err = m.DB.QueryRowContext(r.Context(), `
			SELECT s.revoked, s.expires_at < NOW(), s.user_id, s.client_id, u.status, c.active
			FROM sessions s
			LEFT JOIN users u ON u.id = s.user_id
			LEFT JOIN clients c ON c.client_id = s.client_id
			WHERE s.id = $1
		`, claims.SessionID).Scan(&revoked, &expired, &userID, &clientID, &userStatus, &clientActive)
		if err != nil {
			if err == sql.ErrNoRows {
				response.HandleError(w, apperror.ErrSessionExpired)
				return
			}
			response.HandleError(w, apperror.ErrDatabase)
			return
		}

		if revoked || expired {
			response.HandleError(w, apperror.ErrSessionExpired)
			return
		}

		if clientID.Valid {
			// Client (machine) token: must match the token's client and the client must be active.
			if claims.ClientID != clientID.String || !clientActive.Valid || !clientActive.Bool {
				response.HandleError(w, apperror.ErrSessionExpired)
				return
			}
		} else {
			// User token: subject must own the session and the user must be active.
			if !userID.Valid || claims.Subject != userID.String || userStatus.String != "active" {
				response.HandleError(w, apperror.ErrSessionExpired)
				return
			}
		}

		// attach auth context
		ctx := requestctx.WithUserID(r.Context(), claims.Subject)
		ctx = requestctx.WithSessionID(ctx, claims.SessionID)
		ctx = requestctx.WithClientID(ctx, claims.ClientID)
		ctx = requestctx.WithScope(ctx, claims.Scope)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
