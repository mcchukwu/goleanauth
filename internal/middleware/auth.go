package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"goleanauth/internal/apperror"
	"goleanauth/internal/requestctx"
	"goleanauth/internal/response"
)

type AccessTokenClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`

	jwt.RegisteredClaims
}

type AuthMiddleware struct {
	DB        *sql.DB
	JWTSecret []byte
}

func NewAuthMiddleware(db *sql.DB, secret []byte) *AuthMiddleware {
	return &AuthMiddleware{
		DB:        db,
		JWTSecret: secret,
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

		tokenString := parts[1]

		claims := &AccessTokenClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			// enforce HMAC signing only
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, apperror.ErrInvalidToken
			}

			return m.JWTSecret, nil
		})

		if err != nil || !token.Valid {
			response.HandleError(w, apperror.ErrUnauthorized)
			return
		}

		if claims.UserID == "" || claims.SessionID == "" {
			response.HandleError(w, apperror.ErrUnauthorized)
			return
		}

		// validate active session
		var exists bool

		err = m.DB.QueryRowContext(r.Context(),
			`
				SELECT EXISTS (
				SELECT 1
				FROM sessions
				WHERE id = $1
				  AND user_id = $2
				  AND revoked = false
				  AND expires_at > NOW()
			)`,
			claims.SessionID, claims.UserID).Scan(&exists)
		if err != nil {
			response.HandleError(w, err)
			return
		}

		if !exists {
			response.HandleError(w, apperror.ErrSessionExpired)
			return
		}

		// attach auth context
		ctx := requestctx.WithUserID(r.Context(), claims.UserID)
		ctx = requestctx.WithSessionID(ctx, claims.SessionID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
