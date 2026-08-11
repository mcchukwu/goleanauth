package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/pkg/config"
	"goleanauth/pkg/db"
	"goleanauth/pkg/jwks"
)

type AuthService struct {
	DB              *sql.DB
	Keys            *jwks.KeySet
	Issuer          string
	AuditService    *audit.AuditService
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func NewAuthService(db *sql.DB, keys *jwks.KeySet, auditService *audit.AuditService, cfg *config.Config) *AuthService {
	return &AuthService{
		DB:              db,
		Keys:            keys,
		Issuer:          cfg.Issuer,
		AuditService:    auditService,
		AccessTokenTTL:  time.Duration(cfg.AccessTokenTTLMinutes) * time.Minute,
		RefreshTokenTTL: time.Duration(cfg.RefreshTokenTTLHours) * time.Hour,
	}
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) error {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		// Hash password
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			return apperror.ErrInternalServer
		}

		// Generate username
		username, err := createUniqueUsername(dbCtx, tx)
		if err != nil {
			return err
		}

		// Create user and get the new user ID
		var userID string

		err = tx.QueryRowContext(dbCtx, `
		INSERT INTO users (username, email, phone, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, username, nullableString(req.Email), nullableString(req.Phone), string(hashedPassword), nullableString(req.FirstName), nullableString(req.LastName)).Scan(&userID)
		if err != nil {
			var pqErr *pgconn.PgError
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				switch {
				case strings.Contains(pqErr.ConstraintName, "email"):
					return apperror.ErrEmailAlreadyExists
				case strings.Contains(pqErr.ConstraintName, "phone"):
					return apperror.ErrPhoneAlreadyExists
				}
			}
			return apperror.ErrDatabase
		}

		// Audit log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.registered",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{},
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// Login validates the user credentials and returns a JWT access token
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (string, string, error) {
	var accessToken string
	var refreshToken string

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		var userID string
		var passwordHash string
		var status string

		// detect identifier type and query the right column
		var err error

		if strings.Contains(req.Identifier, "@") {
			err = tx.QueryRowContext(dbCtx, `
                SELECT id, password_hash, status 
								FROM users 
								WHERE email = $1
            `, req.Identifier).Scan(&userID, &passwordHash, &status)
		} else {
			err = tx.QueryRowContext(dbCtx, `
                SELECT id, password_hash, status 
								FROM users 
								WHERE phone = $1
            `, req.Identifier).Scan(&userID, &passwordHash, &status)
		}
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return apperror.ErrUserNotFound
			}

			return apperror.ErrDatabase
		}

		// Check user status
		if status != "active" {
			return apperror.ErrUserSuspended
		}

		// Verify password
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
		if err != nil {
			return apperror.ErrInvalidPassword
		}

		// Create session
		_, accessToken, refreshToken, err = createSession(dbCtx, tx, userID, nil, "", s.Keys, s.Issuer, s.AccessTokenTTL, s.RefreshTokenTTL)
		if err != nil {
			return err
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.logged_in",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{},
		})
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// GoogleLogin exchanges the code for a Google user and logs them in
func (s *AuthService) GoogleLogin(ctx context.Context, code string) (string, string, error) {
	oauthUser, err := exchangeGoogleCode(ctx, code)
	if err != nil {
		return "", "", apperror.ErrInternalServer
	}

	return oauthLogin(ctx, s.DB, s.Keys, s.Issuer, s.AuditService, s.AccessTokenTTL, s.RefreshTokenTTL, oauthUser)
}

// AppleLogin exchanges the code for an Apple user and logs them in. The user
// payload (first/last name, email) is only present on the first authorization.
func (s *AuthService) AppleLogin(ctx context.Context, code, userParam string) (string, string, error) {
	exchanged, err := exchangeAppleCode(ctx, code)
	if err != nil {
		return "", "", apperror.ErrInternalServer
	}

	sub, email, err := parseAppleIDToken(exchanged.IDToken)
	if err != nil {
		return "", "", apperror.ErrInternalServer
	}

	payload := parseAppleUserParam(userParam)
	if payload.Email != "" {
		email = payload.Email
	}

	oauthUser := OAuthUser{
		ProviderID: sub,
		Provider:   "apple",
		Email:      email,
		FirstName:  payload.Name.FirstName,
		LastName:   payload.Name.LastName,
	}

	return oauthLogin(ctx, s.DB, s.Keys, s.Issuer, s.AuditService, s.AccessTokenTTL, s.RefreshTokenTTL, oauthUser)
}

// RefreshToken refreshes the session using refresh token rotation, looking the
// session up directly by the SHA-256 hash of the presented refresh token.
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	var newAccessToken string
	var newRefreshToken string

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		// Find the session by the hashed refresh token (unique indexed lookup)
		sessionHash := hashRefreshToken(refreshToken)

		var sessionID string
		var userID, clientID sql.NullString
		var sessionScope string

		err := tx.QueryRowContext(dbCtx, `
			SELECT s.id, s.user_id, s.client_id, s.scope
			FROM sessions s
			LEFT JOIN users u ON u.id = s.user_id
			LEFT JOIN clients c ON c.client_id = s.client_id
			WHERE s.refresh_token_hash = $1
			  AND s.revoked = false
			  AND s.expires_at > NOW()
			  AND ((s.client_id IS NULL AND u.status = 'active')
			       OR (s.client_id IS NOT NULL AND c.active = true))
		`, sessionHash).Scan(&sessionID, &userID, &clientID, &sessionScope)
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrInvalidToken
		}
		if err != nil {
			return apperror.ErrDatabase
		}

		// Revoke old session (rotation)
		_, err = tx.ExecContext(dbCtx, `
			UPDATE sessions
			SET revoked = true,
			    revoked_at = NOW()
			WHERE id = $1
		`, sessionID)
		if err != nil {
			return apperror.ErrDatabase
		}

		userIDString := userID.String
		var clientIDPtr *string
		if clientID.Valid {
			clientIDPtr = &clientID.String
		}

		// Create new session and issue fresh tokens, carrying over client binding
		_, newAccessToken, newRefreshToken, err = createSession(dbCtx, tx, userIDString, clientIDPtr, sessionScope, s.Keys, s.Issuer, s.AccessTokenTTL, s.RefreshTokenTTL)
		if err != nil {
			return err
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     nullableString(userIDString),
			Action:     "token.refreshed",
			EntityType: "user",
			EntityID:   nullableString(userIDString),
			Metadata:   map[string]any{},
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

// LookupSessionUser resolves a refresh token to an active user session. It is
// read-only: it is used by the interactive authorize flow to determine whether
// the browser holds a valid login without rotating the session.
func (s *AuthService) LookupSessionUser(ctx context.Context, refreshToken string) (string, error) {
	if refreshToken == "" {
		return "", apperror.ErrInvalidToken
	}

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var userID sql.NullString
	err := s.DB.QueryRowContext(dbCtx, `
		SELECT s.user_id
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.refresh_token_hash = $1
		  AND s.user_id IS NOT NULL
		  AND s.revoked = false
		  AND s.expires_at > NOW()
		  AND u.status = 'active'
	`, hashRefreshToken(refreshToken)).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) || !userID.Valid {
		return "", apperror.ErrInvalidToken
	}
	if err != nil {
		return "", apperror.ErrDatabase
	}

	return userID.String, nil
}

// Logout revokes sessions for a user's device
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		// Revoke session and capture the owner for the audit trail
		var userID string
		err := tx.QueryRowContext(dbCtx, `
			UPDATE sessions
			SET revoked = true,
			    revoked_at = NOW()
			WHERE id = $1
			RETURNING user_id
		`, sessionID).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperror.ErrInvalidToken
		}
		if err != nil {
			return apperror.ErrDatabase
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.logged_out",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{},
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// LogoutAllDevices revokes all sessions for a user
func (s *AuthService) LogoutAllDevices(ctx context.Context, userID string) error {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(dbCtx, `
		UPDATE sessions
		SET revoked = true,
		    revoked_at = NOW()
		WHERE user_id = $1
		AND revoked = false
		`,
			userID,
		)
		if err != nil {
			return apperror.ErrDatabase
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.logged_out_all_devices",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{},
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// hashPassword hashes the password using bcrypt
func hashPassword(pw string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(bytes), err
}

// hashRefreshToken hashes the refresh token using SHA-256.
//
// Refresh tokens are high-entropy random values, so a fast, deterministic hash
// is sufficient and enables direct indexed lookup (bcrypt is only needed for
// low-entropy secrets like passwords).
func hashRefreshToken(rt string) string {
	sum := sha256.Sum256([]byte(rt))
	return hex.EncodeToString(sum[:])
}

// createUniqueUsername generates a unique username for the user
func createUniqueUsername(ctx context.Context, tx *sql.Tx) (string, error) {
	for range 5 {
		username, err := generateUsername()
		if err != nil {
			return "", err
		}

		var exists bool
		err = tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username,
		).Scan(&exists)
		if err != nil {
			return "", apperror.ErrDatabase
		}
		if !exists {
			return username, nil
		}
	}
	return "", apperror.ErrInternalServer
}

// generateState generates a random state string
func generateState() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", apperror.ErrInternalServer
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// nullableString returns a pointer to the string if it's not empty
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// oauthLogin is the shared core — provider-agnostic
func oauthLogin(ctx context.Context, conn *sql.DB, keys *jwks.KeySet, issuer string, auditService *audit.AuditService, accessTTL, refreshTTL time.Duration, ou OAuthUser) (string, string, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var accessToken, refreshToken string

	err := db.WithTransaction(dbCtx, conn, func(tx *sql.Tx) error {
		var userID, status string
		err := tx.QueryRowContext(dbCtx, `
            SELECT u.id, u.status
            FROM users u
            JOIN user_oauth_providers p ON p.user_id = u.id
            WHERE p.provider = $1 AND p.provider_id = $2
        `, ou.Provider, ou.ProviderID).Scan(&userID, &status)
		if errors.Is(err, sql.ErrNoRows) {
			emailErr := tx.QueryRowContext(dbCtx, `
                SELECT id, status FROM users WHERE email = $1
            `, ou.Email).Scan(&userID, &status)
			if errors.Is(emailErr, sql.ErrNoRows) {
				username, err := createUniqueUsername(dbCtx, tx)
				if err != nil {
					return err
				}
				err = tx.QueryRowContext(dbCtx, `
                    INSERT INTO users (username, email, first_name, last_name, email_verified)
                    VALUES ($1, $2, $3, $4, true)
                    RETURNING id
                `,
					username,
					nullableString(ou.Email),
					nullableString(ou.FirstName),
					nullableString(ou.LastName),
				).Scan(&userID)
				if err != nil {
					return apperror.ErrDatabase
				}
				status = "active"
			} else if emailErr != nil {
				return apperror.ErrDatabase
			}

			// Create user oauth provider
			_, err = tx.ExecContext(dbCtx, `
                INSERT INTO user_oauth_providers (user_id, provider, provider_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (provider, provider_id) DO NOTHING
            `, userID, ou.Provider, ou.ProviderID)
			if err != nil {
				return apperror.ErrDatabase
			}
		} else if err != nil {
			return apperror.ErrDatabase
		}

		if status != "active" {
			return apperror.ErrUserSuspended
		}

		var sessionErr error
		_, accessToken, refreshToken, sessionErr = createSession(dbCtx, tx, userID, nil, "", keys, issuer, accessTTL, refreshTTL)
		if sessionErr != nil {
			return sessionErr
		}

		// Audit Log
		err = auditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.oauth_login",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{"provider": ou.Provider},
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// createSession is shared — Login and OAuth both call this. It persists a new
// session row (optionally bound to a client) and returns its ID along with
// fresh access and refresh tokens.
func createSession(ctx context.Context, tx *sql.Tx, userID string, clientID *string, scope string, keys *jwks.KeySet, issuer string, accessTTL, refreshTTL time.Duration) (sessionID, accessToken, refreshToken string, err error) {
	refreshTokenBytes := make([]byte, 32)

	if _, err = rand.Read(refreshTokenBytes); err != nil {
		return "", "", "", apperror.ErrInternalServer
	}

	refreshToken = hex.EncodeToString(refreshTokenBytes)
	hashedRefreshToken := hashRefreshToken(refreshToken)

	err = tx.QueryRowContext(ctx, `
        INSERT INTO sessions (user_id, client_id, scope, refresh_token_hash, expires_at, revoked, created_at)
        VALUES ($1, $2, $3, $4, $5, false, NOW())
        RETURNING id
    `,
		nullableString(userID),
		clientID,
		scope,
		hashedRefreshToken,
		time.Now().Add(refreshTTL),
	).Scan(&sessionID)
	if err != nil {
		return "", "", "", apperror.ErrDatabase
	}

	accessToken, err = issueAccessToken(keys, issuer, userID, sessionID, clientID, scope, accessTTL)
	if err != nil {
		return "", "", "", apperror.ErrInternalServer
	}

	return sessionID, accessToken, refreshToken, nil
}

// issueAccessToken builds and signs an access token. userID is empty for
// client-only (machine) tokens.
func issueAccessToken(keys *jwks.KeySet, issuer, userID, sessionID string, clientID *string, scope string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwks.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        sessionID,
		},
		SessionID: sessionID,
		Scope:     scope,
	}

	if clientID != nil {
		claims.ClientID = *clientID
	}

	signed, err := keys.Sign(claims)
	if err != nil {
		return "", apperror.ErrInternalServer
	}

	return signed, nil
}
