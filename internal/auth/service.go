package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/pkg/db"
)

type AuthService struct {
	DB           *sql.DB
	JWTSecret    []byte
	AuditService *audit.AuditService
}

func NewAuthService(db *sql.DB, secret []byte) *AuthService {
	return &AuthService{
		DB:        db,
		JWTSecret: secret,
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
		INSERT INTO users (username, email, phone, password_hash)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, username, nullableString(req.Email), nullableString(req.Phone), string(hashedPassword)).Scan(&userID)
		if err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				switch {
				case strings.Contains(pqErr.Constraint, "email"):
					return apperror.ErrEmailAlreadyExists
				case strings.Contains(pqErr.Constraint, "phone"):
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
		accessToken, refreshToken, err = createSession(dbCtx, tx, userID, s.JWTSecret)
		if err != nil {
			return err
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{UserID: &userID,
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

	return oauthLogin(ctx, s.DB, s.JWTSecret, s.AuditService, oauthUser)
}

// RefreshToken refreshes the session
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	var newAccessToken string
	var newRefreshToken string

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		// Find session
		rows, err := tx.QueryContext(dbCtx, `
			SELECT id, refresh_token_hash, user_id
			FROM sessions
			WHERE revoked = false
	`)
		if err != nil {
			return apperror.ErrDatabase
		}

		// Loop through sessions and find refresh token
		defer rows.Close()

		var sessionID string
		var hashedRefreshToken string
		var userID string
		var found bool

		for rows.Next() {
			err = rows.Scan(&sessionID, &hashedRefreshToken, &userID)
			if err != nil {
				return apperror.ErrInternalServer
			}

			err = bcrypt.CompareHashAndPassword([]byte(hashedRefreshToken), []byte(refreshToken))
			if err == nil {
				found = true
				break
			}
		}

		if !found {
			return apperror.ErrInvalidToken
		}

		// Revoke old session
		_, err = tx.ExecContext(dbCtx, `
		UPDATE sessions
		SET revoked = true,
	    revoked_at = NOW()
		WHERE id = $1
	`,
			sessionID)
		if err != nil {
			return apperror.ErrDatabase
		}

		// Create new refresh token
		refreshBytes := make([]byte, 32)

		_, err = rand.Read(refreshBytes)
		if err != nil {
			return apperror.ErrInternalServer
		}

		newRefreshToken = hex.EncodeToString(refreshBytes)

		// Hash new refresh token
		newRefreshTokenHash, err := hashRefreshToken(newRefreshToken)
		if err != nil {
			return apperror.ErrInternalServer
		}

		// Create new session
		var newSessionID string
		err = tx.QueryRowContext(dbCtx, `
		INSERT INTO sessions (user_id, refresh_token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
`,
			userID,
			newRefreshTokenHash,
			time.Now().Add(30*24*time.Hour),
		).Scan(&newSessionID)
		if err != nil {
			return apperror.ErrDatabase
		}

		// Issue new JWT access token
		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":    userID,
			"session_id": newSessionID,
			"exp":        time.Now().Add(15 * time.Minute).Unix(),
		})

		// Sign access token
		newAccessToken, err = newToken.SignedString(s.JWTSecret)
		if err != nil {
			return apperror.ErrInternalServer
		}

		// Audit Log
		err = s.AuditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "token.refreshed",
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

	return newAccessToken, newRefreshToken, nil
}

// Logout revokes sessions for a user's device
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	err := db.WithTransaction(dbCtx, s.DB, func(tx *sql.Tx) error {
		// Revoke session
		var userID string
		_, err := tx.ExecContext(dbCtx, `
		UPDATE sessions
		SET revoked = true,
	    revoked_at = NOW()
		WHERE id = $1
		RETURNING user_id
	`,
			sessionID)
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

// hashRefreshToken hashes the refresh token using bcrypt
func hashRefreshToken(rt string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(rt), 12)
	return string(bytes), err
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

// nullableString returns a pointer to the string if it's not empty
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// oauthLogin is the shared core — provider-agnostic
func oauthLogin(ctx context.Context, conn *sql.DB, jwtSecret []byte, auditService *audit.AuditService, ou OAuthUser) (string, string, error) {
	var accessToken, refreshToken string

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

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
		accessToken, refreshToken, sessionErr = createSession(dbCtx, tx, userID, jwtSecret)
		if sessionErr != nil {
			return sessionErr
		}

		return auditService.Log(dbCtx, tx, audit.LogEntry{
			UserID:     &userID,
			Action:     "user.oauth_login",
			EntityType: "user",
			EntityID:   &userID,
			Metadata:   map[string]any{"provider": ou.Provider},
		})
	})
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// createSession is shared — Login and OAuth both call this
func createSession(ctx context.Context, tx *sql.Tx, userID string, jwtSecret []byte) (accessToken, refreshToken string, err error) {
	refreshTokenBytes := make([]byte, 32)

	if _, err = rand.Read(refreshTokenBytes); err != nil {
		return "", "", apperror.ErrInternalServer
	}

	refreshToken = hex.EncodeToString(refreshTokenBytes)

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", apperror.ErrInternalServer
	}

	var sessionID string
	err = tx.QueryRowContext(ctx, `
        INSERT INTO sessions (user_id, refresh_token_hash, expires_at, revoked, created_at)
        VALUES ($1, $2, $3, false, NOW())
        RETURNING id
    `,
		userID,
		string(hashedRefreshToken),
		time.Now().Add(30*24*time.Hour),
	).Scan(&sessionID)
	if err != nil {
		return "", "", apperror.ErrDatabase
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    userID,
		"session_id": sessionID,
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
	})
	accessToken, err = token.SignedString(jwtSecret)
	if err != nil {
		return "", "", apperror.ErrInternalServer
	}

	return accessToken, refreshToken, nil
}
