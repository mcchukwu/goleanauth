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

		// Create user and get the new user ID
		var userID string

		err = tx.QueryRowContext(dbCtx, `
		INSERT INTO users (email, phone, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, req.Email, req.Phone, hashedPassword, req.FirstName, req.LastName).Scan(&userID)
		if err != nil {
			if strings.Contains(err.Error(), "users_email_key") {
				return apperror.ErrEmailAlreadyExists
			}
			if strings.Contains(err.Error(), "users_phone_key") {
				return apperror.ErrPhoneAlreadyExists
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

		// Find user
		err := tx.QueryRowContext(dbCtx, `
		SELECT id, password_hash
		FROM users
		WHERE email = $1 OR phone = $1
		`, req.Identifier).Scan(&userID, &passwordHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return apperror.ErrUserNotFound
			}
			return apperror.ErrDatabase
		}

		// Verify password
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
		if err != nil {
			return apperror.ErrInvalidPassword
		}

		// Generate refresh token
		refreshTokenBytes := make([]byte, 32)
		_, err = rand.Read(refreshTokenBytes)
		if err != nil {
			return apperror.ErrInternalServer
		}

		refreshToken = hex.EncodeToString(refreshTokenBytes)

		hashedRefreshToken, err := hashRefreshToken(refreshToken)
		if err != nil {
			return apperror.ErrInternalServer
		}

		// Create session and Store session
		var sessionID string

		err = tx.QueryRowContext(dbCtx, `
		INSERT INTO sessions (user_id, refresh_token_hash, expires_at, revoked, created_at)
		VALUES ($1, $2, $3, false, NOW())
		RETURNING id
	`,
			userID,
			hashedRefreshToken,
			time.Now().Add(30*24*time.Hour),
		).Scan(&sessionID)
		if err != nil {
			return apperror.ErrDatabase
		}

		// Create JWT access token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":    userID,
			"session_id": sessionID,
			"exp":        time.Now().Add(15 * time.Minute).Unix(),
		})

		// Sign JWT
		accessToken, err = token.SignedString(s.JWTSecret)
		if err != nil {
			return apperror.ErrInternalServer
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
