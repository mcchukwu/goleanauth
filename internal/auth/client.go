package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"goleanauth/internal/apperror"
	"goleanauth/pkg/db"
)

// Client is a registered application that can obtain tokens on its own behalf
// (client credentials) or request tokens on behalf of users.
type Client struct {
	ClientID string
	Name     string
	Scope    string
	Active   bool
}

// ClientService manages registered API clients.
type ClientService struct {
	DB *sql.DB
}

func NewClientService(db *sql.DB) *ClientService {
	return &ClientService{DB: db}
}

// RegisterClient creates a new client. The plain-text client secret is
// returned only once and is never stored; only its hash is persisted.
func (s *ClientService) RegisterClient(ctx context.Context, name, scope string) (clientID, clientSecret string, err error) {
	clientIDBytes := make([]byte, 16)
	if _, err = rand.Read(clientIDBytes); err != nil {
		return "", "", apperror.ErrInternalServer
	}
	clientID = base64.RawURLEncoding.EncodeToString(clientIDBytes)

	secretBytes := make([]byte, 32)
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", apperror.ErrInternalServer
	}
	clientSecret = base64.RawURLEncoding.EncodeToString(secretBytes)

	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	_, err = s.DB.ExecContext(dbCtx, `
		INSERT INTO clients (client_id, client_secret_hash, name, scope)
		VALUES ($1, $2, $3, $4)
	`, clientID, hashClientSecret(clientSecret), name, scope)
	if err != nil {
		var pqErr *pgconn.PgError
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return "", "", apperror.ErrClientAlreadyExists
		}
		return "", "", apperror.ErrDatabase
	}

	return clientID, clientSecret, nil
}

// Authenticate verifies a client id and secret and returns the client. It
// rejects inactive clients and unknown or mismatched credentials.
func (s *ClientService) Authenticate(ctx context.Context, clientID, clientSecret string) (Client, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var secretHash string
	var c Client

	err := s.DB.QueryRowContext(dbCtx, `
		SELECT client_id, name, scope, active, client_secret_hash
		FROM clients
		WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.Name, &c.Scope, &c.Active, &secretHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, apperror.ErrInvalidClientCredentials
	}
	if err != nil {
		return Client{}, apperror.ErrDatabase
	}

	if !c.Active {
		return Client{}, apperror.ErrClientInactive
	}

	if subtle.ConstantTimeCompare([]byte(secretHash), []byte(hashClientSecret(clientSecret))) != 1 {
		return Client{}, apperror.ErrInvalidClientCredentials
	}

	return c, nil
}

// Get returns a client by its public identifier without validating a secret.
func (s *ClientService) Get(ctx context.Context, clientID string) (Client, error) {
	dbCtx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var c Client
	err := s.DB.QueryRowContext(dbCtx, `
		SELECT client_id, name, scope, active
		FROM clients
		WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.Name, &c.Scope, &c.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, apperror.ErrClientNotFound
	}
	if err != nil {
		return Client{}, apperror.ErrDatabase
	}

	return c, nil
}

// hashClientSecret hashes a client secret with SHA-256 for storage and
// comparison. Client secrets are high-entropy, so a fast hash is sufficient.
func hashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
