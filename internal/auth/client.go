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
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"goleanauth/internal/apperror"
	"goleanauth/pkg/db"
)

// Client is a registered application that can obtain tokens on its own behalf
// (client credentials) or request tokens on behalf of users.
type Client struct {
	ClientID     string
	Name         string
	Scope        string
	Active       bool
	RedirectURIs []string
}

// StringArray is a database/sql Scanner for PostgreSQL text[] columns (used
// under the pgx stdlib driver, which delivers arrays in text literal form).
type StringArray []string

func (a *StringArray) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*a = nil
		return nil
	case []byte:
		return a.scanLiteral(string(v))
	case string:
		return a.scanLiteral(v)
	default:
		return fmt.Errorf("unsupported type %T for text[] scan", src)
	}
}

// scanLiteral parses a PostgreSQL array literal like {"a","b,c"}.
func (a *StringArray) scanLiteral(s string) error {
	s = strings.TrimSpace(s)
	if s == "{}" {
		*a = nil
		return nil
	}
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return fmt.Errorf("invalid text[] literal %q", s)
	}
	s = s[1 : len(s)-1]

	var out []string
	for _, part := range splitArrayElements(s) {
		if part == "NULL" || part == "null" {
			continue
		}
		out = append(out, unescapeArrayElement(part))
	}
	*a = out
	return nil
}

// splitArrayElements splits on commas that are not inside double quotes.
func splitArrayElements(s string) []string {
	var parts []string
	start, inQuotes := 0, false
	for i, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// unescapeArrayElement removes the surrounding quotes and undoes backslash
// escaping of quotes and backslashes inside array literal elements.
func unescapeArrayElement(elem string) string {
	if len(elem) >= 2 && elem[0] == '"' && elem[len(elem)-1] == '"' {
		elem = elem[1 : len(elem)-1]
	}
	elem = strings.ReplaceAll(elem, `\\`, `\`)
	elem = strings.ReplaceAll(elem, `\"`, `"`)
	return elem
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
func (s *ClientService) RegisterClient(ctx context.Context, name, scope string, redirectURIs ...string) (clientID, clientSecret string, err error) {
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
		INSERT INTO clients (client_id, client_secret_hash, name, scope, redirect_uris)
		VALUES ($1, $2, $3, $4, $5)
	`, clientID, hashClientSecret(clientSecret), name, scope, arrayLiteral(redirectURIs))
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
	var redirectURIs StringArray

	err := s.DB.QueryRowContext(dbCtx, `
		SELECT client_id, name, scope, active, client_secret_hash, redirect_uris
		FROM clients
		WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.Name, &c.Scope, &c.Active, &secretHash, &redirectURIs)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, apperror.ErrInvalidClientCredentials
	}
	if err != nil {
		return Client{}, apperror.ErrDatabase
	}

	c.RedirectURIs = redirectURIs

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
	var redirectURIs StringArray
	err := s.DB.QueryRowContext(dbCtx, `
		SELECT client_id, name, scope, active, redirect_uris
		FROM clients
		WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.Name, &c.Scope, &c.Active, &redirectURIs)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, apperror.ErrClientNotFound
	}
	if err != nil {
		return Client{}, apperror.ErrDatabase
	}

	c.RedirectURIs = redirectURIs

	return c, nil
}

// hashClientSecret hashes a client secret with SHA-256 for storage and
// comparison. Client secrets are high-entropy, so a fast hash is sufficient.
func hashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// arrayLiteral serializes strings to a PostgreSQL array literal. The literal is
// bound as a text parameter and cast to text[] by the server; this keeps the
// value driver-portable (works under both pgx and sqlmock).
func arrayLiteral(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = `"` + escapeArrayLiteral(item) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeArrayLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
