package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"

	"goleanauth/internal/apperror"
)

func TestRegisterClientSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectExec("INSERT INTO clients").WillReturnResult(sqlmock.NewResult(1, 1))

	clientID, secret, err := NewClientService(db).RegisterClient(context.Background(), "My App", "read write")
	if err != nil {
		t.Fatalf("RegisterClient() unexpected error: %v", err)
	}
	if clientID == "" || secret == "" {
		t.Error("RegisterClient() returned empty credentials")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRegisterClientDuplicate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectExec("INSERT INTO clients").WillReturnError(&pgconn.PgError{
		Code: "23505",
	})

	_, _, err = NewClientService(db).RegisterClient(context.Background(), "My App", "")
	if !errors.Is(err, apperror.ErrClientAlreadyExists) {
		t.Fatalf("RegisterClient() error = %v, want %v", err, apperror.ErrClientAlreadyExists)
	}
}

func TestAuthenticateClientSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const secret = "my-secret-value"
	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}).
		AddRow("client-1", "My App", "read write", true, hashClientSecret(secret), `{"http://app.test/cb"}`)
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)

	svc := NewClientService(db)
	c, err := svc.Authenticate(context.Background(), "client-1", secret)
	if err != nil {
		t.Fatalf("Authenticate() unexpected error: %v", err)
	}
	if c.ClientID != "client-1" || c.Scope != "read write" || !c.Active {
		t.Errorf("unexpected client: %+v", c)
	}
}

func TestAuthenticateClientInactive(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const secret = "my-secret-value"
	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}).
		AddRow("client-1", "My App", "", false, hashClientSecret(secret), `{}`)
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)

	_, err = NewClientService(db).Authenticate(context.Background(), "client-1", secret)
	if !errors.Is(err, apperror.ErrClientInactive) {
		t.Fatalf("Authenticate() error = %v, want %v", err, apperror.ErrClientInactive)
	}
}

func TestAuthenticateClientWrongSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rows := sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}).
		AddRow("client-1", "My App", "", true, hashClientSecret("real-secret"), `{}`)
	mock.ExpectQuery("FROM clients").WillReturnRows(rows)

	_, err = NewClientService(db).Authenticate(context.Background(), "client-1", "wrong-secret")
	if !errors.Is(err, apperror.ErrInvalidClientCredentials) {
		t.Fatalf("Authenticate() error = %v, want %v", err, apperror.ErrInvalidClientCredentials)
	}
}

func TestStringArrayRoundTrip(t *testing.T) {
	in := []string{"http://app.test/cb", "http://app.test/alt,cb", `http://with"quote.test/`}
	lit := arrayLiteral(in)

	var out StringArray
	if err := out.Scan(lit); err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("lengths differ: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("element %d = %q, want %q", i, out[i], in[i])
		}
	}
}

func TestStringArrayEmpty(t *testing.T) {
	var out StringArray
	if err := out.Scan("{}"); err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("Scan({}) = %v, want nil", out)
	}
}

func TestAuthenticateClientUnknown(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectQuery("FROM clients").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "name", "scope", "active", "client_secret_hash", "redirect_uris"}))

	_, err = NewClientService(db).Authenticate(context.Background(), "unknown", "secret")
	if !errors.Is(err, apperror.ErrInvalidClientCredentials) {
		t.Fatalf("Authenticate() error = %v, want %v", err, apperror.ErrInvalidClientCredentials)
	}
}
