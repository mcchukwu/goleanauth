package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"goleanauth/internal/apperror"
	"goleanauth/internal/audit"
	"goleanauth/pkg/config"
)

func newTestService(t *testing.T) (*AuthService, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := &config.Config{AccessTokenTTLMinutes: 15, RefreshTokenTTLHours: 24}
	return NewAuthService(db, []byte("test-secret-0123456789abcdef"), audit.NewAuditService(db), cfg), mock
}

const testPassword = "secret123"

func testPasswordHash(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error: %v", err)
	}
	return string(hash)
}

func TestLoginSuccessByEmail(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM users WHERE email").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash", "status"}).
			AddRow("user-1", testPasswordHash(t), "active"))
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	accessToken, refreshToken, err := s.Login(context.Background(), LoginRequest{
		Identifier: "foo@example.com",
		Password:   testPassword,
	})
	if err != nil {
		t.Fatalf("Login() unexpected error: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Fatal("Login() returned empty tokens")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestLoginSuspended(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM users WHERE email").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash", "status"}).
			AddRow("user-1", testPasswordHash(t), "suspended"))
	mock.ExpectRollback()

	_, _, err := s.Login(context.Background(), LoginRequest{
		Identifier: "foo@example.com",
		Password:   testPassword,
	})
	if !errors.Is(err, apperror.ErrUserSuspended) {
		t.Fatalf("Login() error = %v, want %v", err, apperror.ErrUserSuspended)
	}
}

func TestLoginInvalidPassword(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM users WHERE email").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash", "status"}).
			AddRow("user-1", testPasswordHash(t), "active"))
	mock.ExpectRollback()

	_, _, err := s.Login(context.Background(), LoginRequest{
		Identifier: "foo@example.com",
		Password:   "wrong-password",
	})
	if !errors.Is(err, apperror.ErrInvalidPassword) {
		t.Fatalf("Login() error = %v, want %v", err, apperror.ErrInvalidPassword)
	}
}

func TestLoginUserNotFound(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM users WHERE phone").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash", "status"}))
	mock.ExpectRollback()

	_, _, err := s.Login(context.Background(), LoginRequest{
		Identifier: "08012345678",
		Password:   testPassword,
	})
	if !errors.Is(err, apperror.ErrUserNotFound) {
		t.Fatalf("Login() error = %v, want %v", err, apperror.ErrUserNotFound)
	}
}

func TestRegisterSuccess(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("INSERT INTO users").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("user-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := s.Register(context.Background(), RegisterRequest{
		Email:     "foo@example.com",
		Password:  testPassword,
		FirstName: "Miracle",
		LastName:  "Chukwu",
	})
	if err != nil {
		t.Fatalf("Register() unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("INSERT INTO users").WillReturnError(&pgconn.PgError{
		Code:           "23505",
		ConstraintName: "users_email_key",
	})
	mock.ExpectRollback()

	err := s.Register(context.Background(), RegisterRequest{
		Email:     "dup@example.com",
		Password:  testPassword,
		FirstName: "Miracle",
		LastName:  "Chukwu",
	})
	if !errors.Is(err, apperror.ErrEmailAlreadyExists) {
		t.Fatalf("Register() error = %v, want %v", err, apperror.ErrEmailAlreadyExists)
	}
}

func TestRefreshTokenSuccess(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id"}).AddRow("session-1", "user-1"))
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("INSERT INTO sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-2"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	accessToken, refreshToken, err := s.RefreshToken(context.Background(), "some-refresh-token")
	if err != nil {
		t.Fatalf("RefreshToken() unexpected error: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Fatal("RefreshToken() returned empty tokens")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRefreshTokenInvalid(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("FROM sessions").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id"}))
	mock.ExpectRollback()

	_, _, err := s.RefreshToken(context.Background(), "unknown-token")
	if !errors.Is(err, apperror.ErrInvalidToken) {
		t.Fatalf("RefreshToken() error = %v, want %v", err, apperror.ErrInvalidToken)
	}
}

func TestLogoutSuccess(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE sessions").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-1"))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := s.Logout(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("Logout() unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestLogoutAllDevicesSuccess(t *testing.T) {
	s, mock := newTestService(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE sessions").WillReturnResult(sqlmock.NewResult(2, 2))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := s.LogoutAllDevices(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("LogoutAllDevices() unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
