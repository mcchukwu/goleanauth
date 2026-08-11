//go:build integration

// Package integration exercises the auth and OAuth services against a real
// Postgres database. It requires TEST_DB_URL to point at a database whose
// schema is owned by these tests: migrations are applied automatically in
// TestMain, so the target database must be disposable.
//
// Run with:
//
//	make test-integration
package integration

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"goleanauth/migrations"
)

var db *sql.DB

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "TEST_DB_URL not set; skipping integration tests")
		os.Exit(0)
	}

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening test database: %v\n", err)
		os.Exit(1)
	}
	if err := conn.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "pinging test database: %v\n", err)
		os.Exit(1)
	}
	db = conn

	goose.SetBaseFS(migrations.FS)
	goose.SetDialect("postgres")
	if err := goose.Up(db, "."); err != nil {
		fmt.Fprintf(os.Stderr, "applying migrations: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	_ = db.Close()
	os.Exit(code)
}
