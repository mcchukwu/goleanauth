// Command migrate applies the embedded SQL migrations to the database
// configured via DB_URL.
//
// Usage:
//
//	go run ./cmd/migrate                 # apply all pending migrations
//	go run ./cmd/migrate up              # same as above
//	go run ./cmd/migrate down 1          # roll back the last N migrations
//	go run ./cmd/migrate status          # show applied/pending migrations
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"goleanauth/migrations"
	"goleanauth/pkg/config"
)

func main() {
	cfg := config.Load()
	if cfg.DBURL == "" {
		fmt.Fprintln(os.Stderr, "DB_URL is required")
		os.Exit(1)
	}

	db, err := sql.Open("pgx", cfg.DBURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	goose.SetDialect("postgres")

	args := os.Args[1:]
	command := "up"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "up":
		err = goose.Up(db, ".")
	case "down":
		// Roll back a single migration step (goose.Down applies one).
		err = goose.Down(db, ".")
	case "status":
		err = goose.Status(db, ".")
	case "version":
		err = goose.Version(db, ".")
	default:
		err = fmt.Errorf("unknown command %q (want up, down, status, version)", command)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate %s: %v\n", command, err)
		os.Exit(1)
	}
}
