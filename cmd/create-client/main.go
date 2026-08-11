// Command create-client registers a new OAuth client and prints its one-time
// credentials. It connects to the database directly, mirroring cmd/migrate.
//
// Usage:
//
//	go run ./cmd/create-client -name "My App" -scope "read write" -redirect-uri https://app.example.com/cb
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"goleanauth/internal/auth"
	"goleanauth/pkg/config"
	"goleanauth/pkg/db"
)

func main() {
	name := flag.String("name", "", "client display name (required)")
	scope := flag.String("scope", "", "space-separated allowed scopes")
	var redirectURIs multiFlag
	flag.Var(&redirectURIs, "redirect-uri", "registered redirect URI (repeatable)")
	flag.Parse()

	if *name == "" {
		fmt.Fprintln(os.Stderr, "-name is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := config.Load()
	if cfg.DBURL == "" {
		fmt.Fprintln(os.Stderr, "DB_URL is required")
		os.Exit(1)
	}

	if err := db.Connect(cfg.DBURL); err != nil {
		fmt.Fprintf(os.Stderr, "connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer db.DB.Close()

	clientID, clientSecret, err := auth.NewClientService(db.DB).RegisterClient(context.Background(), *name, *scope, redirectURIs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "registering client: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("client_id:     %s\n", clientID)
	fmt.Printf("client_secret: %s\n", clientSecret)
	fmt.Println("Store the secret now; it will not be shown again.")
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}
