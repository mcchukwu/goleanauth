// Package migrations embeds the SQL migration files so they can be applied
// with the bundled migration runner (cmd/migrate) or an external tool.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
