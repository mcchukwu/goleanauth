package normalize

import "strings"

// Email normalizes an email address
func Email(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
