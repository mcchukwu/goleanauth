package normalize

import "strings"

// Identifier normalizes a phone number or email
func Identifier(identifier, defaultRegion string) string {
	identifier = strings.TrimSpace(identifier)
	if strings.Contains(identifier, "@") {
		return Email(identifier)
	}
	normalized, err := Phone(identifier, defaultRegion)
	if err != nil {
		return identifier // return as-is, validator will catch it
	}
	return normalized
}
