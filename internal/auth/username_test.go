package auth

import (
	"regexp"
	"testing"
)

var usernamePattern = regexp.MustCompile(`^[a-z]+_[a-z0-9]{5}$`)

func TestGenerateUsername(t *testing.T) {
	for range 100 {
		username, err := generateUsername()
		if err != nil {
			t.Fatalf("generateUsername() unexpected error: %v", err)
		}
		if !usernamePattern.MatchString(username) {
			t.Errorf("generateUsername() = %q, does not match %s", username, usernamePattern)
		}
	}
}

func TestRandomSuffix(t *testing.T) {
	suffix, err := randomSuffix(5)
	if err != nil {
		t.Fatalf("randomSuffix() unexpected error: %v", err)
	}
	if len(suffix) != 5 {
		t.Errorf("randomSuffix(5) length = %d, want 5", len(suffix))
	}
}
