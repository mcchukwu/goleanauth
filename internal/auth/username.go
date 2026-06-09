package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var prefixes = []string{
	"cool", "fast", "bold", "calm", "wise", "bright", "swift", "keen",
	"brave", "sharp", "lucky", "happy", "fuzzy", "snappy", "witty", "quirky",
	"zesty", "funky", "peppy", "dandy", "merry", "jolly", "plucky", "savvy",
}

func generateUsername() (string, error) {
	prefix, err := randomChoice(prefixes)
	if err != nil {
		return "", fmt.Errorf("generating username prefix: %w", err)
	}

	suffix, err := randomSuffix(5)
	if err != nil {
		return "", fmt.Errorf("generating username suffix: %w", err)
	}

	return prefix + "_" + suffix, nil
}

func randomChoice(options []string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(options))))
	if err != nil {
		return "", err
	}

	return options[n.Int64()], nil
}

func randomSuffix(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

	result := make([]byte, length)

	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}

		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}
