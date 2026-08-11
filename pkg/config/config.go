package config

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv                string   `env:"APP_ENV"`
	AppPort               string   `env:"APP_PORT"`
	DBURL                 string   `env:"DB_URL"`
	Issuer                string   `env:"ISSUER"`
	JWTPrivateKey         string   `env:"JWT_PRIVATE_KEY"`
	JWTPublicKeys         string   `env:"JWT_PUBLIC_KEYS"`
	AccessTokenTTLMinutes int      `env:"ACCESS_TOKEN_TTL_MINUTES"`
	RefreshTokenTTLHours  int      `env:"REFRESH_TOKEN_TTL_HOURS"`
	TrustProxy            bool     `env:"TRUST_PROXY"`
	ServeDocs             bool     `env:"SERVE_DOCS"`
	CORSAllowedOrigins    []string `env:"CORS_ALLOWED_ORIGINS"`
	GoogleClientID        string   `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret    string   `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL     string   `env:"GOOGLE_REDIRECT_URL"`
	AdminAPIKey           string   `env:"ADMIN_API_KEY"`
	AppleClientID         string   `env:"APPLE_CLIENT_ID"`
	AppleTeamID           string   `env:"APPLE_TEAM_ID"`
	AppleKeyID            string   `env:"APPLE_KEY_ID"`
	ApplePrivateKey       string   `env:"APPLE_PRIVATE_KEY"`
	AppleRedirectURL      string   `env:"APPLE_REDIRECT_URL"`
}

// Load() loads the config from the environment and returns a Config struct
func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found")
	}

	accessTokenTTLMinutes, err := strconv.Atoi(getEnv("ACCESS_TOKEN_TTL_MINUTES", "15"))
	if err != nil {
		log.Fatal(err)
	}

	refreshTokenTTLHours, err := strconv.Atoi(getEnv("REFRESH_TOKEN_TTL_HOURS", "720"))
	if err != nil {
		log.Fatal(err)
	}

	trustProxy, err := strconv.ParseBool(getEnv("TRUST_PROXY", "false"))
	if err != nil {
		log.Fatal(err)
	}

	appEnv := getEnv("APP_ENV", "development")

	// Documentation endpoints default on in development and off in
	// production; an explicit SERVE_DOCS value always wins.
	serveDocs := appEnv == "development"
	if v := getEnv("SERVE_DOCS", ""); v != "" {
		serveDocs, err = strconv.ParseBool(v)
		if err != nil {
			log.Fatal(err)
		}
	}

	return &Config{
		AppEnv:                appEnv,
		AppPort:               getEnv("APP_PORT", "8080"),
		DBURL:                 getEnv("DB_URL", ""),
		Issuer:                getEnv("ISSUER", "http://localhost:8080"),
		JWTPrivateKey:         getEnv("JWT_PRIVATE_KEY", ""),
		JWTPublicKeys:         getEnv("JWT_PUBLIC_KEYS", ""),
		AccessTokenTTLMinutes: accessTokenTTLMinutes,
		RefreshTokenTTLHours:  refreshTokenTTLHours,
		TrustProxy:            trustProxy,
		ServeDocs:             serveDocs,
		CORSAllowedOrigins:    strings.Split(getEnv("CORS_ALLOWED_ORIGINS", ""), ","),
		GoogleClientID:        getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:    getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:     getEnv("GOOGLE_REDIRECT_URL", ""),
		AdminAPIKey:           getEnv("ADMIN_API_KEY", ""),
		AppleClientID:         getEnv("APPLE_CLIENT_ID", ""),
		AppleTeamID:           getEnv("APPLE_TEAM_ID", ""),
		AppleKeyID:            getEnv("APPLE_KEY_ID", ""),
		ApplePrivateKey:       getEnv("APPLE_PRIVATE_KEY", ""),
		AppleRedirectURL:      getEnv("APPLE_REDIRECT_URL", ""),
	}
}

// Validate() validates the config
func (c *Config) Validate() error {
	if c.AppEnv != "production" && c.AppEnv != "development" {
		return errors.New("invalid app env")
	}

	if c.AppPort == "" {
		return errors.New("invalid app port")
	}

	if c.DBURL == "" {
		return errors.New("database url is required")
	}

	if c.Issuer == "" {
		return errors.New("issuer is required")
	}

	// A signing key must be explicitly configured in production; development
	// may fall back to an ephemeral generated key.
	if c.AppEnv == "production" && c.JWTPrivateKey == "" {
		return errors.New("jwt private key is required in production")
	}

	if c.AccessTokenTTLMinutes <= 0 {
		return errors.New("access token ttl must be positive")
	}

	if c.RefreshTokenTTLHours <= 0 {
		return errors.New("refresh token ttl must be positive")
	}

	if len(c.CORSAllowedOrigins) == 0 {
		return errors.New("cors allowed origins is required")
	}

	// Google sign-in is optional: when any credential is set, all three are
	// required so a partially-configured provider fails fast. With no Google
	// credentials the service runs email/password-only.
	googleCreds := []string{c.GoogleClientID, c.GoogleClientSecret, c.GoogleRedirectURL}
	set := 0
	for _, v := range googleCreds {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != len(googleCreds) {
		return errors.New("google client id, secret, and redirect url must all be set together")
	}

	return nil
}

// -
// Helpers
// -
// getEnv(key, fallback) helper function to get environment variable
func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
