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
	JWTSecret             string   `env:"JWT_SECRET"`
	AccessTokenTTLMinutes int      `env:"ACCESS_TOKEN_TTL_MINUTES"`
	RefreshTokenTTLHours  int      `env:"REFRESH_TOKEN_TTL_HOURS"`
	TrustProxy            bool     `env:"TRUST_PROXY"`
	CORSAllowedOrigins    []string `env:"CORS_ALLOWED_ORIGINS"`
	GoogleClientID        string   `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret    string   `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL     string   `env:"GOOGLE_REDIRECT_URL"`
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

	return &Config{
		AppEnv:                getEnv("APP_ENV", "development"),
		AppPort:               getEnv("APP_PORT", "8080"),
		DBURL:                 getEnv("DB_URL", ""),
		JWTSecret:             getEnv("JWT_SECRET", ""),
		AccessTokenTTLMinutes: accessTokenTTLMinutes,
		RefreshTokenTTLHours:  refreshTokenTTLHours,
		TrustProxy:            trustProxy,
		CORSAllowedOrigins:    strings.Split(getEnv("CORS_ALLOWED_ORIGINS", ""), ","),
		GoogleClientID:        getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:    getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:     getEnv("GOOGLE_REDIRECT_URL", ""),
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

	if c.JWTSecret == "" {
		return errors.New("jwt secret is required")
	}

	if len(c.JWTSecret) < 32 {
		return errors.New("jwt secret must be at least 32 characters")
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

	if c.GoogleClientID == "" {
		return errors.New("google client id is required")
	}

	if c.GoogleClientSecret == "" {
		return errors.New("google client secret is required")
	}

	if c.GoogleRedirectURL == "" {
		return errors.New("google redirect url is required")
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
