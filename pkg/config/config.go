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
	AppEnv string

	AppPort string

	DatabaseURL string

	JWTSecret string

	AccessTokenTTLMinutes int
	RefreshTokenTTLHours  int

	CORSAllowedOrigins []string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
}

func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found")
	}

	accessTokenTTLMinutes, err := strconv.Atoi(getEnv("ACCESS_TOKEN_TTL_MINUTES", "15"))
	if err != nil {
		log.Fatal(err)
	}

	refreshTokenTTLHours, err := strconv.Atoi(getEnv("REFRESH_TOKEN_TTL_HOURS", "24"))
	if err != nil {
		log.Fatal(err)
	}

	return &Config{
		AppEnv:                getEnv("APP_ENV", ""),
		AppPort:               getEnv("APP_PORT", "8080"),
		DatabaseURL:           getEnv("DATABASE_URL", ""),
		JWTSecret:             getEnv("JWT_SECRET", ""),
		AccessTokenTTLMinutes: accessTokenTTLMinutes,
		RefreshTokenTTLHours:  refreshTokenTTLHours,
		CORSAllowedOrigins:    strings.Split(getEnv("CORS_ALLOWED_ORIGINS", ""), ","),
		GoogleClientID:        getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:    getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:     getEnv("GOOGLE_REDIRECT_URL", ""),
	}
}

func (c *Config) Validate() error {
	if c.AppEnv != "production" && c.AppEnv != "development" {
		return errors.New("invalid app env")
	}

	if c.AppPort == "" {
		return errors.New("invalid app port")
	}

	if c.DatabaseURL == "" {
		return errors.New("database url is required")
	}

	if c.JWTSecret == "" {
		return errors.New("jwt secret is required")
	}

	if len(c.JWTSecret) < 32 {
		return errors.New("jwt secret must be at least 32 characters")
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

// helper function to get environment variable
func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
