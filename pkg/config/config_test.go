package config

import "testing"

func validConfig() *Config {
	return &Config{
		AppEnv:                "development",
		AppPort:               "8080",
		DBURL:                 "postgres://user:pass@localhost:5432/db",
		Issuer:                "http://localhost:8080",
		AccessTokenTTLMinutes: 15,
		RefreshTokenTTLHours:  24,
		CORSAllowedOrigins:    []string{"http://localhost:3000"},
		GoogleClientID:        "id",
		GoogleClientSecret:    "secret",
		GoogleRedirectURL:     "http://localhost/callback",
	}
}

func TestValidateOK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"invalid env", func(c *Config) { c.AppEnv = "staging" }},
		{"missing db url", func(c *Config) { c.DBURL = "" }},
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"production without signing key", func(c *Config) {
			c.AppEnv = "production"
			c.JWTPrivateKey = ""
		}},
		{"missing cors", func(c *Config) { c.CORSAllowedOrigins = nil }},
		{"zero access ttl", func(c *Config) { c.AccessTokenTTLMinutes = 0 }},
		{"zero refresh ttl", func(c *Config) { c.RefreshTokenTTLHours = -1 }},
		{"missing google client id", func(c *Config) { c.GoogleClientID = "" }},
		{"missing google secret", func(c *Config) { c.GoogleClientSecret = "" }},
		{"missing google redirect", func(c *Config) { c.GoogleRedirectURL = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			if err := c.Validate(); err == nil {
				t.Error("Validate() expected error, got nil")
			}
		})
	}
}

func TestValidateGoogleOptional(t *testing.T) {
	t.Run("no google credentials is valid", func(t *testing.T) {
		c := validConfig()
		c.GoogleClientID, c.GoogleClientSecret, c.GoogleRedirectURL = "", "", ""
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("partial google credentials is invalid", func(t *testing.T) {
		c := validConfig()
		c.GoogleClientSecret, c.GoogleRedirectURL = "", ""
		if err := c.Validate(); err == nil {
			t.Error("Validate() expected error, got nil")
		}
	})
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PORT", "9000")
	t.Setenv("DB_URL", "postgres://user:pass@localhost:5432/db")
	t.Setenv("ISSUER", "https://auth.example.com")
	t.Setenv("JWT_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
	t.Setenv("ACCESS_TOKEN_TTL_MINUTES", "5")
	t.Setenv("REFRESH_TOKEN_TTL_HOURS", "48")
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://a.test,http://b.test")
	t.Setenv("GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "client-secret")
	t.Setenv("GOOGLE_REDIRECT_URL", "http://a.test/callback")

	cfg := Load()

	want := []struct {
		name string
		got  any
		want any
	}{
		{"AppEnv", cfg.AppEnv, "production"},
		{"AppPort", cfg.AppPort, "9000"},
		{"DBURL", cfg.DBURL, "postgres://user:pass@localhost:5432/db"},
		{"Issuer", cfg.Issuer, "https://auth.example.com"},
		{"JWTPrivateKey", cfg.JWTPrivateKey, "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"},
		{"AccessTokenTTLMinutes", cfg.AccessTokenTTLMinutes, 5},
		{"RefreshTokenTTLHours", cfg.RefreshTokenTTLHours, 48},
		{"TrustProxy", cfg.TrustProxy, true},
	}
	for _, w := range want {
		if w.got != w.want {
			t.Errorf("%s = %v, want %v", w.name, w.got, w.want)
		}
	}

	if len(cfg.CORSAllowedOrigins) != 2 {
		t.Errorf("CORSAllowedOrigins length = %d, want 2", len(cfg.CORSAllowedOrigins))
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

	if cfg.AppEnv != "development" {
		t.Errorf("AppEnv default = %q, want development", cfg.AppEnv)
	}
	if cfg.AppPort != "8080" {
		t.Errorf("AppPort default = %q, want 8080", cfg.AppPort)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("Issuer default = %q, want http://localhost:8080", cfg.Issuer)
	}
	if cfg.TrustProxy {
		t.Error("TrustProxy default = true, want false")
	}
	if cfg.AccessTokenTTLMinutes != 15 {
		t.Errorf("AccessTokenTTLMinutes default = %d, want 15", cfg.AccessTokenTTLMinutes)
	}
	if cfg.RefreshTokenTTLHours != 720 {
		t.Errorf("RefreshTokenTTLHours default = %d, want 720", cfg.RefreshTokenTTLHours)
	}
}
