package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"goleanauth/internal/audit"
	"goleanauth/internal/auth"
	"goleanauth/internal/health"
	"goleanauth/internal/middleware"
	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
	"goleanauth/pkg/db"
	"goleanauth/pkg/jwks"
	"goleanauth/pkg/logger"
)

func main() {
	cfg := config.Load()

	if err := cfg.Validate(); err != nil {
		logger.Error("Configuration validation failed")
		os.Exit(1)
	}

	// Initialize shared packages
	validation.Init()
	auth.InitOAuth(cfg)

	// Build the signing key set. In development an ephemeral key is generated
	// when one is not configured (tokens will be invalidated on restart).
	var keys *jwks.KeySet

	switch {
	case cfg.JWTPrivateKey != "":
		var err error
		keys, err = jwks.Load(cfg.JWTPrivateKey, cfg.JWTPublicKeys)
		if err != nil {
			logger.Error("Failed to load jwt signing keys: %s", err)
			os.Exit(1)
		}
	case cfg.AppEnv == "production":
		logger.Error("JWT_PRIVATE_KEY is required in production")
		os.Exit(1)
	default:
		var err error
		keys, err = jwks.Generate()
		if err != nil {
			logger.Error("Failed to generate jwt signing key")
			os.Exit(1)
		}
		logger.Warn("Generated ephemeral JWT signing key; configure JWT_PRIVATE_KEY to persist tokens across restarts")
	}

	mux := http.NewServeMux()

	// Connect to database
	if err := db.Connect(cfg.DBURL); err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Configure middleware
	rateLimiterMiddleware := middleware.NewRateLimiterMiddleware(100, time.Minute, cfg.TrustProxy)
	loginLimiterMiddleware := middleware.NewRateLimiterMiddleware(5, time.Minute, cfg.TrustProxy)
	registerLimiterMiddleware := middleware.NewRateLimiterMiddleware(3, time.Minute, cfg.TrustProxy)
	refreshLimiterMiddleware := middleware.NewRateLimiterMiddleware(10, time.Minute, cfg.TrustProxy)
	oauthLimiterMiddleware := middleware.NewRateLimiterMiddleware(5, time.Minute, cfg.TrustProxy)

	authMiddleware := middleware.NewAuthMiddleware(db.DB, keys)

	requestIDMiddleware := middleware.NewRequestIDMiddleware()
	loggingMiddleware := middleware.NewLoggingMiddleware()
	securityHeadersMiddleware := middleware.NewSecurityHeadersMiddleware()
	corsMiddleware := middleware.NewCorsMiddleware(cfg.CORSAllowedOrigins)
	recoveryMiddleware := middleware.NewRecoveryMiddleware()

	// Configure services and handlers
	auditService := audit.NewAuditService(db.DB)
	authService := auth.NewAuthService(db.DB, keys, auditService, cfg)
	authHandler := auth.NewAuthHandler(authService, cfg)

	// Protected routes
	mux.Handle("POST /v1/auth/refresh", authMiddleware.RequireAuth(refreshLimiterMiddleware.Limit(http.HandlerFunc(authHandler.RefreshToken))))
	mux.Handle("POST /v1/auth/logout", authMiddleware.RequireAuth(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("POST /v1/auth/logout-all", authMiddleware.RequireAuth(http.HandlerFunc(authHandler.LogoutAllDevices)))

	// Other routes
	mux.Handle("POST /v1/auth/register", registerLimiterMiddleware.Limit(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /v1/auth/login", loginLimiterMiddleware.Limit(http.HandlerFunc(authHandler.Login)))

	// Oauth routes — Google and Apple follow the same callback pattern
	mux.Handle("GET /v1/auth/google/login", oauthLimiterMiddleware.Limit(http.HandlerFunc(authHandler.GoogleLoginHandler)))
	mux.Handle("GET /v1/auth/google/callback", oauthLimiterMiddleware.Limit(http.HandlerFunc(authHandler.GoogleCallbackHandler)))

	// Health check route (for load balancers)
	healthHandler := health.NewHealthHandler(db.DB)

	mux.HandleFunc("GET /v1/health", healthHandler.Health)
	mux.HandleFunc("GET /v1/ready", healthHandler.Ready)
	mux.HandleFunc("GET /v1/live", healthHandler.Live)

	// chain middleware
	handlerChain := recoveryMiddleware.Recover((requestIDMiddleware.Assign(loggingMiddleware.Log(securityHeadersMiddleware.Secure(corsMiddleware.Cors(rateLimiterMiddleware.Limit(mux)))))))

	// Start server safely
	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      handlerChain,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		logger.Info("Server started on port %s", cfg.AppPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server")
			os.Exit(1)
		}
	}()

	// Shutdown signal listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Shutdown server gracefully
	logger.Info("Shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Graceful shutdown failed")
		server.Close()
	}

	// Close database connection
	logger.Info("Closing database connection")
	if err := db.DB.Close(); err != nil {
		logger.Error("Database connection close failed")
	}
	logger.Info("Database connection closed")

	logger.Info("Server exiting gracefully")
}
