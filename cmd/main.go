package main

import (
	"context"
	"goleanauth/internal/auth"
	"goleanauth/internal/handler"
	"goleanauth/internal/middleware"
	"goleanauth/internal/validation"
	"goleanauth/pkg/config"
	"goleanauth/pkg/db"
	"goleanauth/pkg/logger"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := config.Load()

	// Initialize shared packages
	validation.Init()
	auth.InitOAuth(cfg)

	mux := http.NewServeMux()

	// Connect to database
	if err := db.Connect(cfg.DatabaseURL); err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Configure middleware
	rateLimiterMiddleware := middleware.NewRateLimiterMiddleware(100, time.Minute)
	loginLimiterMiddleware := middleware.NewRateLimiterMiddleware(5, time.Minute)
	registerLimiterMiddleware := middleware.NewRateLimiterMiddleware(3, time.Minute)
	refreshLimiterMiddleware := middleware.NewRateLimiterMiddleware(10, time.Minute)
	oauthLimiterMiddleware := middleware.NewRateLimiterMiddleware(5, time.Minute)

	authMiddleware := middleware.NewAuthMiddleware(db.DB, []byte(cfg.JWTSecret))

	requestIDMiddleware := middleware.NewRequestIDMiddleware()
	loggingMiddleware := middleware.NewLoggingMiddleware()
	securityHeadersMiddleware := middleware.NewSecurityHeadersMiddleware()
	corsMiddleware := middleware.NewCorsMiddleware(cfg.CORSAllowedOrigins)
	recoveryMiddleware := middleware.NewRecoveryMiddleware()

	// Configure services and handlers
	authService := auth.NewAuthService(db.DB, []byte(cfg.JWTSecret))
	authHandler := auth.NewAuthHandler(authService)

	// Protected routes
	mux.Handle("POST /v1/auth/refresh", authMiddleware.RequireAuth(refreshLimiterMiddleware.Limit(http.HandlerFunc(authHandler.RefreshToken))))
	mux.Handle("POST /v1/auth/logout", authMiddleware.RequireAuth(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("POST /v1/auth/logout-all", authMiddleware.RequireAuth(http.HandlerFunc(authHandler.LogoutAllDevices)))

	// Other routes
	mux.Handle("POST /v1/auth/register", registerLimiterMiddleware.Limit(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /v1/auth/login", loginLimiterMiddleware.Limit(http.HandlerFunc(authHandler.Login)))

	// oauth routes — Google and Apple follow the same callback pattern
	mux.Handle("GET /v1/auth/google/callback", oauthLimiterMiddleware.Limit(http.HandlerFunc(authHandler.GoogleCallbackHandler)))

	// Health check route (for load balancers)
	healthHandler := handler.NewHealthHandler(db.DB)

	mux.HandleFunc("GET /v1/health", healthHandler.Health)
	mux.HandleFunc("GET /v1/ready", healthHandler.Ready)
	mux.HandleFunc("GET /v1/live", healthHandler.Live)

	// chain middleware
	handlerChain := recoveryMiddleware.Recover((requestIDMiddleware.Assign(loggingMiddleware.Log(securityHeadersMiddleware.Secure(corsMiddleware.Cors(rateLimiterMiddleware.Limit(mux)))))))

	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      handlerChain,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server safely
	go func() {
		logger.Info("Server starting on port " + cfg.AppPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server")
			os.Exit(1)
		}
	}()

	// Shutdown signal listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown context
	logger.Info("Shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Graceful shutdown failed")

		server.Close()
	}

	// Close database connection
	if err := db.DB.Close(); err != nil {
		logger.Error("Database connection close failed")
	}

	logger.Info("Server exiting gracefully")
}
