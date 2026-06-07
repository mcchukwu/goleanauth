package middleware

import (
	"goleanauth/internal/apperror"
	"goleanauth/internal/response"
	"net"
	"net/http"
	"sync"
	"time"
)

type clientLimiter struct {
	requests int
	lastSeen time.Time
}

type RateLimiterMiddleware struct {
	mu          sync.Mutex
	clients     map[string]*clientLimiter
	maxRequests int
	window      time.Duration
}

func NewRateLimiterMiddleware(maxRequests int, window time.Duration) *RateLimiterMiddleware {
	rl := &RateLimiterMiddleware{
		clients:     make(map[string]*clientLimiter),
		maxRequests: maxRequests,
		window:      window,
	}

	go rl.cleanup()

	return rl
}

func (rl *RateLimiterMiddleware) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		rl.mu.Lock()

		client, exists := rl.clients[ip]
		if !exists {
			client = &clientLimiter{
				requests: 0,
				lastSeen: time.Now(),
			}

			rl.clients[ip] = client
		}

		// reset window
		if time.Since(client.lastSeen) > rl.window {
			client.requests = 0
		}

		client.requests++
		client.lastSeen = time.Now()

		requests := client.requests

		rl.mu.Unlock()

		if requests > rl.maxRequests {
			response.HandleError(w, apperror.ErrRateLimited)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiterMiddleware) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)

	for range ticker.C {
		rl.mu.Lock()

		for ip, client := range rl.clients {
			if time.Since(client.lastSeen) > 10*time.Minute {
				delete(rl.clients, ip)
			}
		}

		rl.mu.Unlock()
	}
}

func getClientIP(r *http.Request) string {
	// reverse proxy support
	forwarded := r.Header.Get(
		"X-Forwarded-For",
	)
	if forwarded != "" {
		return forwarded
	}

	ip, _, err := net.SplitHostPort(
		r.RemoteAddr,
	)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
