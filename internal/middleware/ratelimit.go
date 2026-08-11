package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"goleanauth/internal/apperror"
	"goleanauth/internal/response"
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
	trustProxy  bool
}

func NewRateLimiterMiddleware(maxRequests int, window time.Duration, trustProxy bool) *RateLimiterMiddleware {
	rl := &RateLimiterMiddleware{
		clients:     make(map[string]*clientLimiter),
		maxRequests: maxRequests,
		window:      window,
		trustProxy:  trustProxy,
	}

	go rl.cleanup()

	return rl
}

// Limit limits the number of requests per client
func (rl *RateLimiterMiddleware) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r, rl.trustProxy)

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

// cleanup removes clients that haven't made a request in the last 10 minutes
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

// getClientIP returns the client IP address. Proxy headers are only trusted
// when the service runs behind a trusted reverse proxy (TRUST_PROXY=true);
// otherwise the remote address is used to prevent header spoofing.
func getClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
				return first
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
