package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens    map[string]*TokenBucket
	mutex     sync.RWMutex
	cleanup   time.Duration
	lastClean time.Time
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens    int
	maxTokens int
	refillAt  time.Time
	window    time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		tokens:    make(map[string]*TokenBucket),
		cleanup:   5 * time.Minute,
		lastClean: time.Now(),
	}
}

// Allow checks if a request should be allowed based on client IP
func (rl *RateLimiter) Allow(clientIP string, maxRequests int, window time.Duration) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Cleanup old entries periodically
	if time.Since(rl.lastClean) > rl.cleanup {
		rl.cleanupExpired()
		rl.lastClean = time.Now()
	}
	
	bucket, exists := rl.tokens[clientIP]
	if !exists {
		bucket = &TokenBucket{
			tokens:    maxRequests - 1, // Consume one token
			maxTokens: maxRequests,
			refillAt:  time.Now().Add(window),
			window:    window,
		}
		rl.tokens[clientIP] = bucket
		return true
	}
	
	// Refill tokens if window has passed
	if time.Now().After(bucket.refillAt) {
		bucket.tokens = bucket.maxTokens
		bucket.refillAt = time.Now().Add(window)
	}
	
	// Check if tokens available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	
	return false
}

// cleanupExpired removes expired token buckets
func (rl *RateLimiter) cleanupExpired() {
	now := time.Now()
	for ip, bucket := range rl.tokens {
		if now.After(bucket.refillAt.Add(bucket.window)) {
			delete(rl.tokens, ip)
		}
	}
}

// RateLimit middleware factory
func RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	limiter := NewRateLimiter()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := extractClientIP(r)
			
			if !limiter.Allow(clientIP, maxRequests, window) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-RateLimit-Limit", string(rune(maxRequests)))
				w.Header().Set("X-RateLimit-Window", window.String())
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error": "Rate limit exceeded", "status": 429, "detail": "Too many requests from your IP address"}`))
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP extracts client IP from request for rate limiting
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for load balancers/proxies)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header (for reverse proxies)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Fall back to RemoteAddr (remove port if present)
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	
	// Remove IPv6 brackets if present
	ip = strings.Trim(ip, "[]")
	
	return ip
}
