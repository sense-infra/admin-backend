package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

// Logger middleware logs all requests
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a custom response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(lrw, r)
		
		log.Printf(
			"[%s] %s %s %d %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			lrw.statusCode,
			time.Since(start),
		)
	})
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "3600")
		
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// ContentType middleware sets the content type for all responses
func ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// APIKeyAuth middleware validates API key authentication
func APIKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	// Create a map for O(1) lookup
	keyMap := make(map[string]bool)
	for _, key := range validKeys {
		keyMap[strings.TrimSpace(key)] = true
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for API key in header
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				// Also check Authorization header with Bearer token
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					apiKey = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			
			// Validate API key
			if apiKey == "" || !keyMap[strings.TrimSpace(apiKey)] {
				http.Error(w, `{"error": "Invalid or missing API key"}`, http.StatusUnauthorized)
				return
			}
			
			// Add API key to context for logging purposes
			ctx := context.WithValue(r.Context(), "api_key", apiKey[:8]+"...") // Only store partial key
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
