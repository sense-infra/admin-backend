package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

type AuthMiddleware struct {
	authService *services.AuthService
}

type contextKey string

const AuthContextKey contextKey = "auth"

func NewAuthMiddleware(authService *services.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// CORS middleware for web interface (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Configure this for production
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LogAPIUsage middleware that logs API key usage (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) LogAPIUsage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status and size
		wrapper := &responseWrapper{
			ResponseWriter: w,
			statusCode:     200,
		}

		next.ServeHTTP(wrapper, r)

		// Log usage if authenticated with API key
		authContext := GetAuthContext(r)
		if authContext != nil && authContext.IsAPIKey && authContext.APIKeyID != nil {
			duration := time.Since(start)
			
			go func() {
				am.authService.LogAPIUsage(
					*authContext.APIKeyID,
					r.URL.Path,
					r.Method,
					getClientIP(r),
					r.UserAgent(),
					wrapper.statusCode,
					int(duration.Milliseconds()),
					int(r.ContentLength),
					wrapper.size,
				)
			}()
		}
	})
}

// AddRateLimitHeaders middleware that adds rate limit headers (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) AddRateLimitHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call the next handler first
		next.ServeHTTP(w, r)

		// Add rate limit headers if this was an API key request
		authContext := GetAuthContext(r)
		if authContext != nil && authContext.IsAPIKey && authContext.APIKeyID != nil {
			rateLimitInfo, err := am.authService.GetRateLimitInfo(*authContext.APIKeyID)
			if err == nil {
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimitInfo.Limit))
				w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", rateLimitInfo.Remaining))
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", rateLimitInfo.ResetAt))
			}
		}
	})
}

// RequireAuth middleware that requires authentication (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authContext, err := am.authenticate(r)
		if err != nil {
			statusCode := http.StatusUnauthorized
			message := "Authentication required"
			
			// Handle specific errors
			switch err {
			case services.ErrRateLimitExceeded:
				statusCode = http.StatusTooManyRequests
				message = "API rate limit exceeded"
			case services.ErrAPIKeyExpired:
				message = "API key has expired"
			case services.ErrAPIKeyInactive:
				message = "API key is inactive"
			case services.ErrInvalidCredentials:
				message = "Invalid credentials"
			case services.ErrUserLocked:
				message = "User account is locked"
			case services.ErrUserInactive:
				message = "User account is inactive"
			}
			
			am.writeErrorResponse(w, statusCode, message, err.Error())
			return
		}

		// Add auth context to request
		ctx := context.WithValue(r.Context(), AuthContextKey, authContext)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission middleware that requires specific permission (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return am.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authContext := GetAuthContext(r)
			if authContext == nil {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
				return
			}

			if !authContext.HasPermission(resource, action) {
				am.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", 
					"Required permission: "+resource+":"+action)
				return
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// RequireRole middleware that requires specific role (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return am.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authContext := GetAuthContext(r)
			if authContext == nil {
				am.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "")
				return
			}

			if authContext.Role == nil || authContext.Role.Name != roleName {
				am.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", 
					"Required role: "+roleName)
				return
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// RequireAdmin middleware that requires admin role (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	return am.RequireRole("admin")(next)
}

// OptionalAuth middleware that optionally authenticates (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authContext, _ := am.authenticate(r) // Ignore errors for optional auth
		
		if authContext != nil {
			ctx := context.WithValue(r.Context(), AuthContextKey, authContext)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions

func (am *AuthMiddleware) authenticate(r *http.Request) (*models.AuthContext, error) {
	// Try JWT token first (Authorization header)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return am.authService.ValidateToken(token)
		}
	}

	// Try API key (X-API-Key header)
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return am.authService.ValidateAPIKey(apiKey)
	}

	return nil, services.ErrInvalidCredentials
}

func (am *AuthMiddleware) writeErrorResponse(w http.ResponseWriter, statusCode int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	
	// Special handling for rate limit errors
	if statusCode == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "3600") // 1 hour in seconds
	}
	
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":   message,
		"status":  statusCode,
		"timestamp": time.Now().Unix(),
	}
	
	if detail != "" {
		response["detail"] = detail
	}
	
	json.NewEncoder(w).Encode(response)
}

// GetAuthContext extracts the auth context from request context
func GetAuthContext(r *http.Request) *models.AuthContext {
	if authContext, ok := r.Context().Value(AuthContextKey).(*models.AuthContext); ok {
		return authContext
	}
	return nil
}

// GetUserID extracts the user ID from auth context
func GetUserID(r *http.Request) *int {
	authContext := GetAuthContext(r)
	if authContext != nil {
		return authContext.UserID
	}
	return nil
}

// GetAPIKeyID extracts the API key ID from auth context
func GetAPIKeyID(r *http.Request) *int {
	authContext := GetAuthContext(r)
	if authContext != nil {
		return authContext.APIKeyID
	}
	return nil
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(r *http.Request) bool {
	return GetAuthContext(r) != nil
}

// HasPermission checks if the authenticated user/API key has permission
func HasPermission(r *http.Request, resource, action string) bool {
	authContext := GetAuthContext(r)
	if authContext == nil {
		return false
	}
	return authContext.HasPermission(resource, action)
}

// IsAdmin checks if the authenticated user is an admin
func IsAdmin(r *http.Request) bool {
	authContext := GetAuthContext(r)
	if authContext == nil || authContext.Role == nil {
		return false
	}
	return authContext.Role.Name == "admin"
}

// responseWrapper wraps http.ResponseWriter to capture response details
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWrapper) Write(data []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(data)
	rw.size += size
	return size, err
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}
