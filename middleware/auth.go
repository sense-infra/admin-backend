package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux" // if you're using Gorilla Mux router
	"github.com/sense-security/api/models"
	"github.com/sense-security/api/services"
)

type AuthMiddleware struct {
	authService *services.AuthService
}

type contextKey string

const AuthContextKey contextKey = "auth"

type customerContextKey string

const CustomerAuthContextKey customerContextKey = "customer_auth"

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

// RequireAuth middleware that requires authentication (mux.MiddlewareFunc compatible)
func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authContext, err := am.authenticate(r)
		if err != nil {
			// Use your original error handling logic
			am.writeAuthErrorResponse(w, err)
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

// APIKeyRateLimit middleware specifically for API key rate limiting
func (am *AuthMiddleware) APIKeyRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get API key from headers
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header with Bearer token
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				apiKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		// If no API key, continue without rate limiting
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validate API key and check rate limit
		authContext, err := am.authService.ValidateAPIKey(apiKey)
		if err != nil {
			if err == services.ErrAPIKeyRateLimited {
				// Get API key ID to provide more detailed rate limit info
				keyHash := am.hashAPIKey(apiKey)
				apiKeyData, keyErr := am.getAPIKeyByHash(keyHash)
				if keyErr == nil {
					usageLastHour, _ := am.authService.GetAPIKeyUsageInLastHour(apiKeyData.APIKeyID)
					am.writeDetailedRateLimitError(w, apiKeyData.RateLimitPerHour, usageLastHour)
					return
				}
			}
			am.writeErrorResponse(w, http.StatusUnauthorized, "Invalid API key", err.Error())
			return
		}

		// Add auth context to request and continue
		ctx := context.WithValue(r.Context(), AuthContextKey, authContext)
		next.ServeHTTP(w, r.WithContext(ctx))
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

// Helper methods for getting API key info (needed for detailed rate limit responses)
func (am *AuthMiddleware) hashAPIKey(key string) string {
	// This should match the hashing logic in AuthService
	// For now, we'll call the service method if available
	// In a production system, you might want to extract this to a common utility
	return "" // Placeholder - would need access to the same hashing function
}

func (am *AuthMiddleware) getAPIKeyByHash(keyHash string) (*models.APIKey, error) {
	// This would need to be implemented to get API key info for detailed error responses
	// For now, returning nil to avoid compilation errors
	return nil, nil
}

func (am *AuthMiddleware) writeErrorResponse(w http.ResponseWriter, statusCode int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now().Unix(),
	}
	
	if detail != "" {
		response["detail"] = detail
	}
	
	json.NewEncoder(w).Encode(response)
}

func (am *AuthMiddleware) writeAuthErrorResponse(w http.ResponseWriter, err error) {
	var statusCode int
	var message string
	
	// Handle specific authentication errors with your original logic
	switch err {
	case services.ErrAPIKeyRateLimited:
		statusCode = http.StatusTooManyRequests
		message = "API rate limit exceeded"
		// Add rate limit headers
		w.Header().Set("X-RateLimit-Exceeded", "true")
	case services.ErrAPIKeyExpired:
		statusCode = http.StatusUnauthorized
		message = "API key has expired"
	case services.ErrAPIKeyInactive:
		statusCode = http.StatusUnauthorized
		message = "API key is inactive"
	case services.ErrInvalidCredentials:
		statusCode = http.StatusUnauthorized
		message = "Invalid credentials"
	case services.ErrUserLocked:
		statusCode = http.StatusUnauthorized
		message = "User account is locked"
	case services.ErrUserInactive:
		statusCode = http.StatusUnauthorized
		message = "User account is inactive"
	case services.ErrSessionExpired:
		statusCode = http.StatusUnauthorized
		message = "Session has expired"
	case services.ErrInvalidToken:
		statusCode = http.StatusUnauthorized
		message = "Invalid or expired token"
	default:
		statusCode = http.StatusUnauthorized
		message = "Authentication required"
	}

	am.writeErrorResponse(w, statusCode, message, err.Error())
}

func (am *AuthMiddleware) writeRateLimitErrorResponse(w http.ResponseWriter, r *http.Request, authContext *models.AuthContext) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Exceeded", "true")
	w.WriteHeader(http.StatusTooManyRequests)
	
	response := map[string]interface{}{
		"error":     "Rate limit exceeded",
		"status":    429,
		"timestamp": time.Now().Unix(),
		"detail":    "API key has exceeded its hourly rate limit",
	}
	
	// Add additional rate limit info if available
	if authContext != nil && authContext.APIKeyID != nil {
		if usageCount, err := am.authService.GetAPIKeyUsageInLastHour(*authContext.APIKeyID); err == nil {
			response["usage_last_hour"] = usageCount
		}
	}
	
	json.NewEncoder(w).Encode(response)
}

func (am *AuthMiddleware) writeDetailedRateLimitError(w http.ResponseWriter, rateLimit, usageLastHour int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit", string(rune(rateLimit)))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", string(rune(time.Now().Add(time.Hour).Unix())))
	w.WriteHeader(http.StatusTooManyRequests)
	
	response := map[string]interface{}{
		"error":           "Rate limit exceeded",
		"status":          429,
		"timestamp":       time.Now().Unix(),
		"detail":          "API key has exceeded its hourly rate limit",
		"rate_limit":      rateLimit,
		"usage_last_hour": usageLastHour,
		"reset_time":      time.Now().Add(time.Hour).Unix(),
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

// RequireCustomerAuth middleware that requires customer authentication
func (am *AuthMiddleware) RequireCustomerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customerAuthContext, err := am.authenticateCustomer(r)
		if err != nil {
			am.writeCustomerAuthErrorResponse(w, err)
			return
		}

		// Add customer auth context to request
		ctx := context.WithValue(r.Context(), CustomerAuthContextKey, customerAuthContext)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireContractAccess middleware that ensures customer can access specific contract
func (am *AuthMiddleware) RequireContractAccess(next http.Handler) http.Handler {
	return am.RequireCustomerAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customerAuthContext := GetCustomerAuthContext(r)
		if customerAuthContext == nil {
			am.writeErrorResponse(w, http.StatusUnauthorized, "Customer authentication required", "")
			return
		}

		// Extract contract ID from URL path
		vars := mux.Vars(r)
		contractIDStr, exists := vars["contract_id"]
		if !exists {
			contractIDStr = vars["id"] // fallback for routes like /contracts/{id}
		}

		if contractIDStr != "" {
			if contractID, err := strconv.Atoi(contractIDStr); err == nil {
				if !customerAuthContext.CanAccessContract(contractID) {
					am.writeErrorResponse(w, http.StatusForbidden, "Access denied to contract", 
						fmt.Sprintf("Customer does not have access to contract %d", contractID))
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	}))
}

// OptionalCustomerAuth middleware that optionally authenticates customers
func (am *AuthMiddleware) OptionalCustomerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customerAuthContext, _ := am.authenticateCustomer(r) // Ignore errors for optional auth

		if customerAuthContext != nil {
			ctx := context.WithValue(r.Context(), CustomerAuthContextKey, customerAuthContext)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// Helper methods for customer authentication

func (am *AuthMiddleware) authenticateCustomer(r *http.Request) (*models.CustomerAuthContext, error) {
	// Try JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return am.authService.ValidateCustomerToken(token)
		}
	}

	return nil, services.ErrInvalidCredentials
}

func (am *AuthMiddleware) writeCustomerAuthErrorResponse(w http.ResponseWriter, err error) {
	var statusCode int
	var message string

	// Handle specific customer authentication errors
	switch err {
	case services.ErrCustomerInvalidCredentials:
		statusCode = http.StatusUnauthorized
		message = "Invalid email or password"
	case services.ErrCustomerLocked:
		statusCode = http.StatusLocked
		message = "Customer account is locked"
	case services.ErrCustomerInactive:
		statusCode = http.StatusForbidden
		message = "Customer account is inactive"
	case services.ErrSessionExpired:
		statusCode = http.StatusUnauthorized
		message = "Session has expired"
	case services.ErrInvalidToken:
		statusCode = http.StatusUnauthorized
		message = "Invalid or expired token"
	default:
		statusCode = http.StatusUnauthorized
		message = "Customer authentication required"
	}

	am.writeErrorResponse(w, statusCode, message, err.Error())
}

// Helper functions for customer context

// GetCustomerAuthContext extracts the customer auth context from request context
func GetCustomerAuthContext(r *http.Request) *models.CustomerAuthContext {
	if customerAuthContext, ok := r.Context().Value(CustomerAuthContextKey).(*models.CustomerAuthContext); ok {
		return customerAuthContext
	}
	return nil
}

// GetCustomerID extracts the customer ID from customer auth context
func GetCustomerID(r *http.Request) *int {
	customerAuthContext := GetCustomerAuthContext(r)
	if customerAuthContext != nil {
		return customerAuthContext.CustomerID
	}
	return nil
}

// IsCustomerAuthenticated checks if the request has customer authentication
func IsCustomerAuthenticated(r *http.Request) bool {
	return GetCustomerAuthContext(r) != nil
}

// CustomerCanAccessContract checks if the customer can access a specific contract
func CustomerCanAccessContract(r *http.Request, contractID int) bool {
	customerAuthContext := GetCustomerAuthContext(r)
	if customerAuthContext == nil {
		return false
	}
	return customerAuthContext.CanAccessContract(contractID)
}

// GetCustomerContractIDs returns the contract IDs the customer has access to
func GetCustomerContractIDs(r *http.Request) []int {
	customerAuthContext := GetCustomerAuthContext(r)
	if customerAuthContext == nil {
		return nil
	}
	return customerAuthContext.ContractIDs
}
