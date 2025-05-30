package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// BaseHandler provides common functionality for all handlers
type BaseHandler struct {
	db *sqlx.DB
}

func NewBaseHandler(database *sqlx.DB) *BaseHandler {
	return &BaseHandler{
		db: database,
	}
}

// Shared utility functions for all handlers

func WriteJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func WriteErrorResponse(w http.ResponseWriter, statusCode int, message, detail string) {
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

// Helper function to get client IP
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
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

// Helper function to join strings
func JoinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// Helper function to check for unique constraint errors
func IsUniqueConstraintError(err error) bool {
	return err != nil && (
		ContainsString(err.Error(), "Duplicate entry") ||
		ContainsString(err.Error(), "UNIQUE constraint failed") ||
		ContainsString(err.Error(), "duplicate key value"))
}

// Helper function to check if string contains substring
func ContainsString(str, substr string) bool {
	return len(str) >= len(substr) && IndexOfString(str, substr) >= 0
}

// Helper function to find substring index
func IndexOfString(str, substr string) int {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
